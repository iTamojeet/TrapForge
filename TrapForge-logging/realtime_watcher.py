"""
realtime_watcher.py
---------------------
The real-time ingestion engine. Watches honeypot log files for new
lines being appended (i.e. as attacks happen live) and immediately
parses + normalizes + inserts each new line into MySQL.

This satisfies the project requirement: "logs must flow in as attacks
happen, not in batches."

HOW IT WORKS
------------
Uses the `watchdog` library to get OS-level filesystem notifications
the instant a watched log file is modified, rather than polling on a
timer. For each watched file we track the last read byte offset, so
when a modification event fires we only read the *new* bytes appended
since last time (instead of re-reading the whole file).

CONFIGURATION
-------------
Edit WATCHED_FILES below to point at the real paths where each
honeypot service writes its logs once Member 1's services are
deployed. Currently configured to watch the local sample_logs/
files for demo/testing purposes.

USAGE
-----
    python realtime_watcher.py

Then, in another terminal, simulate a live attack by appending a new
line to one of the watched files, e.g.:

    echo '{"eventid": "cowrie.command.input", "timestamp": "2026-06-24T04:00:00.000Z", "session": "live-test-1", "src_ip": "203.0.113.99", "input": "whoami"}' >> sample_logs/ssh_cowrie.json

You should see it picked up and inserted within a second.
"""

import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from parsers import ssh_parser, ftp_parser, web_parser, db_parser
from db_writer import insert_event


# Maps a watched file path -> the parser module responsible for it.
# Update these paths once real honeypot log locations are known.
WATCHED_FILES = {
    "/home/ubuntu/cowrie-logs/cowrie/cowrie.json": ssh_parser,
    "sample_logs/ftp_honeypot.log": ftp_parser,
    "sample_logs/web_access.log": web_parser,
}


class LogFileHandler(FileSystemEventHandler):
    """
    Tracks a byte offset per watched file so that on each modification
    event we only process newly-appended lines, not the whole file.
    """

    def __init__(self, watched_files: dict):
        self.watched_files = {
            os.path.abspath(path): parser for path, parser in watched_files.items()
        }
        self.offsets = {}

        # Initialize offsets to current end-of-file so we only react to
        # NEW lines from this point forward, not lines already present.
        for path in self.watched_files:
            self.offsets[path] = os.path.getsize(path) if os.path.exists(path) else 0

    def on_modified(self, event):
        if event.is_directory:
            return

        path = os.path.abspath(event.src_path)
        if path not in self.watched_files:
            return

        parser = self.watched_files[path]
        self._process_new_lines(path, parser)

    def _process_new_lines(self, path: str, parser):
        try:
            with open(path, "r") as f:
                f.seek(self.offsets[path])
                new_lines = f.readlines()
                self.offsets[path] = f.tell()
        except FileNotFoundError:
            return

        for line in new_lines:
            if not line.strip():
                continue
            try:
                normalized_event = parser.parse_line(line)
            except Exception as e:
                print(f"[watcher] ERROR parsing line from {path}: {e}")
                continue

            if normalized_event is None:
                continue  # not an event type we track, or malformed -- skip

            success = insert_event(normalized_event)
            tag = "OK" if success else "FAILED"
            print(
                f"[{tag}] {normalized_event.service:4s} | "
                f"{normalized_event.event_type:15s} | "
                f"{normalized_event.source_ip:15s} | "
                f"{normalized_event.raw_payload}"
            )


def main():
    handler = LogFileHandler(WATCHED_FILES)
    observer = Observer()

    watched_dirs = set()
    for path in WATCHED_FILES:
        directory = os.path.dirname(os.path.abspath(path)) or "."
        watched_dirs.add(directory)

    for directory in watched_dirs:
        observer.schedule(handler, directory, recursive=False)

    observer.start()
    print("Real-time log watcher started. Watching:")
    for path in WATCHED_FILES:
        print(f"  - {path}")
    print("\nPress Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nWatcher stopped.")
    observer.join()


if __name__ == "__main__":
    main()
