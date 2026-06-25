"""
backfill.py
------------
Bulk-processes existing log files into MySQL. Useful for:
  - Initial testing (process the sample_logs/ files once to verify
    the whole pipeline works before running the live watcher)
  - Loading historical logs that existed before the real-time
    watcher was started

Usage:
    python backfill.py
"""

from parsers import ssh_parser, ftp_parser, web_parser, db_parser
from db_writer import insert_events_batch, get_total_row_count


SOURCES = [
    ("sample_logs/ssh_cowrie.json", ssh_parser),
    ("sample_logs/ftp_honeypot.log", ftp_parser),
    ("sample_logs/web_access.log", web_parser),
    ("sample_logs/db_honeypot.json", db_parser),
]


def main():
    print(f"Row count before backfill: {get_total_row_count()}\n")

    total_inserted = 0
    for filepath, parser in SOURCES:
        events = parser.parse_file(filepath)
        inserted = insert_events_batch(events)
        total_inserted += inserted
        print(f"{filepath}: parsed {len(events)} events, inserted {inserted}")

    print(f"\nTotal events inserted this run: {total_inserted}")
    print(f"Row count after backfill: {get_total_row_count()}")


if __name__ == "__main__":
    main()
