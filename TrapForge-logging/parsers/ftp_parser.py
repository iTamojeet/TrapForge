"""
parsers/ftp_parser.py
------------------------
Parses FTP honeypot logs in the format:

    2026-06-24 03:20:15,887 INFO [ftp_honeypot] COMMAND src=198.51.100.17 session=f7e8d9c0 cmd=LIST args=/

Each line is: TIMESTAMP LEVEL [SOURCE] EVENT_TYPE key=value key=value ...

This key=value style is common for simple custom FTP honeypots
(e.g. ones built on top of pyftpdlib or twisted.protocols.ftp with
custom logging). If Member 1's actual FTP honeypot logs in a
different format, only this file needs to change -- the rest of
the pipeline (schema, watcher, MySQL insert) stays the same.
"""

import re
from datetime import datetime
from typing import Optional

from schema import UnifiedLogEvent
from geoip import lookup


LINE_PATTERN = re.compile(
    r"^(?P<timestamp>[\d\-]+ [\d:,]+)\s+"
    r"(?P<level>\w+)\s+"
    r"\[(?P<source>[\w_]+)\]\s+"
    r"(?P<event>\w+)\s+"
    r"(?P<kv_pairs>.*)$"
)

# FTP event -> normalized event_type
EVENT_TYPE_MAP = {
    "CONNECT": "connection",
    "LOGIN": "login_attempt",
    "COMMAND": "command",
    "FILE_TRANSFER": "file_transfer",
    "DISCONNECT": "session_closed",
}


def _parse_kv_pairs(kv_string: str) -> dict:
    """
    Parse 'key=value key2=value2' style strings into a dict.
    Handles values that may contain '=' themselves (e.g. pass=guest@)
    by splitting only on the first '=' per token.
    """
    result = {}
    # Split on whitespace but keep things simple -- this format doesn't
    # quote values, so a naive split is adequate for this honeypot's output.
    for token in kv_string.split():
        if "=" in token:
            key, _, value = token.partition("=")
            result[key] = value
    return result


def parse_line(line: str) -> Optional[UnifiedLogEvent]:
    """Parse a single line of FTP honeypot log output."""
    line = line.strip()
    if not line:
        return None

    match = LINE_PATTERN.match(line)
    if not match:
        print(f"[ftp_parser] WARNING: line did not match expected format: {line[:100]}")
        return None

    parts = match.groupdict()
    event_type = EVENT_TYPE_MAP.get(parts["event"])
    if event_type is None:
        return None

    kv = _parse_kv_pairs(parts["kv_pairs"])
    src_ip = kv.get("src", "unknown")
    geo = lookup(src_ip)

    # Build a human/analyst-readable raw_payload depending on event type.
    if parts["event"] == "COMMAND":
        raw_payload = f"{kv.get('cmd', '')} {kv.get('args', '')}".strip()
    elif parts["event"] == "LOGIN":
        raw_payload = f"{kv.get('user', '')}:{kv.get('pass', '')}"
    elif parts["event"] == "FILE_TRANSFER":
        raw_payload = kv.get("filename")
    else:
        raw_payload = None

    timestamp_str = parts["timestamp"].replace(",", ".")
    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")

    return UnifiedLogEvent(
        timestamp=timestamp,
        session_id=kv.get("session"),
        service="ftp",
        source_ip=src_ip,
        source_country=geo.country,
        source_city=geo.city,
        source_lat=geo.lat,
        source_lon=geo.lon,
        event_type=event_type,
        raw_payload=raw_payload,
        metadata=kv,
    )


def parse_file(filepath: str) -> list[UnifiedLogEvent]:
    events = []
    with open(filepath, "r") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)
    return events


if __name__ == "__main__":
    events = parse_file("sample_logs/ftp_honeypot.log")
    print(f"Parsed {len(events)} events from sample FTP log:\n")
    for e in events:
        print(f"  [{e.event_type}] session={e.session_id} ip={e.source_ip} payload={e.raw_payload!r}")
