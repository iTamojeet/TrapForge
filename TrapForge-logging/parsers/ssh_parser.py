"""
parsers/ssh_parser.py
-----------------------
Parses Cowrie SSH honeypot logs (JSON-lines format, one JSON object
per line) into UnifiedLogEvent objects.

Cowrie event types we care about and how they map:

    cowrie.session.connect   -> event_type="connection"
    cowrie.login.success     -> event_type="login_attempt" (metadata.success=true)
    cowrie.login.failed      -> event_type="login_attempt" (metadata.success=false)
    cowrie.command.input     -> event_type="command"
    cowrie.session.file_download -> event_type="file_transfer"
    cowrie.session.closed    -> event_type="session_closed"

Reference: https://docs.cowrie.org/en/latest/events.html
"""

import json
from datetime import datetime
from typing import Optional

from schema import UnifiedLogEvent
from geoip import lookup


# Cowrie event IDs we recognize -> normalized event_type string
EVENT_TYPE_MAP = {
    "cowrie.session.connect": "connection",
    "cowrie.login.success": "login_attempt",
    "cowrie.login.failed": "login_attempt",
    "cowrie.command.input": "command",
    "cowrie.session.file_download": "file_transfer",
    "cowrie.session.file_upload": "file_transfer",
    "cowrie.session.closed": "session_closed",
}


def parse_line(line: str) -> Optional[UnifiedLogEvent]:
    """
    Parse a single line of Cowrie JSON log output into a UnifiedLogEvent.
    Returns None if the line is blank, malformed, or an event type we
    don't track (so the watcher can just skip it).
    """
    line = line.strip()
    if not line:
        return None

    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        # Malformed line -- log and skip rather than crash the whole pipeline.
        print(f"[ssh_parser] WARNING: could not parse line as JSON: {line[:100]}")
        return None

    eventid = raw.get("eventid", "")
    event_type = EVENT_TYPE_MAP.get(eventid)
    if event_type is None:
        # Not an event type we care about for AEI / CTI purposes -- skip.
        return None

    src_ip = raw.get("src_ip", "unknown")
    geo = lookup(src_ip)

    # raw_payload differs per event type -- pick the most meaningful field.
    if eventid == "cowrie.command.input":
        raw_payload = raw.get("input")
    elif eventid in ("cowrie.login.success", "cowrie.login.failed"):
        raw_payload = f"{raw.get('username')}:{raw.get('password')}"
    elif eventid == "cowrie.session.file_download":
        raw_payload = raw.get("url")
    else:
        raw_payload = None

    metadata = {k: v for k, v in raw.items() if k not in (
        "eventid", "timestamp", "session", "src_ip", "input"
    )}

    return UnifiedLogEvent(
        timestamp=datetime.fromisoformat(raw["timestamp"].replace("Z", "+00:00")),
        session_id=raw.get("session"),
        service="ssh",
        source_ip=src_ip,
        source_country=geo.country,
        source_city=geo.city,
        source_lat=geo.lat,
        source_lon=geo.lon,
        event_type=event_type,
        raw_payload=raw_payload,
        metadata=metadata,
    )


def parse_file(filepath: str) -> list[UnifiedLogEvent]:
    """Parse an entire Cowrie log file at once (used for batch/testing)."""
    events = []
    with open(filepath, "r") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)
    return events


if __name__ == "__main__":
    # Quick manual test against the sample file
    events = parse_file("sample_logs/ssh_cowrie.json")
    print(f"Parsed {len(events)} events from sample SSH log:\n")
    for e in events:
        print(f"  [{e.event_type}] session={e.session_id} ip={e.source_ip} payload={e.raw_payload!r}")
