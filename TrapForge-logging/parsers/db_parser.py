"""
parsers/db_parser.py
-----------------------
Parses DB (e.g. fake MySQL) honeypot logs in JSON-lines format:

    {"timestamp": "...", "session_id": "...", "src_ip": "...", "event": "query", "query": "SHOW DATABASES;"}

Event types:
    connection_attempt -> event_type="connection"
    auth_attempt        -> event_type="login_attempt"
    query               -> event_type="query"
    disconnect          -> event_type="session_closed"
"""

import json
from datetime import datetime
from typing import Optional

from schema import UnifiedLogEvent
from geoip import lookup


EVENT_TYPE_MAP = {
    "connection_attempt": "connection",
    "auth_attempt": "login_attempt",
    "query": "query",
    "disconnect": "session_closed",
}


def parse_line(line: str) -> Optional[UnifiedLogEvent]:
    """Parse a single line of DB honeypot JSON log output."""
    line = line.strip()
    if not line:
        return None

    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        print(f"[db_parser] WARNING: could not parse line as JSON: {line[:100]}")
        return None

    event = raw.get("event", "")
    event_type = EVENT_TYPE_MAP.get(event)
    if event_type is None:
        return None

    src_ip = raw.get("src_ip", "unknown")
    geo = lookup(src_ip)

    if event == "query":
        raw_payload = raw.get("query")
    elif event == "auth_attempt":
        raw_payload = f"{raw.get('username')}:{raw.get('password')}"
    else:
        raw_payload = None

    metadata = {k: v for k, v in raw.items() if k not in (
        "timestamp", "session_id", "src_ip", "event", "query"
    )}

    return UnifiedLogEvent(
        timestamp=datetime.fromisoformat(raw["timestamp"].replace("Z", "+00:00")),
        session_id=raw.get("session_id"),
        service="db",
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
    events = []
    with open(filepath, "r") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)
    return events


if __name__ == "__main__":
    events = parse_file("sample_logs/db_honeypot.json")
    print(f"Parsed {len(events)} events from sample DB log:\n")
    for e in events:
        print(f"  [{e.event_type}] session={e.session_id} ip={e.source_ip} payload={e.raw_payload!r}")
