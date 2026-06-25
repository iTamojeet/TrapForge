"""
parsers/web_parser.py
------------------------
Parses web honeypot access logs in standard Apache/nginx "combined"
log format:

    192.0.2.88 - - [24/Jun/2026:03:30:05 +0000] "GET /wp-login.php HTTP/1.1" 200 1843 "-" "Mozilla/5.0 ..."

This is the format produced by basically any web server (including
a Flask/DVWA-style decoy app sitting behind nginx), so this parser
should work regardless of exactly which fake web app Member 1 builds,
as long as access logging is in combined format.
"""

import re
from datetime import datetime
from typing import Optional

from schema import UnifiedLogEvent
from geoip import lookup


COMBINED_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request_line>[^"]*)" '
    r'(?P<status>\d+) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"$'
)
# NOTE: we deliberately capture the whole request line as one blob rather
# than splitting method/path/protocol directly in the regex. Attacker
# payloads (e.g. SQL injection in a query string) frequently contain raw,
# unencoded spaces -- a strict "METHOD \S+ PROTOCOL" pattern silently
# fails to match those lines and drops them. We split method/path/protocol
# manually after matching instead, which tolerates spaces inside the path.

# Simple heuristics to flag likely exploitation attempts in the request
# path -- useful for AEI's "exploitation_attempts" sub-metric later.
SUSPICIOUS_PATTERNS = [
    r"\.\./",            # path traversal
    r"(?i)union\s+select",  # SQL injection
    r"(?i)'.*or.*'1'='1",   # classic SQLi
    r"(?i)<script",        # XSS attempt
    r"(?i)cmd=",            # command injection via query param
    r"(?i)/etc/passwd",
    r"(?i)wp-login\.php",
]


def _is_suspicious(path: str) -> bool:
    return any(re.search(pattern, path) for pattern in SUSPICIOUS_PATTERNS)


def parse_line(line: str) -> Optional[UnifiedLogEvent]:
    """Parse a single line of combined-format web access log."""
    line = line.strip()
    if not line:
        return None

    match = COMBINED_LOG_PATTERN.match(line)
    if not match:
        print(f"[web_parser] WARNING: line did not match combined log format: {line[:100]}")
        return None

    parts = match.groupdict()
    src_ip = parts["ip"]
    geo = lookup(src_ip)

    timestamp = datetime.strptime(parts["timestamp"], "%d/%b/%Y:%H:%M:%S %z")

    # Split "METHOD /path/with possible spaces HTTP/1.1" manually:
    # method = first token, protocol = last token, path = everything between.
    request_line = parts["request_line"]
    try:
        method, remainder = request_line.split(" ", 1)
        path, _, protocol = remainder.rpartition(" ")
    except ValueError:
        # Malformed request line (e.g. just "-" for some scanners) -- skip gracefully.
        print(f"[web_parser] WARNING: could not split request line: {request_line!r}")
        return None

    raw_payload = f"{method} {path}"

    metadata = {
        "method": method,
        "path": path,
        "protocol": protocol,
        "status_code": int(parts["status"]),
        "response_size": parts["size"],
        "user_agent": parts["user_agent"],
        "suspicious": _is_suspicious(path),
    }

    # Web logs typically have no explicit session ID -- use IP+user-agent
    # as a loose session grouping key for now. This is a known limitation;
    # see docs/SCHEMA.md "Known Limitations" section.
    session_id = f"web-{src_ip}"

    return UnifiedLogEvent(
        timestamp=timestamp,
        session_id=session_id,
        service="http",
        source_ip=src_ip,
        source_country=geo.country,
        source_city=geo.city,
        source_lat=geo.lat,
        source_lon=geo.lon,
        event_type="http_request",
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
    events = parse_file("sample_logs/web_access.log")
    print(f"Parsed {len(events)} events from sample web log:\n")
    for e in events:
        flag = " [SUSPICIOUS]" if e.metadata.get("suspicious") else ""
        print(f"  [{e.event_type}] ip={e.source_ip} payload={e.raw_payload!r}{flag}")
