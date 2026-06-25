# TrapForge — Centralized Log Collection & Storage (Member 2)

Normalizes logs from SSH, FTP, HTTP, and DB honeypots into a single MySQL
table in real time. See `docs/SCHEMA.md` for full schema and pipeline
documentation (this is the file to reference/adapt for the paper).

## Setup

1. Make sure your MySQL container (from `docker-compose.yml`) is running:
   ```
   docker compose up -d
   ```
2. Install Python dependencies:
   ```
   pip install -r requirements.txt
   ```
3. (Optional) Download MaxMind GeoLite2-City database for IP geolocation,
   place at `geoip_db/GeoLite2-City.mmdb`. Without it, location fields are
   simply NULL — everything else still works.

## Project Structure

```
trapforge-logging/
├── docker-compose.yml       # MySQL + Adminer (from earlier setup)
├── schema.py                # Unified log schema (Pydantic model)
├── geoip.py                 # IP -> location lookup helper
├── db_writer.py             # MySQL insert logic
├── realtime_watcher.py      # Real-time ingestion (the main deliverable)
├── backfill.py              # One-off bulk ingestion / testing helper
├── parsers/
│   ├── ssh_parser.py        # Cowrie SSH logs -> unified schema
│   ├── ftp_parser.py        # FTP honeypot logs -> unified schema
│   ├── web_parser.py        # Web access logs -> unified schema
│   └── db_parser.py         # DB honeypot logs -> unified schema
├── sample_logs/             # Representative sample logs for testing
└── docs/
    └── SCHEMA.md            # Full documentation (paper-ready)
```

## How to Test It

### 1. One-time backfill test (verifies the whole pipeline works)

```
python backfill.py
```

This parses all four sample log files and inserts every event into MySQL.
Check the row count printed before/after, then open Adminer
(http://localhost:8080) and run:

```sql
SELECT service, event_type, COUNT(*) FROM unified_logs GROUP BY service, event_type;
```

You should see a breakdown across all four services.

### 2. Real-time ingestion test (the actual deliverable)

In one terminal:

```
python realtime_watcher.py
```

Leave it running. In a **second terminal**, simulate a live attack by
appending a new line to one of the watched files:

```
echo {"eventid": "cowrie.command.input", "timestamp": "2026-06-24T04:00:00.000Z", "session": "live-test-1", "src_ip": "203.0.113.99", "input": "whoami"} >> sample_logs/ssh_cowrie.json
```

You should see the first terminal immediately print an `[OK]` line showing
the event was parsed and inserted — within about a second of appending it.
That's your real-time ingestion proof.

## Switching to Real Honeypot Logs

Once Member 1's actual honeypots are deployed, update the file paths in
`WATCHED_FILES` (in `realtime_watcher.py`) and `SOURCES` (in `backfill.py`)
to point at the real log file locations. If the real log *format* differs
from the placeholder formats used here (likely for FTP and DB, see
`docs/SCHEMA.md` §6), only the relevant parser file needs updating — the
schema, watcher, and database layer are unaffected.
