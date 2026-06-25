# TrapForge — Centralized Logging: Data Schema & Pipeline Documentation

**Member 2 deliverable** — Adaptive Multi-Service Deception Framework with AEI

---

## 1. Overview

This document describes the centralized logging subsystem that ingests
events from all deceptive services (SSH, FTP, HTTP/web, DB) into a single
unified schema, in real time, for downstream use by the AEI scoring engine
and CTI output layer.

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│ SSH Honeypot│   │ FTP Honeypot│   │ Web Honeypot│   │ DB Honeypot │
│  (Cowrie)   │   │             │   │             │   │             │
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       │ writes log file  │ writes log file  │ writes log file  │ writes log file
       ▼                  ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│              realtime_watcher.py  (filesystem watcher)               │
│   detects new lines appended to each log file the instant they      │
│   are written, using OS-level inotify events (via `watchdog`)       │
└──────────────────────────────┬────────────────────────────────────┘
                                │  raw log line
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│   Service-specific parser (parsers/ssh_parser.py, ftp_parser.py,     │
│   web_parser.py, db_parser.py)                                      │
│   - extracts fields from raw format                                 │
│   - enriches with GeoIP (geoip.py)                                  │
│   - returns a UnifiedLogEvent (schema.py)                           │
└──────────────────────────────┬────────────────────────────────────┘
                                │  UnifiedLogEvent object
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       db_writer.py                                  │
│           INSERT into MySQL `unified_logs` table                    │
│           (connection-pooled, fails soft on error)                  │
└──────────────────────────────┬────────────────────────────────────┘
                                ▼
                    ┌───────────────────────┐
                    │   MySQL: trapforge_logs│
                    │      unified_logs table│
                    └───────────────────────┘
                                │
                    consumed by AEI engine, adaptation
                    engine, and CTI dashboard (other members)
```

---

## 2. Unified Schema

All events from all four services are normalized into a single table,
`unified_logs`, regardless of source service. This is the core design
decision of this subsystem: downstream consumers (AEI calculator,
dashboards, threat feed generator) only ever need to query **one** table
with **one** consistent shape, rather than knowing the internal log format
of every honeypot.

| Field | Type | Description |
|---|---|---|
| `event_id` | VARCHAR(36) | UUID, globally unique per event. Primary key. |
| `timestamp` | DATETIME(3) | When the event occurred at the honeypot (millisecond precision), as reported by the honeypot's own log, NOT ingestion time. |
| `session_id` | VARCHAR(64) | Groups events belonging to the same attacker session. Source varies (see §4 Known Limitations for HTTP). |
| `service` | ENUM | One of `ssh`, `ftp`, `http`, `db`. |
| `source_ip` | VARCHAR(45) | Attacker's source IP (IPv4 or IPv6). |
| `source_country` | VARCHAR(100) | GeoIP-resolved country name. NULL if lookup unavailable/failed. |
| `source_city` | VARCHAR(100) | GeoIP-resolved city name. NULL if lookup unavailable/failed. |
| `source_lat` / `source_lon` | DOUBLE | GeoIP-resolved coordinates, feeds the geographic attack visualization. |
| `event_type` | VARCHAR(50) | Normalized event category — see §3. |
| `raw_payload` | TEXT | The most meaningful original content of the event (a command, a query, an HTTP request line, login credentials attempted). |
| `metadata` | JSON | Service-specific extra fields that don't fit the common columns (e.g. HTTP status code, FTP file size, SSH file SHA hash). |
| `ingested_at` | DATETIME(3) | When this row was actually written to MySQL — used to measure ingestion latency (event `timestamp` vs `ingested_at`), which demonstrates the "real-time" claim quantitatively for the paper. |

Full JSON Schema is auto-generated from the Pydantic model in `schema.py`
and exported to `docs/unified_log_schema.json` (run `python schema.py` to
regenerate after any schema change).

---

## 3. Normalized Event Types

Regardless of source service, every event is tagged with one of these
`event_type` values, which is what lets the AEI engine compute cross-service
metrics like "interaction depth" and "command diversity" uniformly:

| `event_type` | Meaning | Present in services |
|---|---|---|
| `connection` | A new session/connection was opened | ssh, ftp, db |
| `login_attempt` | Credentials were submitted (success or failure in `metadata`) | ssh, ftp, db |
| `command` | An interactive command was issued | ssh, ftp |
| `query` | A database query was issued | db |
| `http_request` | An HTTP request was made | http |
| `file_transfer` | A file was uploaded or downloaded | ssh, ftp |
| `session_closed` | The session/connection ended | ssh, ftp, db |

---

## 4. Per-Service Mapping Details

### 4.1 SSH (Cowrie)
- **Source format:** JSON-lines, one Cowrie event object per line.
- **Parser:** `parsers/ssh_parser.py`
- **Session grouping:** Cowrie's native `session` field, used directly.
- **Reference:** https://docs.cowrie.org/en/latest/events.html

### 4.2 FTP
- **Source format:** Plaintext log lines: `TIMESTAMP LEVEL [source] EVENT key=value key=value ...`
- **Parser:** `parsers/ftp_parser.py`
- **Session grouping:** Native `session` key from the log line.
- **Note:** This format is a placeholder based on common simple FTP honeypot implementations. **Once Member 1 provides the actual FTP honeypot's log output, this parser's regex must be re-validated against the real format** — the rest of the pipeline (schema, watcher, DB writer) will not need to change.

### 4.3 HTTP / Web
- **Source format:** Standard Apache/nginx "combined" access log format.
- **Parser:** `parsers/web_parser.py`
- **Session grouping:** **Known limitation** — standard web access logs carry no native session ID. We currently group by `web-{source_ip}` as a coarse proxy. A more accurate approach (recommended follow-up) is to have the decoy web app set a tracking cookie/session token so true session boundaries can be recovered.
- **Exploitation detection:** A simple regex heuristic (`_is_suspicious()` in the parser) flags requests matching common attack patterns (path traversal, SQLi, XSS, command injection) into `metadata.suspicious`. This feeds AEI's "exploitation attempts" sub-metric directly.

### 4.4 DB
- **Source format:** JSON-lines, one event object per line.
- **Parser:** `parsers/db_parser.py`
- **Session grouping:** Native `session_id` field.
- **Note:** Also a placeholder format pending Member 1's actual DB honeypot implementation.

---

## 5. Real-Time Ingestion Design

**Requirement:** logs must flow in as attacks happen, not in batches.

**Implementation:** `realtime_watcher.py` uses the `watchdog` library, which
relies on OS-level filesystem notification APIs (`inotify` on Linux) rather
than polling on a timer. This means:

- New lines are detected within milliseconds of being written by the
  honeypot process — there is no fixed polling interval to wait out.
- Each watched file's last-read byte offset is tracked in memory, so on
  each filesystem notification we only read and process the **newly
  appended** bytes, never re-scanning the whole file.
- Each new line is parsed, normalized, and inserted into MySQL
  individually and immediately — there is no batching window.

**Measuring "real-time" quantitatively (for the paper):** because the
schema stores both the honeypot-reported `timestamp` and the
database-assigned `ingested_at`, the ingestion latency for any event can
be computed directly in SQL:

```sql
SELECT
    service,
    AVG(TIMESTAMPDIFF(MICROSECOND, timestamp, ingested_at)) / 1000 AS avg_latency_ms,
    MAX(TIMESTAMPDIFF(MICROSECOND, timestamp, ingested_at)) / 1000 AS max_latency_ms
FROM unified_logs
GROUP BY service;
```

This gives a defensible, measured latency figure rather than just an
architectural claim of "real-time."

**Fault tolerance:** a malformed log line, a parser exception, or a failed
MySQL insert are all caught and logged individually — one bad event never
stops the watcher from processing subsequent events. This matters because
honeypots are exposed to genuinely adversarial, often malformed/malicious
input by design.

---

## 6. Known Limitations / Future Work

1. **HTTP session grouping** is IP-based, not a true session token (see §4.3).
2. **Placeholder log formats** for FTP and DB parsers are based on common
   honeypot conventions, not Member 1's actual implementation — these two
   parsers need re-validation once real honeypots are deployed (the schema
   and rest of the pipeline are unaffected).
3. **GeoIP database** (MaxMind GeoLite2) is not bundled in this repo (license
   requires a free account) — must be downloaded separately; see `geoip.py`
   docstring for the download link. Without it, location fields are NULL but
   the pipeline still runs.
4. **Connection-pooling** is currently sized for single-machine local testing
   (pool size 5) — should be tuned once deployed against real, sustained
   attacker traffic volume.

---

## 7. File Reference

| File | Purpose |
|---|---|
| `schema.py` | Pydantic model defining `UnifiedLogEvent`; single source of truth for the schema |
| `geoip.py` | IP → location enrichment, shared by all parsers |
| `parsers/ssh_parser.py` | Cowrie SSH log → UnifiedLogEvent |
| `parsers/ftp_parser.py` | FTP honeypot log → UnifiedLogEvent |
| `parsers/web_parser.py` | Web access log → UnifiedLogEvent |
| `parsers/db_parser.py` | DB honeypot log → UnifiedLogEvent |
| `db_writer.py` | Inserts UnifiedLogEvent objects into MySQL |
| `realtime_watcher.py` | Watches log files, triggers real-time ingestion |
| `backfill.py` | One-off bulk ingestion of existing log files |
| `sample_logs/` | Representative sample logs for each service, used for testing |
