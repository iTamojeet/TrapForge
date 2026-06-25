"""
db_writer.py
-------------
Handles writing UnifiedLogEvent objects into the central MySQL
'unified_logs' table. Used by both the real-time watcher and any
batch/backfill scripts.

Connection settings are read from environment variables with sensible
defaults matching the docker-compose.yml setup, so this works out of
the box for local dev and can be overridden for other environments
(e.g. a teammate's machine, or a cloud-hosted MySQL instance later).
"""

import os
import mysql.connector
from mysql.connector import pooling

from schema import UnifiedLogEvent


DB_CONFIG = {
    "host": os.environ.get("TRAPFORGE_DB_HOST", "localhost"),
    "port": int(os.environ.get("TRAPFORGE_DB_PORT", 3306)),
    "user": os.environ.get("TRAPFORGE_DB_USER", "trapforge_user"),
    "password": os.environ.get("TRAPFORGE_DB_PASSWORD", "trapforge_pass"),
    "database": os.environ.get("TRAPFORGE_DB_NAME", "trapforge_logs"),
}

INSERT_SQL = """
    INSERT INTO unified_logs
        (event_id, timestamp, session_id, service, source_ip,
         source_country, source_city, source_lat, source_lon,
         event_type, raw_payload, metadata)
    VALUES
        (%(event_id)s, %(timestamp)s, %(session_id)s, %(service)s, %(source_ip)s,
         %(source_country)s, %(source_city)s, %(source_lat)s, %(source_lon)s,
         %(event_type)s, %(raw_payload)s, %(metadata)s)
"""

# Connection pool so the real-time watcher doesn't open a brand-new
# TCP connection to MySQL for every single event -- important once
# you're handling bursts of attacker activity.
_pool = None


def _get_pool():
    global _pool
    if _pool is None:
        _pool = pooling.MySQLConnectionPool(
            pool_name="trapforge_pool",
            pool_size=5,
            **DB_CONFIG,
        )
    return _pool


def insert_event(event: UnifiedLogEvent) -> bool:
    """
    Insert a single normalized event into MySQL.
    Returns True on success, False on failure (and prints the error
    rather than crashing -- a single bad insert should never take
    down the whole real-time ingestion loop).
    """
    conn = None
    try:
        conn = _get_pool().get_connection()
        cursor = conn.cursor()
        cursor.execute(INSERT_SQL, event.to_mysql_params())
        conn.commit()
        cursor.close()
        return True
    except mysql.connector.Error as err:
        print(f"[db_writer] ERROR inserting event {event.event_id}: {err}")
        return False
    finally:
        if conn is not None:
            conn.close()  # returns connection to the pool


def insert_events_batch(events: list[UnifiedLogEvent]) -> int:
    """
    Insert multiple events at once (used for backfilling from
    existing log files). Returns count of successful inserts.
    """
    success_count = 0
    for event in events:
        if insert_event(event):
            success_count += 1
    return success_count


def get_total_row_count() -> int:
    """Quick helper to check row count -- useful for verifying ingestion worked."""
    conn = _get_pool().get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM unified_logs")
    count = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return count


if __name__ == "__main__":
    print(f"Current row count in unified_logs: {get_total_row_count()}")
