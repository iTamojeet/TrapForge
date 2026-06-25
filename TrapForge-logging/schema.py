"""
schema.py
----------
Defines the unified log schema used across all honeypot services
(SSH, FTP, HTTP/web, DB). Every parser in parsers/ must produce
objects conforming to this schema before they are inserted into
MySQL.

This file is also the source of truth for the documentation in
docs/SCHEMA.md — if you change a field here, update the docs too.
"""

from __future__ import annotations
from datetime import datetime
from typing import Optional, Literal, Any
from pydantic import BaseModel, Field
import uuid


class UnifiedLogEvent(BaseModel):
    """
    The single normalized event format that every honeypot service
    (ssh, ftp, http, db) gets converted into before storage.
    """

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    session_id: Optional[str] = None
    service: Literal["ssh", "ftp", "http", "db"]
    source_ip: str
    source_country: Optional[str] = None
    source_city: Optional[str] = None
    source_lat: Optional[float] = None
    source_lon: Optional[float] = None
    event_type: str  # e.g. "login_attempt", "command", "file_transfer", "http_request", "query"
    raw_payload: Optional[str] = None  # the original command / request / query text
    metadata: dict[str, Any] = Field(default_factory=dict)  # service-specific extra fields

    class Config:
        json_schema_extra = {
            "example": {
                "event_id": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
                "timestamp": "2026-06-24T03:12:09.876Z",
                "session_id": "a1b2c3d4",
                "service": "ssh",
                "source_ip": "203.0.113.42",
                "source_country": "Russia",
                "source_city": "Moscow",
                "source_lat": 55.7558,
                "source_lon": 37.6173,
                "event_type": "command",
                "raw_payload": "cat /etc/passwd",
                "metadata": {"shell": "bash"},
            }
        }

    def to_mysql_params(self) -> dict:
        """Convert to a dict ready for the MySQL INSERT statement."""
        import json
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "session_id": self.session_id,
            "service": self.service,
            "source_ip": self.source_ip,
            "source_country": self.source_country,
            "source_city": self.source_city,
            "source_lat": self.source_lat,
            "source_lon": self.source_lon,
            "event_type": self.event_type,
            "raw_payload": self.raw_payload,
            "metadata": json.dumps(self.metadata),
        }


def export_json_schema(path: str = "docs/unified_log_schema.json") -> None:
    """Dump the formal JSON Schema for documentation purposes."""
    import json
    schema = UnifiedLogEvent.model_json_schema()
    with open(path, "w") as f:
        json.dump(schema, f, indent=2)


if __name__ == "__main__":
    export_json_schema()
    print("Schema exported.")
