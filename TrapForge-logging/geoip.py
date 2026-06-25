"""
geoip.py
---------
Lightweight IP -> geolocation lookup used to enrich every normalized
event with country/city/lat/lon, which feeds the "geographic attack
visualization" requirement of the project.

Uses the free MaxMind GeoLite2-City database. Download it from:
https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
(requires a free MaxMind account)

Place the downloaded file at: geoip_db/GeoLite2-City.mmdb

If the database file is not present, this module falls back to
returning None for all location fields so the pipeline still runs
end-to-end without crashing (useful for local testing with private
/ example IP ranges, which GeoLite2 cannot resolve anyway).
"""

import os
from typing import Optional
from dataclasses import dataclass

GEOIP_DB_PATH = os.path.join(os.path.dirname(__file__), "geoip_db", "GeoLite2-City.mmdb")

_reader = None
_geoip_available = False

try:
    import geoip2.database
    if os.path.exists(GEOIP_DB_PATH):
        _reader = geoip2.database.Reader(GEOIP_DB_PATH)
        _geoip_available = True
except ImportError:
    pass


@dataclass
class GeoResult:
    country: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None


def lookup(ip: str) -> GeoResult:
    """
    Look up geolocation for an IP address.
    Returns a GeoResult with all-None fields if lookup is unavailable
    or the IP is private/reserved (e.g. RFC 5737 test ranges used in
    sample data, like 203.0.113.x or 198.51.100.x).
    """
    if not _geoip_available:
        return GeoResult()

    try:
        response = _reader.city(ip)
        return GeoResult(
            country=response.country.name,
            city=response.city.name,
            lat=response.location.latitude,
            lon=response.location.longitude,
        )
    except Exception:
        # Covers AddressNotFoundError (private/reserved IPs, which is
        # exactly what our RFC 5737 sample IPs are) and any other
        # lookup failure. Fail soft -- a missing geo lookup should
        # never break ingestion.
        return GeoResult()
