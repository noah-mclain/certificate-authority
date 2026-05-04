import datetime


def utcnow():
    """Return a timezone-aware UTC datetime"""
    return datetime.datetime.now(datetime.timezone.utc)


def parse_iso_utc(s: str) -> datetime.datetime:
    """Parse an ISO datetime string, assuming UTC if naive"""
    dt = datetime.datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt
