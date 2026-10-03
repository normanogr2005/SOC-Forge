import re
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from .models import LogEvent


IP_PATTERN = r"from\s+([0-9A-Fa-f:.]+)"
TIMESTAMP_PATTERN = (
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
)


def parse_timestamp(
    line: str,
    now: datetime | None = None,
) -> datetime:
    """
    Extract the syslog timestamp from an auth.log line.

    Syslog entries do not contain a year, so the current UTC year is used
    with a rollover guard for logs from the previous December.
    """

    match = re.search(TIMESTAMP_PATTERN, line)

    if not match:
        raise ValueError(f"Unable to parse log timestamp: {line}")

    now = now or datetime.now(timezone.utc)
    year = now.year

    timestamp_text = (
        f"{year} "
        f"{match.group('month')} "
        f"{match.group('day')} "
        f"{match.group('time')}"
    )

    timestamp = datetime.strptime(
        timestamp_text,
        "%Y %b %d %H:%M:%S",
    ).replace(tzinfo=timezone.utc)

    # A January run can legitimately be processing late-December syslog
    # entries from the previous year. Treat timestamps more than one day in
    # the future as belonging to the previous year.
    if timestamp - now > timedelta(days=1):
        timestamp = timestamp.replace(year=year - 1)

    return timestamp


def parse_log_line(line: str) -> LogEvent | None:
    """
    Convert one auth.log line into a LogEvent.
    """

    line = line.strip()

    if not line:
        return None

    source_ip = None
    source_ip_match = re.search(IP_PATTERN, line)
    if source_ip_match:
        candidate = source_ip_match.group(1)
        try:
            source_ip = str(ip_address(candidate))
        except ValueError:
            source_ip = None

    if "Failed password" in line:
        event_type = "authentication_failed"
    elif "Accepted password" in line:
        event_type = "authentication_success"
    elif "Invalid password" in line:
        event_type = "authentication_failed"
    else:
        event_type = "unknown"

    return LogEvent(
        timestamp=parse_timestamp(line),
        source="auth.log",
        event_type=event_type,
        message=line,
        source_ip=source_ip,
    )


def parse_log_file(path: str) -> list[LogEvent]:
    """
    Read a complete log file and return its parsed events.
    """

    events: list[LogEvent] = []

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            event = parse_log_line(line)

            if event is not None:
                events.append(event)

    return events
