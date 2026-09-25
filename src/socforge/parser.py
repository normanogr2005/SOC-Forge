import re
from datetime import datetime, timezone

from .models import LogEvent


IP_PATTERN = r"from\s+(\d{1,3}(?:\.\d{1,3}){3})"
TIMESTAMP_PATTERN = (
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
)


def parse_timestamp(line: str) -> datetime:
    """
    Extract the syslog timestamp from an auth.log line.

    Syslog entries do not contain a year, so the current UTC year
    is used when constructing the datetime.
    """

    match = re.search(TIMESTAMP_PATTERN, line)

    if not match:
        raise ValueError(f"Unable to parse log timestamp: {line}")

    year = datetime.now(timezone.utc).year

    timestamp_text = (
        f"{year} "
        f"{match.group('month')} "
        f"{match.group('day')} "
        f"{match.group('time')}"
    )

    return datetime.strptime(
        timestamp_text,
        "%Y %b %d %H:%M:%S",
    ).replace(tzinfo=timezone.utc)


def parse_log_line(line: str) -> LogEvent | None:
    """
    Convert one auth.log line into a LogEvent.
    """

    line = line.strip()

    if not line:
        return None

    source_ip_match = re.search(IP_PATTERN, line)
    source_ip = source_ip_match.group(1) if source_ip_match else None

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
