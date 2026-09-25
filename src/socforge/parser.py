import re
from datetime import datetime, timezone

from .models import LogEvent


IP_PATTERN = r"from\s+(\d{1,3}(?:\.\d{1,3}){3})"


def parse_log_line(line: str) -> LogEvent | None:
    """
    Convierte una línea de auth.log en un LogEvent.
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
        timestamp=datetime.now(timezone.utc),
        source="auth.log",
        event_type=event_type,
        message=line,
        source_ip=source_ip,
    )


def parse_log_file(path: str) -> list[LogEvent]:
    """
    Lee un archivo completo y devuelve los eventos reconocidos.
    """

    events: list[LogEvent] = []

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            event = parse_log_line(line)

            if event is not None:
                events.append(event)

    return events