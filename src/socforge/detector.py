from collections import defaultdict
from datetime import timedelta

from .models import Alert, LogEvent


FAILED_LOGIN_RULE = "AUTH-001"
BRUTE_FORCE_RULE = "AUTH-002"
BRUTE_FORCE_WINDOW = timedelta(minutes=5)
BRUTE_FORCE_THRESHOLD = 3


def detect_failed_login(event: LogEvent) -> Alert | None:
    """
    Detecta intentos fallidos de autenticación.
    """

    message = event.message.lower()

    failed_login_patterns = [
        "failed password",
        "authentication failure",
        "login failed",
        "invalid password",
    ]

    if any(pattern in message for pattern in failed_login_patterns):
        return Alert(
            rule_id=FAILED_LOGIN_RULE,
            severity="medium",
            message="Possible failed authentication attempt",
            event=event,
        )

    return None


def detect_brute_force(events: list[LogEvent]) -> list[Alert]:
    """
    Detecta múltiples intentos fallidos desde una misma IP
    dentro de una ventana temporal de 5 minutos.
    """

    failed_by_ip: dict[str, list[LogEvent]] = defaultdict(list)

    for event in events:
        if (
            event.event_type == "authentication_failed"
            and event.source_ip is not None
        ):
            failed_by_ip[event.source_ip].append(event)

    alerts: list[Alert] = []

    for ip, ip_events in failed_by_ip.items():
        ip_events.sort(key=lambda event: event.timestamp)

        for index, event in enumerate(ip_events):
            window_start = event.timestamp
            window_end = window_start + BRUTE_FORCE_WINDOW

            attempts = [
                candidate
                for candidate in ip_events[index:]
                if candidate.timestamp <= window_end
            ]

            if len(attempts) >= BRUTE_FORCE_THRESHOLD:
                alerts.append(
                    Alert(
                        rule_id=BRUTE_FORCE_RULE,
                        severity="high",
                        message=(
                            f"Possible brute-force activity detected "
                            f"from {ip} ({len(attempts)} failed attempts "
                            f"within {int(BRUTE_FORCE_WINDOW.total_seconds() / 60)} minutes)"
                        ),
                        event=event,
                    )
                )
                break

    return alerts
