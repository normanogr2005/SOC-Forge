from collections import Counter

from .models import Alert, LogEvent


FAILED_LOGIN_RULE = "AUTH-001"
BRUTE_FORCE_RULE = "AUTH-002"


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
    Detecta múltiples intentos fallidos desde una misma IP.
    """

    failed_ips = [
        event.source_ip
        for event in events
        if event.event_type == "authentication_failed"
        and event.source_ip is not None
    ]

    ip_counts = Counter(failed_ips)

    alerts = []

    for ip, count in ip_counts.items():
        if count >= 3:
            event = next(
                event
                for event in events
                if event.source_ip == ip
                and event.event_type == "authentication_failed"
            )

            alerts.append(
                Alert(
                    rule_id=BRUTE_FORCE_RULE,
                    severity="high",
                    message=(
                        f"Possible brute-force activity detected "
                        f"from {ip} ({count} failed attempts)"
                    ),
                    event=event,
                )
            )

    return alerts