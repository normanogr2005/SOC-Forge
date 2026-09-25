from datetime import datetime, timezone

from socforge.detector import detect_brute_force, detect_failed_login
from socforge.models import LogEvent


def create_event(message: str, source_ip: str) -> LogEvent:
    return LogEvent(
        timestamp=datetime.now(timezone.utc),
        source="ssh",
        event_type="authentication_failed",
        message=message,
        source_ip=source_ip,
    )


def test_detect_failed_login():
    event = create_event(
        "Failed password for user admin",
        "192.168.1.50",
    )

    alert = detect_failed_login(event)

    assert alert is not None
    assert alert.rule_id == "AUTH-001"
    assert alert.severity == "medium"


def test_ignore_normal_login():
    event = LogEvent(
        timestamp=datetime.now(timezone.utc),
        source="ssh",
        event_type="authentication_success",
        message="Accepted password for user admin",
        source_ip="192.168.1.50",
    )

    alert = detect_failed_login(event)

    assert alert is None


def test_detect_brute_force():
    events = [
        create_event("Failed password for user admin", "192.168.1.50"),
        create_event("Failed password for user root", "192.168.1.50"),
        create_event("Invalid password for user admin", "192.168.1.50"),
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "AUTH-002"
    assert alerts[0].severity == "high"
    assert alerts[0].event.source_ip == "192.168.1.50"


def test_no_brute_force_with_two_attempts():
    events = [
        create_event("Failed password for user admin", "192.168.1.50"),
        create_event("Failed password for user root", "192.168.1.50"),
    ]

    alerts = detect_brute_force(events)

    assert alerts == []