from datetime import datetime, timedelta, timezone

from socforge.detector import detect_brute_force, detect_failed_login
from socforge.models import LogEvent


def create_event(
    message: str,
    source_ip: str,
    timestamp: datetime | None = None,
) -> LogEvent:
    return LogEvent(
        timestamp=timestamp or datetime.now(timezone.utc),
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
    base = datetime(2026, 9, 25, 2, 10, 0, tzinfo=timezone.utc)

    events = [
        create_event(
            "Failed password for user admin",
            "192.168.1.50",
            base,
        ),
        create_event(
            "Failed password for user root",
            "192.168.1.50",
            base + timedelta(minutes=2),
        ),
        create_event(
            "Invalid password for user admin",
            "192.168.1.50",
            base + timedelta(minutes=4),
        ),
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "AUTH-002"
    assert alerts[0].severity == "high"
    assert alerts[0].event.source_ip == "192.168.1.50"


def test_no_brute_force_with_two_attempts():
    base = datetime(2026, 9, 25, 2, 10, 0, tzinfo=timezone.utc)

    events = [
        create_event(
            "Failed password for user admin",
            "192.168.1.50",
            base,
        ),
        create_event(
            "Failed password for user root",
            "192.168.1.50",
            base + timedelta(minutes=2),
        ),
    ]

    alerts = detect_brute_force(events)

    assert alerts == []


def test_no_brute_force_when_attempts_are_outside_window():
    base = datetime(2026, 9, 25, 2, 10, 0, tzinfo=timezone.utc)

    events = [
        create_event("Failed password for user admin", "192.168.1.50", base),
        create_event(
            "Failed password for user root",
            "192.168.1.50",
            base + timedelta(minutes=6),
        ),
        create_event(
            "Invalid password for user admin",
            "192.168.1.50",
            base + timedelta(minutes=12),
        ),
    ]

    alerts = detect_brute_force(events)

    assert alerts == []
