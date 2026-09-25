from datetime import datetime, timezone

from socforge.parser import parse_log_line


def test_parse_failed_authentication_line():
    line = (
        "Sep 25 02:10:01 sansan sshd[1201]: "
        "Failed password for user admin from 192.168.1.50"
    )

    event = parse_log_line(line)

    assert event is not None
    assert event.source == "auth.log"
    assert event.event_type == "authentication_failed"
    assert event.source_ip == "192.168.1.50"
    assert event.message == line

    current_year = datetime.now(timezone.utc).year

    assert event.timestamp == datetime(
        current_year,
        9,
        25,
        2,
        10,
        1,
        tzinfo=timezone.utc,
    )


def test_parse_successful_authentication_line():
    line = (
        "Sep 25 02:10:05 sansan sshd[1202]: "
        "Accepted password for user norman from 192.168.1.20"
    )

    event = parse_log_line(line)

    assert event is not None
    assert event.event_type == "authentication_success"
    assert event.source_ip == "192.168.1.20"


def test_ignore_blank_log_line():
    assert parse_log_line("   ") is None
