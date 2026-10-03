from datetime import datetime, timezone

from socforge.parser import parse_log_line, parse_timestamp


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
    assert event.event_id

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


def test_invalid_source_ip_is_not_trusted():
    line = (
        "Sep 25 02:10:05 sansan sshd[1203]: "
        "Failed password for user admin from 999.999.999.999"
    )

    event = parse_log_line(line)

    assert event is not None
    assert event.event_type == "authentication_failed"
    assert event.source_ip is None


def test_identical_log_lines_get_distinct_event_ids():
    line = (
        "Sep 25 02:10:05 sansan sshd[1204]: "
        "Failed password for user admin from 192.168.1.50"
    )

    first = parse_log_line(line)
    second = parse_log_line(line)

    assert first is not None
    assert second is not None
    assert first.event_id != second.event_id


def test_previous_year_syslog_rollover():
    line = "Dec 31 23:59:59 sansan sshd[1205]: Failed password for user admin"
    reference = datetime(2027, 1, 1, 0, 30, tzinfo=timezone.utc)

    timestamp = parse_timestamp(line, reference)

    assert timestamp == datetime(
        2026,
        12,
        31,
        23,
        59,
        59,
        tzinfo=timezone.utc,
    )


def test_ignore_blank_log_line():
    assert parse_log_line("   ") is None
