import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from socforge.models import Alert, LogEvent
from socforge.storage import init_db, save_alert
import socforge.storage as storage


def make_alert(event_id: str, message: str = "Failed password for user admin") -> Alert:
    event = LogEvent(
        timestamp=datetime(2026, 10, 3, 9, 0, tzinfo=timezone.utc),
        source="auth.log",
        event_type="authentication_failed",
        message=message,
        source_ip="192.168.1.50",
        event_id=event_id,
    )
    return Alert(
        rule_id="AUTH-001",
        severity="medium",
        message="Possible failed authentication attempt",
        event=event,
    )


def test_distinct_events_with_same_content_are_persisted(tmp_path: Path):
    db_path = tmp_path / "socforge.db"

    with patch.object(storage, "DB_PATH", db_path):
        init_db()

        save_alert(make_alert("event-001"))
        save_alert(make_alert("event-002"))

        connection = sqlite3.connect(db_path)
        try:
            count = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        finally:
            connection.close()

    assert count == 2


def test_duplicate_event_id_is_ignored(tmp_path: Path):
    db_path = tmp_path / "socforge.db"

    with patch.object(storage, "DB_PATH", db_path):
        init_db()

        alert = make_alert("event-001")
        save_alert(alert)
        save_alert(alert)

        connection = sqlite3.connect(db_path)
        try:
            count = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        finally:
            connection.close()

    assert count == 1


def test_legacy_database_is_migrated(tmp_path: Path):
    db_path = tmp_path / "legacy.db"

    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            """
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                source_ip TEXT,
                event_message TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX ux_alert_identity
            ON alerts(rule_id, source_ip, event_message)
            """
        )
        connection.execute(
            """
            INSERT INTO alerts (
                rule_id, severity, message, source_ip, event_message, timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "AUTH-001",
                "medium",
                "legacy alert",
                "192.168.1.50",
                "legacy message",
                "2026-10-03T09:00:00+00:00",
            ),
        )
        connection.commit()
    finally:
        connection.close()

    with patch.object(storage, "DB_PATH", db_path):
        init_db()

    connection = sqlite3.connect(db_path)
    try:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(alerts)")
        }
        event_id = connection.execute(
            "SELECT event_id FROM alerts WHERE id = 1"
        ).fetchone()[0]
        indexes = {
            row[1]
            for row in connection.execute("PRAGMA index_list(alerts)")
        }
    finally:
        connection.close()

    assert "event_id" in columns
    assert event_id == "legacy-1"
    assert "ux_alert_event_id" in indexes
    assert "ux_alert_identity" not in indexes
