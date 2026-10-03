import sqlite3
from pathlib import Path

from .models import Alert


DB_PATH = Path("socforge.db")


def _migrate_legacy_alerts(connection: sqlite3.Connection) -> None:
    columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(alerts)")
    }

    if "event_id" in columns:
        return

    connection.execute(
        """
        CREATE TABLE alerts_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL,
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
        INSERT INTO alerts_new (
            id,
            event_id,
            rule_id,
            severity,
            message,
            source_ip,
            event_message,
            timestamp
        )
        SELECT
            id,
            'legacy-' || id,
            rule_id,
            severity,
            message,
            source_ip,
            event_message,
            timestamp
        FROM alerts
        """
    )

    connection.execute("DROP TABLE alerts")
    connection.execute("ALTER TABLE alerts_new RENAME TO alerts")


def init_db() -> None:
    connection = sqlite3.connect(DB_PATH)

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                source_ip TEXT,
                event_message TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )

        _migrate_legacy_alerts(connection)

        connection.execute("DROP INDEX IF EXISTS ux_alert_identity")

        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS ux_alert_event_id
            ON alerts(event_id)
            """
        )

        connection.commit()

    finally:
        connection.close()


def save_alert(alert: Alert) -> None:
    connection = sqlite3.connect(DB_PATH)

    try:
        connection.execute(
            """
            INSERT OR IGNORE INTO alerts (
                event_id,
                rule_id,
                severity,
                message,
                source_ip,
                event_message,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.event.event_id,
                alert.rule_id,
                alert.severity,
                alert.message,
                alert.event.source_ip,
                alert.event.message,
                alert.event.timestamp.isoformat(),
            ),
        )

        connection.commit()

    finally:
        connection.close()
