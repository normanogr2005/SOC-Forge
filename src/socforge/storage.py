import sqlite3
from pathlib import Path

from .models import Alert


DB_PATH = Path("socforge.db")


def init_db() -> None:
    connection = sqlite3.connect(DB_PATH)

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
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
            CREATE UNIQUE INDEX IF NOT EXISTS ux_alert_identity
            ON alerts(rule_id, source_ip, event_message)
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
                rule_id,
                severity,
                message,
                source_ip,
                event_message,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
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