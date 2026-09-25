from dataclasses import dataclass
from datetime import datetime


@dataclass
class LogEvent:
    timestamp: datetime
    source: str
    event_type: str
    message: str
    source_ip: str | None = None


@dataclass
class Alert:
    rule_id: str
    severity: str
    message: str
    event: LogEvent