from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4


@dataclass
class LogEvent:
    timestamp: datetime
    source: str
    event_type: str
    message: str
    source_ip: str | None = None
    event_id: str = field(default_factory=lambda: str(uuid4()))


@dataclass
class Alert:
    rule_id: str
    severity: str
    message: str
    event: LogEvent
