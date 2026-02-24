from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertType(Enum):
    BANDWIDTH_HIGH = "bandwidth_high"
    LATENCY_HIGH = "latency_high"
    DEVICE_OFFLINE = "device_offline"
    DEVICE_NEW = "device_new"
    PORT_CHANGE = "port_change"


@dataclass
class Alert:
    alert_type: AlertType
    severity: AlertSeverity
    message: str
    source: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    acknowledged: bool = False
    id: Optional[int] = None
