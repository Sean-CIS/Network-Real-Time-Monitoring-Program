from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"
    state: str = "unknown"
    service: str = ""
    version: str = ""


@dataclass
class ScanResult:
    target_ip: str
    ports: list[PortResult] = field(default_factory=list)
    scan_time: datetime = field(default_factory=datetime.now)
    scan_duration_s: float = 0.0
    os_match: str = ""
