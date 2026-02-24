from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Device:
    ip: str
    mac: str = ""
    hostname: str = ""
    os_info: str = ""
    vendor: str = ""
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    is_online: bool = True
    open_ports: list[int] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        return self.hostname if self.hostname else self.ip
