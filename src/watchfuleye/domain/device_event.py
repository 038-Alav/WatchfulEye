from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class DeviceEventType(str, Enum):
    DISCOVERED = "DISCOVERED"
    INFORMATION_UPDATED = "INFORMATION_UPDATED"
    STATUS_CHANGED = "STATUS_CHANGED"
    AVAILABILITY_CHANGED = "AVAILABILITY_CHANGED"
    MARKED_STALE = "MARKED_STALE"
    REMOVED = "REMOVED"


@dataclass
class DeviceEvent:
    device_id: str
    event_type: DeviceEventType
    id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    scan_id: str | None = None
    description: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.device_id:
            raise ValueError("Device ID cannot be empty.")

        if not isinstance(self.event_type, DeviceEventType):
            raise TypeError("event_type must be a DeviceEventType.")

        if self.timestamp.tzinfo is None:
            raise ValueError("Event timestamp must be timezone-aware.")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "device_id": self.device_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "scan_id": self.scan_id,
            "description": self.description,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DeviceEvent":
        return cls(
            id=data["id"],
            device_id=data["device_id"],
            event_type=DeviceEventType(data["event_type"]),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            scan_id=data.get("scan_id"),
            description=data.get("description", ""),
            details=data.get("details", {}),
        )
