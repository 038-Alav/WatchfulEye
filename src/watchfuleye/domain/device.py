from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4


@dataclass
class Device:
    """
    Represents a device tracked by Watchful Eye.

    The internal UUID is the device identity.
    IP addresses and MAC addresses are properties
    and evidence, not permanent identifiers.
    """

    id: str = field(default_factory=lambda: str(uuid4()))

    ip: str | None = None
    mac: str | None = None
    hostname: str | None = None

    manufacturer: str | None = None
    device_type: str | None = None
    operating_system: str | None = None

    status: str = "UNKNOWN"

    first_seen: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    last_seen: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    latency_ms: float | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "manufacturer": self.manufacturer,
            "device_type": self.device_type,
            "operating_system": self.operating_system,
            "status": self.status,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "latency_ms": self.latency_ms,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Device":
        return cls(
            id=data["id"],
            ip=data.get("ip"),
            mac=data.get("mac"),
            hostname=data.get("hostname"),
            manufacturer=data.get("manufacturer"),
            device_type=data.get("device_type"),
            operating_system=data.get("operating_system"),
            status=data.get("status", "UNKNOWN"),
            first_seen=datetime.fromisoformat(data["first_seen"]),
            last_seen=datetime.fromisoformat(data["last_seen"]),
            latency_ms=data.get("latency_ms"),
        )
