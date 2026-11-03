from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4


class ObservationType(str, Enum):
    IP_ADDRESS = "ip_address"
    MAC_ADDRESS = "mac_address"
    HOSTNAME = "hostname"
    MANUFACTURER = "manufacturer"
    OPERATING_SYSTEM = "operating_system"
    SERVICE = "service"
    PORT = "port"
    TTL = "ttl"
    DEVICE_TYPE = "device_type"
    OTHER = "other"


@dataclass
class Observation:
    """
    Represents a single piece of evidence collected
    by a discovery or enrichment component.

    An observation does not establish permanent device
    identity. That association is handled later by
    DeviceIdentityResolver.

    correlation_id groups observations originating from
    the same discovery response or evidence collection.
    It is not a permanent device identifier.
    """

    scan_id: str
    source: str
    type: ObservationType
    value: str

    id: str = field(default_factory=lambda: str(uuid4()))

    device_id: str | None = None
    correlation_id: str | None = None

    confidence: float = 1.0

    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    interface: str | None = None

    def __post_init__(self):
        if not self.source.strip():
            raise ValueError("Observation source cannot be empty.")

        if not self.value.strip():
            raise ValueError("Observation value cannot be empty.")

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "Observation confidence must be between 0.0 and 1.0."
            )

        if self.timestamp.tzinfo is None:
            raise ValueError(
                "Observation timestamp must be timezone-aware."
            )

        if (
            self.correlation_id is not None
            and not self.correlation_id.strip()
        ):
            raise ValueError(
                "Correlation ID cannot be empty."
            )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "device_id": self.device_id,
            "correlation_id": self.correlation_id,
            "source": self.source,
            "type": self.type.value,
            "value": self.value,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "interface": self.interface,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Observation":
        return cls(
            id=data["id"],
            scan_id=data["scan_id"],
            device_id=data.get("device_id"),
            correlation_id=data.get("correlation_id"),
            source=data["source"],
            type=ObservationType(data["type"]),
            value=data["value"],
            confidence=float(data.get("confidence", 1.0)),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            interface=data.get("interface"),
        )
