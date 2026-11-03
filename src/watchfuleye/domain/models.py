from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from uuid import uuid4


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Device:
    id: str = field(default_factory=lambda: str(uuid4()))

    ip: str = ""
    mac: str = ""

    hostname: str = ""
    manufacturer: str = "Unknown"
    device_type: str = "Unknown"

    status: str = "UNKNOWN"

    first_seen: str = field(default_factory=utc_now)
    last_seen: str = field(default_factory=utc_now)

    latency_ms: float | None = None

    observations: list[dict] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        allowed_fields = cls.__dataclass_fields__.keys()

        filtered_data = {
            key: value
            for key, value in data.items()
            if key in allowed_fields
        }

        return cls(**filtered_data)