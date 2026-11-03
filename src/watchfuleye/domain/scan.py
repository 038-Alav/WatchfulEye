from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from watchfuleye.domain.observation import Observation


class ScanStatus(str, Enum):
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class ProviderStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass
class ProviderExecutionResult:
    """
    Result of executing one discovery provider.
    """

    provider: str

    status: ProviderStatus

    observations: list[Observation] = field(default_factory=list)

    duration_ms: float = 0.0

    error: str | None = None


@dataclass
class ScanRun:
    """
    Represents a complete discovery execution.
    """

    network_cidr: str
    interface_name: str

    id: str = field(default_factory=lambda: str(uuid4()))

    status: ScanStatus = ScanStatus.RUNNING

    started_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    provider_results: list[ProviderExecutionResult] = field(
        default_factory=list
    )

    finished_at: datetime | None = None

    providers_executed: list[str] = field(default_factory=list)

    errors: list[str] = field(default_factory=list)

    @property
    def duration_ms(self) -> float | None:
        if self.finished_at is None:
            return None

        return (
            self.finished_at - self.started_at
        ).total_seconds() * 1000

    def finish(self, status: ScanStatus) -> None:
        self.status = status
        self.finished_at = datetime.now(timezone.utc)


@dataclass
class DiscoveryResult:
    """
    Complete result returned by DiscoveryEngine.
    """

    scan: ScanRun

    observations: list[Observation] = field(default_factory=list)

    provider_results: list[ProviderExecutionResult] = field(
        default_factory=list
    )

    @property
    def successful(self) -> bool:
        return self.scan.status in (
            ScanStatus.SUCCESS,
            ScanStatus.PARTIAL,
        )

    @property
    def errors(self) -> list[str]:
        """Warnings recorded by the engine, including optional enrichment."""
        return list(self.scan.errors)

    @property
    def discovered_count(self) -> int:
        return len(self.observations)
