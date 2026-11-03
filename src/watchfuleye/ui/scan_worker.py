import traceback
from PySide6.QtCore import QObject, QRunnable, Signal, Slot

from watchfuleye.application.discovery_engine import DiscoveryEngine
from watchfuleye.domain.scan import DiscoveryResult


class WorkerSignals(QObject):
    progress = Signal(str)
    finished = Signal(object)
    failed = Signal(str)


class ScanWorker(QRunnable):

    def __init__(
        self,
        engine: DiscoveryEngine,
        network_cidr: str,
        interface_name: str,
        timeout_seconds: int = 2,
    ):
        super().__init__()

        self.engine = engine
        self.network_cidr = network_cidr
        self.interface_name = interface_name
        self.timeout_seconds = timeout_seconds

        self.signals = WorkerSignals()

    @Slot()
    def run(self):
        try:
            self.signals.progress.emit(
                f"Discovering devices on {self.network_cidr}..."
            )

            result = self.engine.discover(
                network_cidr=self.network_cidr,
                interface_name=self.interface_name,
                timeout_seconds=self.timeout_seconds,
            )

            if not isinstance(result, DiscoveryResult):
                raise TypeError(
                    "DiscoveryEngine must return a DiscoveryResult."
                )

            self.signals.finished.emit(result)

        except Exception as exc:
            traceback.print_exc()

            self.signals.failed.emit(
                f"{type(exc).__name__}: {exc}"
            )