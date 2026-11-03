import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from watchfuleye.discovery.arp_provider import ArpDiscoveryProvider
from watchfuleye.discovery.dhcp_discovery_provider import DhcpDiscoveryProvider
from watchfuleye.discovery.mdns_provider import MDNSProvider
from watchfuleye.discovery.netbios_provider import NetBIOSProvider

from watchfuleye.application.discovery_registry import DiscoveryRegistry
from watchfuleye.application.discovery_coordinator import DiscoveryCoordinator
from watchfuleye.application.discovery_engine import DiscoveryEngine

from watchfuleye.persistence.device_repository import DeviceRepository
from watchfuleye.persistence.scan_repository import ScanRepository
from watchfuleye.persistence.observation_repository import ObservationRepository

from watchfuleye.infrastructure.logging_config import configure_logging
from watchfuleye.infrastructure.paths import (
    get_user_data_directory,
    migrate_legacy_data,
)

from watchfuleye.ui.main_window import MainWindow


DATA_DIRECTORY = get_user_data_directory() / "data"
LEGACY_DATA_DIRECTORY = Path(__file__).resolve().parents[2] / "data"
DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)
migrate_legacy_data(LEGACY_DATA_DIRECTORY, DATA_DIRECTORY)


def create_discovery_engine():

    registry = DiscoveryRegistry()

    # --------------------------------------------------
    # Discovery providers
    # --------------------------------------------------

    arp_provider = ArpDiscoveryProvider()
    dhcp_provider = DhcpDiscoveryProvider()
    mdns_provider = MDNSProvider()
    netbios_provider = NetBIOSProvider()

    registry.register(arp_provider, enabled=True)
    registry.register(dhcp_provider, enabled=True)
    registry.register(mdns_provider, enabled=True)
    registry.register(netbios_provider, enabled=True)

    # --------------------------------------------------
    # Provider coordination
    # --------------------------------------------------

    coordinator = DiscoveryCoordinator(registry)

    # --------------------------------------------------
    # Repositories
    # --------------------------------------------------

    device_repository = DeviceRepository(
        DATA_DIRECTORY / "devices.json"
    )

    scan_repository = ScanRepository(
        DATA_DIRECTORY / "scans.json"
    )

    observation_repository = ObservationRepository(
        DATA_DIRECTORY / "observations.json"
    )

    # --------------------------------------------------
    # Discovery engine
    # --------------------------------------------------

    engine = DiscoveryEngine(
        coordinator=coordinator,
        scan_repository=scan_repository,
        observation_repository=observation_repository,
        device_repository=device_repository,
    )

    return engine, dhcp_provider


def main():

    configure_logging()

    app = QApplication(sys.argv)
    app.setApplicationName("Watchful Eye")

    engine, dhcp_provider = create_discovery_engine()

    # DHCP performs background packet capture.
    # Stop it cleanly when the application exits.
    app.aboutToQuit.connect(dhcp_provider.stop)

    window = MainWindow(engine)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()