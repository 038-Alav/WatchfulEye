from datetime import datetime
from ipaddress import ip_network

from PySide6.QtCore import QThreadPool, Qt
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QComboBox,
    QTableWidget,
    QTableWidgetItem,
    QMessageBox,
    QFrame,
    QHeaderView,
    QTabWidget,
    QAbstractItemView,
)

from watchfuleye.network.interfaces import get_ipv4_interfaces
from watchfuleye.application.discovery_engine import DiscoveryEngine
from watchfuleye.domain.scan import DiscoveryResult
from watchfuleye.ui.scan_worker import ScanWorker
from watchfuleye.ui.device_details_dialog import DeviceDetailsDialog
from watchfuleye.ui.presentation import format_local_datetime, format_observation_value


class MainWindow(QMainWindow):

    def __init__(self, engine: DiscoveryEngine):

        super().__init__()

        self.engine = engine
        self.interfaces = []
        self.active_worker = None
        self.last_result = None

        self.thread_pool = QThreadPool.globalInstance()

        self.setWindowTitle("Watchful Eye")
        self.resize(1120, 720)

        self.setStyleSheet("""
            QMainWindow, QWidget {
                background: #101722;
                color: #e6edf3;
                font-family: Segoe UI;
            }

            QFrame#panel {
                background: #182333;
                border: 1px solid #29384b;
                border-radius: 10px;
            }

            QLabel#muted {
                color: #91a0b4;
            }

            QPushButton {
                background: #2677d8;
                color: white;
                border: 0;
                padding: 9px 16px;
                border-radius: 6px;
            }

            QPushButton:disabled {
                background: #40516a;
                color: #aab4c2;
            }

            QComboBox {
                background: #182333;
                border: 1px solid #34445a;
                padding: 8px;
                border-radius: 5px;
            }

            QTableWidget {
                background: #182333;
                alternate-background-color: #1d2a3c;
                gridline-color: #2b3a4e;
                border: 1px solid #29384b;
                selection-background-color: #334b68;
                selection-color: #ffffff;
            }

            QTableWidget::item:selected {
                background: #334b68;
                color: #ffffff;
            }

            QHeaderView::section {
                background: #223249;
                color: #cbd5e1;
                padding: 8px;
                border: 0;
            }
                           
            QTabBar::tab {
                background: #182333;
                color: #91a0b4;
                padding: 9px 16px;
                margin-right: 4px;
                border: 1px solid #29384b;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
            }

            QTabBar::tab:selected {
                background: #223249;
                color: #e6edf3;
                font-weight: 600;
            }

            QTabBar::tab:hover {
                background: #29384b;
                color: #ffffff;
            }
        """)

        self._build_ui()

        self.refresh_interfaces()
        self.refresh_table()
        self.refresh_devices()

    # --------------------------------------------------
    # UI construction
    # --------------------------------------------------

    def _build_ui(self):

        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout(central)

        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(16)

        # Header

        header = QHBoxLayout()
        title_box = QVBoxLayout()

        title = QLabel("Watchful Eye")
        title.setStyleSheet(
            "font-size: 25px; font-weight: 700;"
        )

        subtitle = QLabel(
            "Local network discovery and device inventory"
        )
        subtitle.setObjectName("muted")

        title_box.addWidget(title)
        title_box.addWidget(subtitle)

        header.addLayout(title_box)
        header.addStretch()

        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("muted")

        header.addWidget(self.status_label)

        layout.addLayout(header)

        # Network controls

        controls = QFrame()
        controls.setObjectName("panel")

        controls_layout = QHBoxLayout(controls)

        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(300)

        self.interface_combo.currentIndexChanged.connect(
            self.on_interface_changed
        )

        self.scope_label = QLabel("Subnet: —")
        self.scope_label.setObjectName("muted")

        self.refresh_button = QPushButton(
            "Refresh interfaces"
        )
        self.refresh_button.clicked.connect(
            self.refresh_interfaces
        )

        self.scan_button = QPushButton(
            "Start scan"
        )
        self.scan_button.clicked.connect(
            self.start_scan
        )

        controls_layout.addWidget(QLabel("Interface"))
        controls_layout.addWidget(self.interface_combo, 2)
        controls_layout.addWidget(self.scope_label, 2)
        controls_layout.addWidget(self.refresh_button)
        controls_layout.addWidget(self.scan_button)

        layout.addWidget(controls)

        # Metric cards

        cards = QHBoxLayout()

        self.total_card = self.make_card(
            "Observations", "0"
        )

        self.online_card = self.make_card(
            "Successful providers", "0"
        )

        self.stale_card = self.make_card(
            "Warnings", "0"
        )

        self.last_card = self.make_card(
            "Last scan", "Never"
        )

        for card in (
            self.total_card,
            self.online_card,
            self.stale_card,
            self.last_card,
        ):
            cards.addWidget(card)

        layout.addLayout(cards)

        # Discovery tabs
        self.tabs = QTabWidget()

        # ----------------------------------------------
        # Observations tab
        # ----------------------------------------------

        observations_page = QWidget()
        observations_layout = QVBoxLayout(observations_page)
        observations_layout.setContentsMargins(8, 12, 8, 8)

        observations_title = QLabel("Discovery observations")
        observations_title.setStyleSheet(
            "font-size: 17px; font-weight: 600;"
        )

        observations_layout.addWidget(observations_title)

        self.table = QTableWidget(0, 7)

        self.table.setHorizontalHeaderLabels([
            "Source",
            "Observation",
            "Value",
            "Confidence",
            "Interface",
            "Timestamp",
            "Scan ID",
        ])

        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)

        self.table.horizontalHeader().setStretchLastSection(True)

        self.table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents
        )

        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeToContents
        )

        self.table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.Stretch
        )

        observations_layout.addWidget(self.table, 1)

        observations_footer = QLabel(
            "Raw evidence collected by discovery and enrichment "
            "components. Multiple observations may refer to the "
            "same device."
        )

        observations_footer.setObjectName("muted")
        observations_footer.setWordWrap(True)

        observations_layout.addWidget(observations_footer)

        self.tabs.addTab(
            observations_page,
            "Observations",
        )

        # ----------------------------------------------
        # Devices tab
        # ----------------------------------------------

        devices_page = QWidget()
        devices_layout = QVBoxLayout(devices_page)
        devices_layout.setContentsMargins(8, 12, 8, 8)

        devices_header = QHBoxLayout()

        devices_title = QLabel("Discovered devices")
        devices_title.setStyleSheet(
            "font-size: 17px; font-weight: 600;"
        )

        self.device_count_label = QLabel("0 devices")
        self.device_count_label.setObjectName("muted")

        self.device_details_button = QPushButton("View device details")
        self.device_details_button.setEnabled(False)
        self.device_details_button.clicked.connect(self.open_selected_device_details)

        self.devices_refresh_button = QPushButton("Refresh inventory")
        self.devices_refresh_button.clicked.connect(self.refresh_devices)

        devices_header.addWidget(devices_title)
        devices_header.addStretch()
        devices_header.addWidget(self.device_count_label)
        devices_header.addWidget(self.device_details_button)
        devices_header.addWidget(self.devices_refresh_button)

        devices_layout.addLayout(devices_header)

        self.devices_table = QTableWidget(0, 8)

        self.devices_table.setHorizontalHeaderLabels([
            "Hostname",
            "IP address",
            "MAC address",
            "Manufacturer",
            "Device type",
            "Status",
            "First seen",
            "Last seen",
        ])

        self.devices_table.setAlternatingRowColors(True)

        self.devices_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.devices_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.devices_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.devices_table.itemSelectionChanged.connect(
            self._update_device_details_button
        )
        self.devices_table.itemDoubleClicked.connect(
            lambda _item: self.open_selected_device_details()
        )

        self.devices_table.horizontalHeader().setStretchLastSection(
            True
        )

        self.devices_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents
        )

        self.devices_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeToContents
        )

        self.devices_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeToContents
        )

        self.devices_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.Stretch
        )

        devices_layout.addWidget(self.devices_table, 1)

        devices_footer = QLabel(
            "Each row represents one device identity. Hostnames "
            "and manufacturers are displayed when supporting "
            "observations are available. Select a device or double-click "
            "a row to inspect its classification rationale and evidence history."
        )

        devices_footer.setObjectName("muted")
        devices_footer.setWordWrap(True)

        devices_layout.addWidget(devices_footer)

        self.tabs.addTab(
            devices_page,
            "Devices",
        )

        layout.addWidget(self.tabs, 1)

    # --------------------------------------------------
    # Metric cards
    # --------------------------------------------------

    def make_card(self, caption, value):

        frame = QFrame()
        frame.setObjectName("panel")

        box = QVBoxLayout(frame)

        label = QLabel(caption)
        label.setObjectName("muted")

        value_label = QLabel(value)
        value_label.setStyleSheet(
            "font-size: 22px; font-weight: 700;"
        )

        box.addWidget(label)
        box.addWidget(value_label)

        frame.value_label = value_label

        return frame

    # --------------------------------------------------
    # Network interfaces
    # --------------------------------------------------

    def refresh_interfaces(self):

        self.interfaces = get_ipv4_interfaces()

        self.interface_combo.blockSignals(True)
        self.interface_combo.clear()

        for interface in self.interfaces:

            self.interface_combo.addItem(
                interface.display_name
            )

        self.interface_combo.blockSignals(False)

        self.on_interface_changed()

        if not self.interfaces:

            self.status_label.setText(
                "No active IPv4 interface found"
            )

    def on_interface_changed(self, *_):

        index = self.interface_combo.currentIndex()

        if 0 <= index < len(self.interfaces):

            interface = self.interfaces[index]

            self.scope_label.setText(
                f"Subnet: {interface.cidr}"
            )

        else:

            self.scope_label.setText("Subnet: —")

    # --------------------------------------------------
    # Scan execution
    # --------------------------------------------------

    def start_scan(self):

        index = self.interface_combo.currentIndex()

        if not (0 <= index < len(self.interfaces)):

            QMessageBox.warning(
                self,
                "No interface",
                "Select an active network interface first."
            )

            return

        interface = self.interfaces[index]

        network = ip_network(
            interface.cidr,
            strict=False
        )

        if network.num_addresses > 1024:

            QMessageBox.warning(
                self,
                "Subnet too large",
                f"{network} contains "
                f"{network.num_addresses} addresses. "
                "The POC limit is 1024."
            )

            return

        answer = QMessageBox.question(
            self,
            "Confirm scan",
            f"Run an ARP discovery scan on {network} "
            f"using interface {interface.name}?",
            QMessageBox.Yes | QMessageBox.No,
        )

        if answer != QMessageBox.Yes:
            return

        self.scan_button.setEnabled(False)
        self.refresh_button.setEnabled(False)

        self.status_label.setText(
            f"Scanning {network}..."
        )

        worker = ScanWorker(
            engine=self.engine,
            network_cidr=str(network),
            interface_name=interface.name,
            timeout_seconds=2,
        )

        worker.signals.progress.connect(
            self.on_scan_progress
        )

        worker.signals.finished.connect(
            self.on_scan_finished
        )

        worker.signals.failed.connect(
            self.on_scan_failed
        )

        # Keep a reference while the QRunnable is executing.
        self.active_worker = worker

        self.thread_pool.start(worker)

    # --------------------------------------------------
    # Scan progress
    # --------------------------------------------------

    def on_scan_progress(self, message):

        self.status_label.setText(message)

    # --------------------------------------------------
    # Scan results
    # --------------------------------------------------

    def on_scan_finished(self, result):

        self._restore_scan_controls()

        if not isinstance(result, DiscoveryResult):

            self.on_scan_failed(
                "DiscoveryEngine returned an invalid result."
            )

            return

        self.last_result = result

        self.refresh_table(result)
        self.refresh_devices()

        scan = result.scan

        status = scan.status.value

        successful_providers = sum(
            provider_result.status.value == "SUCCESS"
            for provider_result in result.provider_results
        )

        warning_count = len(result.errors)

        observation_count = len(result.observations)

        self.total_card.value_label.setText(
            str(observation_count)
        )

        self.online_card.value_label.setText(
            str(successful_providers)
        )

        self.stale_card.value_label.setText(
            str(warning_count)
        )

        if scan.finished_at:

            self.last_card.value_label.setText(
                format_local_datetime(scan.finished_at, include_date=False)
            )

        else:

            self.last_card.value_label.setText(
                format_local_datetime(datetime.now().astimezone(), include_date=False)
            )

        self.status_label.setText(
            f"Scan {status.lower()} — "
            f"{observation_count} observation(s)"
        )

        if result.errors:

            QMessageBox.warning(
                self,
                "Scan completed with warnings",
                "\n".join(result.errors)
            )

    def on_scan_failed(self, message):

        self._restore_scan_controls()

        self.status_label.setText("Scan failed")

        QMessageBox.critical(
            self,
            "Scan failed",
            message
        )

    def _restore_scan_controls(self):

        self.scan_button.setEnabled(True)
        self.refresh_button.setEnabled(True)

        self.active_worker = None

    # --------------------------------------------------
    # Discovery observations table
    # --------------------------------------------------

    @staticmethod
    def _format_observation_value(observation):
        return format_observation_value(observation)

    def refresh_table(self, result=None):

        if result is None:
            result = self.last_result

        if result is None:

            self.table.setRowCount(0)
            return

        observations = result.observations

        self.table.setRowCount(len(observations))

        for row, observation in enumerate(observations):

            observation_type = observation.type.value

            timestamp = format_local_datetime(observation.timestamp)

            values = [
                observation.source,
                observation_type,
                self._format_observation_value(observation),
                f"{observation.confidence:.0%}",
                observation.interface or "—",
                timestamp,
                observation.scan_id[:8],
            ]

            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if (
                    column == 2
                    and observation.source == "DEVICE_CLASSIFIER"
                    and observation.type.value == "other"
                ):
                    item.setToolTip(observation.value)
                self.table.setItem(row, column, item)
    # --------------------------------------------------
    # Device inventory table
    # --------------------------------------------------

    def refresh_devices(self):
        try:
            devices = self.engine.get_devices()
        except Exception as exc:
            self.status_label.setText("Could not load device inventory")
            QMessageBox.warning(
                self, "Inventory error", f"Could not load devices:\n{exc}"
            )
            return

        self._devices_by_id = {device.id: device for device in devices}
        self.devices_table.setSortingEnabled(False)
        self.devices_table.setRowCount(len(devices))
        self.device_count_label.setText(f"{len(devices)} device(s)")

        for row, device in enumerate(devices):
            values = [
                device.hostname or "Unknown",
                device.ip or "—",
                device.mac or "—",
                device.manufacturer or "Unknown",
                device.device_type or "Unclassified",
                str(device.status),
                format_local_datetime(device.first_seen),
                format_local_datetime(device.last_seen),
            ]

            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 0:
                    item.setData(Qt.UserRole, device.id)
                self.devices_table.setItem(row, column, item)

        self._update_device_details_button()

    def _update_device_details_button(self):
        selected = bool(self.devices_table.selectionModel().selectedRows())
        self.device_details_button.setEnabled(selected)

    def open_selected_device_details(self):
        selected_rows = self.devices_table.selectionModel().selectedRows()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        identity_item = self.devices_table.item(row, 0)
        if identity_item is None:
            return

        device_id = identity_item.data(Qt.UserRole)
        device = getattr(self, "_devices_by_id", {}).get(device_id)
        if device is None:
            return

        try:
            observations = self.engine.get_device_observations(device_id)
        except Exception as exc:
            QMessageBox.warning(
                self,
                "Device evidence unavailable",
                f"Could not load evidence for this device:\n{exc}",
            )
            return

        dialog = DeviceDetailsDialog(device, observations, self)
        dialog.exec()
