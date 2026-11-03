from __future__ import annotations

import html
import json

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
)

from watchfuleye.domain.device import Device
from watchfuleye.domain.observation import Observation
from watchfuleye.ui.presentation import (
    classification_payload,
    format_local_datetime,
    format_observation_value,
)


class DeviceDetailsDialog(QDialog):
    """Show a device summary, latest classification rationale and evidence history."""

    def __init__(
        self,
        device: Device,
        observations: list[Observation],
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.device = device
        self.observations = sorted(
            observations, key=lambda item: item.timestamp, reverse=True
        )

        identity = device.hostname or device.ip or device.mac or device.id[:8]
        self.setWindowTitle(f"Device details — {identity}")
        self.resize(980, 720)
        self.setMinimumSize(760, 560)

        layout = QVBoxLayout(self)
        heading = QLabel(identity)
        heading.setStyleSheet("font-size: 20px; font-weight: 700;")
        layout.addWidget(heading)

        identifier = QLabel(f"Device ID: {device.id}")
        identifier.setTextInteractionFlags(Qt.TextSelectableByMouse)
        identifier.setStyleSheet("color: #91a0b4;")
        layout.addWidget(identifier)

        summary = QFormLayout()
        self._add_summary_row(summary, "Hostname", device.hostname)
        self._add_summary_row(summary, "IP address", device.ip)
        self._add_summary_row(summary, "MAC address", device.mac)
        self._add_summary_row(summary, "Manufacturer", device.manufacturer)
        self._add_summary_row(summary, "Device type", device.device_type or "Unknown")
        self._add_summary_row(summary, "Operating system hint", device.operating_system)
        self._add_summary_row(summary, "Status", str(device.status))
        self._add_summary_row(summary, "First seen", format_local_datetime(device.first_seen))
        self._add_summary_row(summary, "Last seen", format_local_datetime(device.last_seen))
        layout.addLayout(summary)

        evidence_title = QLabel("Classification rationale")
        evidence_title.setStyleSheet("font-size: 16px; font-weight: 600;")
        layout.addWidget(evidence_title)
        self.classification_browser = QTextBrowser()
        self.classification_browser.setOpenExternalLinks(False)
        self.classification_browser.setMaximumHeight(190)
        self.classification_browser.setHtml(self._classification_html())
        layout.addWidget(self.classification_browser)

        observations_title = QLabel(
            f"Evidence history — {len(self.observations)} observation(s)"
        )
        observations_title.setStyleSheet("font-size: 16px; font-weight: 600;")
        layout.addWidget(observations_title)

        self.evidence_table = QTableWidget(0, 5)
        self.evidence_table.setHorizontalHeaderLabels(
            ["Observed at (local)", "Source", "Type", "Value", "Confidence"]
        )
        self.evidence_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.evidence_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.evidence_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.evidence_table.setAlternatingRowColors(True)
        self.evidence_table.setWordWrap(False)
        self.evidence_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.evidence_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.evidence_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.evidence_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.evidence_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.evidence_table.setRowCount(len(self.observations))

        for row, observation in enumerate(self.observations):
            values = (
                format_local_datetime(observation.timestamp),
                observation.source,
                observation.type.value,
                format_observation_value(observation),
                f"{observation.confidence:.0%}",
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(observation.value))
                self.evidence_table.setItem(row, column, item)

        layout.addWidget(self.evidence_table, 1)

        note = QLabel(
            "Classification confidence is a heuristic support score, not a calibrated probability. "
            "Open ports and inferred services are clues, not proof that a device has a particular role."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color: #91a0b4;")
        layout.addWidget(note)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    @staticmethod
    def _add_summary_row(form: QFormLayout, label: str, value: str | None) -> None:
        field = QLabel(value or "—")
        field.setTextInteractionFlags(Qt.TextSelectableByMouse)
        form.addRow(f"{label}:", field)

    def _classification_html(self) -> str:
        type_observations = [
            item for item in self.observations
            if item.source == "DEVICE_CLASSIFIER" and item.type.value == "device_type"
        ]
        latest_type = type_observations[0] if type_observations else None
        explanation = None
        if latest_type is not None:
            for item in self.observations:
                if (
                    item.source == "DEVICE_CLASSIFIER"
                    and item.type.value == "other"
                    and item.scan_id == latest_type.scan_id
                    and item.correlation_id == latest_type.correlation_id
                ):
                    candidate = classification_payload(item)
                    if candidate is not None:
                        explanation = candidate
                        break

        if explanation is None:
            label = self.device.device_type or "Unknown"
            return (
                f"<p><b>Current classification:</b> {html.escape(label)}</p>"
                "<p>No stored classification explanation is available for this device yet.</p>"
            )

        label = html.escape(str(explanation.get("device_type", "Unknown")))
        confidence = explanation.get("confidence", latest_type.confidence if latest_type else 0.0)
        if label == "Unknown":
            confidence_text = "No classification confidence assigned"
        else:
            try:
                confidence_text = f"{float(confidence):.0%} heuristic support"
            except (TypeError, ValueError):
                confidence_text = "Heuristic support not available"
        reason = html.escape(str(explanation.get("reason", "No explanation recorded.")))

        scores = explanation.get("scores", {})
        score_html = ""
        if isinstance(scores, dict) and scores:
            normalized_scores = []
            for name, score in scores.items():
                try:
                    normalized_scores.append((str(name), float(score)))
                except (TypeError, ValueError):
                    continue
            score_items = sorted(normalized_scores, key=lambda pair: pair[1], reverse=True)
            if score_items:
                score_html = "<p><b>Candidate support scores:</b><br>" + "<br>".join(
                    f"{html.escape(name)}: {score:.2f}"
                    for name, score in score_items[:8]
                ) + "</p>"

        evidence = explanation.get("evidence", [])
        if not isinstance(evidence, list):
            evidence = []
        if evidence:
            evidence_html = "<ul>" + "".join(
                f"<li>{html.escape(str(detail))}</li>" for detail in evidence
            ) + "</ul>"
        else:
            evidence_html = "<p>No decisive supporting signals were stored.</p>"

        return (
            f"<p><b>Latest classification:</b> {label} &nbsp; "
            f"<b>{html.escape(confidence_text)}</b></p>"
            f"<p>{reason}</p>"
            f"{score_html}<b>Signals considered:</b>{evidence_html}"
            "<p><i>These are heuristic signals, not verified device identity facts.</i></p>"
        )
