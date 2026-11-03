from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from watchfuleye.domain.observation import Observation, ObservationType
from watchfuleye.enrichment.service_detector import ServiceDetector


@dataclass(frozen=True)
class ClassificationResult:
    """Explainable heuristic classification derived from collected evidence."""

    device_type: str
    confidence: float
    evidence: tuple[str, ...]
    scores: dict[str, float]
    reason: str = ""

    @property
    def is_classified(self) -> bool:
        return self.device_type != "Unknown"

    def to_observations(
        self,
        *,
        scan_id: str,
        device_id: str,
        interface: str | None,
    ) -> list[Observation]:
        """Represent the classification and its rationale as persisted evidence."""
        correlation_id = f"classification:{scan_id}:{device_id}"
        type_observation = Observation(
            scan_id=scan_id,
            source="DEVICE_CLASSIFIER",
            type=ObservationType.DEVICE_TYPE,
            value=self.device_type,
            device_id=device_id,
            correlation_id=correlation_id,
            confidence=self.confidence,
            interface=interface,
        )
        explanation = {
            "kind": "classification_evidence",
            "device_type": self.device_type,
            "confidence": round(self.confidence, 4),
            "scores": {
                key: round(value, 3)
                for key, value in self.scores.items()
            },
            "evidence": list(self.evidence),
            "reason": self.reason or (
                "Classification supported by the collected evidence."
                if self.is_classified
                else "No classification conclusion could be supported."
            ),
            "status": "classified" if self.is_classified else "insufficient_evidence",
            "confidence_note": "Heuristic support score, not a calibrated probability.",
        }
        evidence_observation = Observation(
            scan_id=scan_id,
            source="DEVICE_CLASSIFIER",
            type=ObservationType.OTHER,
            value=json.dumps(explanation, ensure_ascii=False, sort_keys=True),
            device_id=device_id,
            correlation_id=correlation_id,
            confidence=self.confidence,
            interface=interface,
        )
        return [type_observation, evidence_observation]


class DeviceClassifier:
    """Combine independent hostname, vendor, port, service and OS signals.

    The score is a transparent heuristic, not a statistical probability.
    Historical DEVICE_TYPE and classifier-explanation observations are
    deliberately excluded so an earlier answer cannot reinforce itself.
    """

    MINIMUM_SCORE = 2.5
    MINIMUM_MARGIN = 0.8

    HOSTNAME_RULES = {
        "Camera / video device": ("camera", "ipcam", "cctv", "nvr", "dvr", "webcam"),
        "Printer": ("printer", "print", "laserjet", "deskjet", "officejet"),
        "Server": ("server", "nas", "synology", "qnap", "truenas"),
        "Mobile device": ("iphone", "ipad", "android", "galaxy", "pixel", "phone", "tablet"),
        "Smart TV / media device": ("smarttv", "smart-tv", "television", "chromecast", "roku", "firetv", "apple-tv", "androidtv"),
        "Network infrastructure": ("router", "gateway", "access-point", "accesspoint", "wireless-ap", "switch", "firewall"),
        "Computer": ("desktop", "laptop", "workstation", "notebook", "macbook", "imac", "pc"),
        "IoT device": ("sensor", "smartplug", "smart-plug", "esp32", "esp8266", "shelly", "sonoff", "thermostat", "smart-bulb", "bulb"),
    }

    MANUFACTURER_RULES = {
        "Camera / video device": (("hikvision", "dahua", "axis communications", "reolink", "uniview", "hanwha"), 1.6),
        "Printer": (("brother", "canon", "epson", "lexmark", "xerox", "hewlett packard", "hp inc"), 1.6),
        "Server": (("supermicro", "hewlett packard enterprise", "hpe", "dell inc", "lenovo"), 0.9),
        "Network infrastructure": (("cisco", "mikrotik", "tp-link", "netgear", "ubiquiti", "juniper", "aruba", "fortinet"), 1.3),
        "IoT device": (("espressif", "tuya", "shelly"), 1.4),
        "Computer": (("acer", "asus", "msi", "intel corporate", "hewlett-packard"), 0.7),
    }

    PORT_RULES = {
        554: (("Camera / video device", 2.8, "RTSP port 554"),),
        37777: (("Camera / video device", 2.0, "Dahua-related service port 37777"),),
        9100: (("Printer", 2.8, "JetDirect printing port 9100"),),
        631: (("Printer", 2.5, "IPP printing port 631"),),
        515: (("Printer", 2.0, "LPD printing port 515"),),
        3389: (("Computer", 1.8, "RDP port 3389"), ("Server", 0.8, "RDP port 3389")),
        445: (("Computer", 1.2, "SMB port 445"), ("Server", 1.0, "SMB port 445")),
        139: (("Computer", 0.8, "NetBIOS session port 139"),),
        62078: (("Mobile device", 1.8, "Apple mobile-device service port 62078"),),
        8008: (("Smart TV / media device", 2.6, "Google Cast port 8008"),),
        8009: (("Smart TV / media device", 2.6, "Google Cast port 8009"),),
        7000: (("Smart TV / media device", 1.3, "AirPlay-related port 7000"),),
        1883: (("IoT device", 2.8, "MQTT port 1883"),),
        8883: (("IoT device", 2.5, "MQTT TLS port 8883"),),
        8291: (("Network infrastructure", 2.5, "MikroTik API port 8291"),),
        179: (("Network infrastructure", 2.0, "BGP port 179"),),
        2601: (("Network infrastructure", 2.0, "Router VTY port 2601"),),
        2604: (("Network infrastructure", 2.0, "Router VTY port 2604"),),
        4786: (("Network infrastructure", 2.0, "Cisco Smart Install port 4786"),),
        3306: (("Server", 1.5, "MySQL port 3306"),),
        5432: (("Server", 1.5, "PostgreSQL port 5432"),),
        1433: (("Server", 1.5, "Microsoft SQL Server port 1433"),),
        27017: (("Server", 1.5, "MongoDB port 27017"),),
        6379: (("Server", 1.3, "Redis port 6379"),),
        9200: (("Server", 1.5, "Elasticsearch port 9200"),),
    }

    SERVICE_RULES = {
        "rtsp": (("Camera / video device", 2.8, "RTSP service"),),
        "dahua-service": (("Camera / video device", 2.0, "Dahua-related service"),),
        "jetdirect": (("Printer", 2.8, "JetDirect service"),),
        "pdl-datastream": (("Printer", 2.5, "Printer data-stream service advertised over mDNS"),),
        "printer": (("Printer", 2.5, "Printer service advertised over mDNS"),),
        "ipp": (("Printer", 2.5, "IPP service"),),
        "lpd": (("Printer", 2.0, "LPD service"),),
        "rdp": (("Computer", 1.8, "Remote Desktop service"), ("Server", 0.8, "Remote Desktop service")),
        "smb": (("Computer", 1.2, "SMB file-sharing service"), ("Server", 1.0, "SMB file-sharing service")),
        "apple-mobile-device": (("Mobile device", 1.8, "Apple mobile-device service"),),
        "google-cast": (("Smart TV / media device", 2.6, "Google Cast service"),),
        "airplay": (("Smart TV / media device", 1.3, "AirPlay service"),),
        "mqtt": (("IoT device", 2.8, "MQTT service"),),
        "mqtt-tls": (("IoT device", 2.5, "MQTT TLS service"),),
        "hap": (("IoT device", 1.8, "HomeKit accessory service advertised over mDNS"),),
        "mikrotik-api": (("Network infrastructure", 2.5, "MikroTik API service"),),
        "bgp": (("Network infrastructure", 2.0, "BGP service"),),
        "router-vty": (("Network infrastructure", 2.0, "Router VTY service"),),
        "cisco-smart-install": (("Network infrastructure", 2.0, "Cisco Smart Install service"),),
        "mysql": (("Server", 1.5, "MySQL service"),),
        "postgresql": (("Server", 1.5, "PostgreSQL service"),),
        "mssql": (("Server", 1.5, "Microsoft SQL Server service"),),
        "mongodb": (("Server", 1.5, "MongoDB service"),),
        "redis": (("Server", 1.3, "Redis service"),),
        "elasticsearch": (("Server", 1.5, "Elasticsearch service"),),
    }

    @staticmethod
    def _normalize(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()

    @classmethod
    def _contains_keyword(cls, value: str, keyword: str) -> bool:
        normalized_value = f" {cls._normalize(value)} "
        normalized_keyword = f" {cls._normalize(keyword)} "
        return bool(normalized_keyword.strip()) and normalized_keyword in normalized_value

    @staticmethod
    def _normalize_service_name(value: str) -> str:
        """Extract recognizable mDNS service types from composite values."""
        match = re.search(r"_([a-z0-9-]+)\._(?:tcp|udp)\.", value.casefold())
        if match:
            service_name = match.group(1)
            aliases = {
                "googlecast": "google-cast",
                "airplay": "airplay",
                "raop": "airplay",
                "pdl-datastream": "pdl-datastream",
                "printer": "printer",
                "ipp": "ipp",
                "rtsp": "rtsp",
                "mqtt": "mqtt",
                "smb": "smb",
                "hap": "hap",
            }
            return aliases.get(service_name, service_name)
        return value.casefold().strip()

    @staticmethod
    def _parse_port(value: str) -> int | None:
        match = re.fullmatch(r"(?:tcp[/:-])?(\d+)", value.strip(), re.IGNORECASE)
        if not match:
            return None
        port = int(match.group(1))
        return port if 1 <= port <= 65535 else None

    @staticmethod
    def _recency_factor(observation: Observation, now: datetime) -> float:
        age_days = max(0.0, (now - observation.timestamp).total_seconds() / 86400)
        if age_days > 365:
            return 0.50
        if age_days > 180:
            return 0.65
        if age_days > 30:
            return 0.85
        return 1.0

    def classify(self, observations: list[Observation]) -> ClassificationResult:
        if not isinstance(observations, list) or not all(
            isinstance(item, Observation) for item in observations
        ):
            raise TypeError("DeviceClassifier requires a list of Observation objects.")

        # Each signal family is counted once. Port and service observations
        # for the same service share the same key and cannot double the score.
        signals: dict[str, dict[str, tuple[float, str]]] = {}
        now = datetime.now(timezone.utc)

        def add_signal(category: str, key: str, weight: float, detail: str, factor: float = 1.0):
            category_signals = signals.setdefault(category, {})
            weighted = weight * factor
            current = category_signals.get(key)
            if current is None or weighted > current[0]:
                category_signals[key] = (weighted, detail)

        valid = [
            item for item in observations
            if item.type not in (ObservationType.DEVICE_TYPE,)
            and item.source != "DEVICE_CLASSIFIER"
        ]

        for observation in valid:
            factor = self._recency_factor(observation, now) * observation.confidence
            if observation.type == ObservationType.HOSTNAME:
                for category, keywords in self.HOSTNAME_RULES.items():
                    matched = [
                        keyword for keyword in keywords
                        if self._contains_keyword(observation.value, keyword)
                    ]
                    if matched:
                        add_signal(
                            category,
                            "hostname",
                            3.2,
                            f"Hostname '{observation.value}' contains '{matched[0]}'.",
                            factor,
                        )

            elif observation.type == ObservationType.MANUFACTURER:
                normalized_manufacturer = self._normalize(observation.value)
                for category, (vendors, weight) in self.MANUFACTURER_RULES.items():
                    matched = next(
                        (vendor for vendor in vendors if self._contains_keyword(normalized_manufacturer, vendor)),
                        None,
                    )
                    if matched:
                        add_signal(
                            category,
                            "manufacturer",
                            weight,
                            f"Manufacturer '{observation.value}' matches '{matched}'.",
                            factor,
                        )

            elif observation.type == ObservationType.PORT:
                port = self._parse_port(observation.value)
                if port is None:
                    continue
                rules = self.PORT_RULES.get(port, ())
                service = ServiceDetector.PORT_SERVICES.get(port)
                service_name = service[0] if service else None
                signal_key = f"service:{service_name}" if service_name else f"port:{port}"
                for category, weight, detail in rules:
                    add_signal(category, signal_key, weight, detail, factor)

            elif observation.type == ObservationType.SERVICE:
                service_name = self._normalize_service_name(observation.value)
                rules = self.SERVICE_RULES.get(service_name, ())
                for category, weight, detail in rules:
                    add_signal(
                        category,
                        f"service:{service_name}",
                        weight,
                        detail,
                        factor,
                    )

            elif observation.type == ObservationType.OPERATING_SYSTEM:
                value = observation.value.casefold()
                if "windows-like" in value:
                    add_signal("Computer", "os_hint", 0.35, "Windows-like TTL hint.", factor)
                    add_signal("Server", "os_hint", 0.25, "Windows-like TTL hint.", factor)
                elif "linux / unix-like" in value:
                    add_signal("Server", "os_hint", 0.30, "Linux / Unix-like TTL hint.", factor)
                    add_signal("Computer", "os_hint", 0.20, "Linux / Unix-like TTL hint.", factor)
                elif "network appliance" in value:
                    add_signal("Network infrastructure", "os_hint", 0.50, "Network-appliance TTL hint.", factor)

        scores = {
            category: sum(weight for weight, _ in category_signals.values())
            for category, category_signals in signals.items()
        }
        ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        if not ranked:
            return ClassificationResult(
                "Unknown",
                0.0,
                (),
                {},
                "No known classification rule matched the evidence collected so far.",
            )

        top_category, top_score = ranked[0]
        second_score = ranked[1][1] if len(ranked) > 1 else 0.0
        margin = top_score - second_score
        top_signals = signals[top_category]
        evidence = tuple(
            detail
            for _, detail in sorted(
                top_signals.values(),
                key=lambda item: item[0],
                reverse=True,
            )
        )

        if top_score < self.MINIMUM_SCORE or margin < self.MINIMUM_MARGIN:
            # Preserve evidence for every candidate, not just the current
            # leader, so an Unknown result can explain weak or conflicting
            # signals instead of looking like an empty classification.
            candidate_evidence = tuple(
                f"{category} candidate: {detail}"
                for category in sorted(
                    signals,
                    key=lambda name: scores.get(name, 0.0),
                    reverse=True,
                )
                for _, detail in sorted(
                    signals[category].values(),
                    key=lambda item: item[0],
                    reverse=True,
                )
            )
            if top_score < self.MINIMUM_SCORE:
                reason = (
                    f"The strongest candidate score ({top_score:.2f}) is below "
                    f"the required threshold ({self.MINIMUM_SCORE:.2f})."
                )
            else:
                reason = (
                    f"The leading candidates are too close (score margin "
                    f"{margin:.2f}; required {self.MINIMUM_MARGIN:.2f})."
                )
            return ClassificationResult(
                "Unknown",
                0.0,
                candidate_evidence,
                scores,
                reason,
            )

        # This is a support indicator only; it is intentionally not described
        # as a calibrated probability or statistical confidence interval.
        confidence = min(
            0.96,
            0.45 + (0.07 * top_score) + (0.025 * min(len(top_signals), 3)),
        )
        return ClassificationResult(
            top_category,
            round(confidence, 4),
            evidence,
            scores,
            "The leading category passed the minimum score and separation thresholds.",
        )

