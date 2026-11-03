from __future__ import annotations

import re

from watchfuleye.domain.observation import Observation, ObservationType


class ServiceDetector:
    """Convert known open TCP ports into likely service observations.

    A port-to-service mapping is a hint, not proof of the software running on
    the remote endpoint. Values are intentionally normalized for downstream
    classification and remain linked to the original device and scan.
    """

    SOURCE = "SERVICE_DETECTOR"

    PORT_SERVICES = {
        22: ("ssh", 0.90),
        23: ("telnet", 0.90),
        53: ("dns", 0.85),
        80: ("http", 0.80),
        139: ("netbios-session", 0.85),
        443: ("https", 0.80),
        445: ("smb", 0.90),
        515: ("lpd", 0.90),
        554: ("rtsp", 0.90),
        631: ("ipp", 0.90),
        1883: ("mqtt", 0.90),
        1433: ("mssql", 0.90),
        179: ("bgp", 0.85),
        2601: ("router-vty", 0.80),
        2604: ("router-vty", 0.80),
        3306: ("mysql", 0.90),
        3389: ("rdp", 0.90),
        5432: ("postgresql", 0.90),
        62078: ("apple-mobile-device", 0.75),
        7000: ("airplay", 0.80),
        8008: ("google-cast", 0.85),
        8009: ("google-cast", 0.85),
        8080: ("http-alt", 0.75),
        8291: ("mikrotik-api", 0.90),
        8443: ("https-alt", 0.75),
        8883: ("mqtt-tls", 0.90),
        9100: ("jetdirect", 0.90),
        9200: ("elasticsearch", 0.90),
        27017: ("mongodb", 0.90),
        37777: ("dahua-service", 0.80),
        4786: ("cisco-smart-install", 0.80),
        6379: ("redis", 0.90),
    }

    PORT_PATTERN = re.compile(r"^(?:tcp[/:-])?(\d+)$", re.IGNORECASE)

    @classmethod
    def parse_tcp_port(cls, value: str) -> int | None:
        if not isinstance(value, str):
            return None
        match = cls.PORT_PATTERN.fullmatch(value.strip())
        if not match:
            return None
        port = int(match.group(1))
        return port if 1 <= port <= 65535 else None

    def detect(self, observations: list[Observation]) -> list[Observation]:
        if not isinstance(observations, list) or not all(
            isinstance(item, Observation) for item in observations
        ):
            raise TypeError("ServiceDetector requires a list of Observation objects.")

        detected: dict[tuple[str, int, str], Observation] = {}
        for observation in observations:
            if observation.type != ObservationType.PORT:
                continue

            port = self.parse_tcp_port(observation.value)
            if port is None or port not in self.PORT_SERVICES:
                continue

            service_name, confidence = self.PORT_SERVICES[port]
            key = (observation.device_id or "", port, service_name)
            if key in detected:
                continue

            detected[key] = Observation(
                scan_id=observation.scan_id,
                source=self.SOURCE,
                type=ObservationType.SERVICE,
                value=service_name,
                device_id=observation.device_id,
                correlation_id=observation.correlation_id,
                confidence=confidence,
                interface=observation.interface,
            )

        return list(detected.values())
