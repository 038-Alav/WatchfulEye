from __future__ import annotations

import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from watchfuleye.domain.observation import Observation, ObservationType
from watchfuleye.enrichment.service_detector import ServiceDetector
from watchfuleye.enrichment.tcp_probe import TCPProbe
from watchfuleye.enrichment.ttl_fingerprinter import TTLFingerprinter
from watchfuleye.network.interface_resolver import (
    InterfaceResolutionError,
    NetworkInterfaceResolver,
)


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FingerprintTarget:
    """A device/IP pair already associated by the identity pipeline."""

    device_id: str
    ip_address: str
    interface_name: str
    source_ip: str | None = None


class FingerprintingService:
    """Orchestrate bounded active fingerprinting for current-scan devices.

    This service only returns observations. It does not modify devices,
    perform identity resolution, or access persistence.
    """

    def __init__(
        self,
        ttl_fingerprinter: TTLFingerprinter | None = None,
        tcp_probe: TCPProbe | None = None,
        service_detector: ServiceDetector | None = None,
        interface_resolver: NetworkInterfaceResolver | None = None,
        *,
        max_workers: int = 32,
        max_devices: int = 256,
        tcp_timeout_seconds: float = 0.4,
    ):
        if max_workers < 1:
            raise ValueError("max_workers must be at least 1.")
        if max_devices < 1:
            raise ValueError("max_devices must be at least 1.")
        if not 0.0 < tcp_timeout_seconds <= 10.0:
            raise ValueError("tcp_timeout_seconds must be greater than 0 and <= 10.")

        self.ttl_fingerprinter = ttl_fingerprinter or TTLFingerprinter()
        self.tcp_probe = tcp_probe or TCPProbe()
        self.service_detector = service_detector or ServiceDetector()
        self.interface_resolver = interface_resolver or NetworkInterfaceResolver()
        self.max_workers = max_workers
        self.max_devices = max_devices
        self.tcp_timeout_seconds = tcp_timeout_seconds

    @staticmethod
    def _normalize_targets(
        targets: list[FingerprintTarget],
        network_cidr: str,
    ) -> list[FingerprintTarget]:
        network = ipaddress.ip_network(network_cidr, strict=False)
        if network.version != 4:
            return []

        unique: dict[tuple[str, str], FingerprintTarget] = {}
        for target in targets:
            if not isinstance(target, FingerprintTarget):
                raise TypeError("Fingerprint targets must be FingerprintTarget objects.")
            if not target.device_id or not target.interface_name:
                continue
            try:
                address = ipaddress.ip_address(target.ip_address)
            except ValueError:
                continue
            if address.version != 4 or address not in network:
                continue

            normalized = FingerprintTarget(
                device_id=target.device_id,
                ip_address=str(address),
                interface_name=target.interface_name,
            )
            unique.setdefault((normalized.device_id, normalized.ip_address), normalized)

        return list(unique.values())

    def run(
        self,
        targets: list[FingerprintTarget],
        *,
        network_cidr: str,
        scan_id: str,
        timeout_seconds: float,
    ) -> list[Observation]:
        """Probe in-scope targets and return TTL, port, and service evidence."""
        if not isinstance(targets, list):
            raise TypeError("targets must be a list.")
        if not scan_id or not scan_id.strip():
            raise ValueError("scan_id cannot be empty.")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero.")

        normalized_targets = self._normalize_targets(targets, network_cidr)
        if len(normalized_targets) > self.max_devices:
            logger.warning(
                "Fingerprint target limit reached | selected=%d | limit=%d",
                len(normalized_targets),
                self.max_devices,
            )
            normalized_targets = normalized_targets[:self.max_devices]

        if not normalized_targets:
            return []

        # Bind TCP sockets and ICMP packets to the interface selected for the
        # discovery scan. Do not silently fall back to the system default route.
        source_ips: dict[str, str] = {}
        for interface_name in dict.fromkeys(
            target.interface_name for target in normalized_targets
        ):
            try:
                resolved = self.interface_resolver.resolve(
                    interface_name,
                    network_cidr,
                )
            except InterfaceResolutionError as exc:
                raise RuntimeError(
                    f"Cannot bind fingerprinting to interface {interface_name}: {exc}"
                ) from exc
            source_ips[interface_name] = resolved.ip

        normalized_targets = [
            FingerprintTarget(
                device_id=target.device_id,
                ip_address=target.ip_address,
                interface_name=target.interface_name,
                source_ip=source_ips[target.interface_name],
            )
            for target in normalized_targets
        ]

        ttl_timeout = min(max(float(timeout_seconds), 0.5), 1.5)
        futures = {}
        port_observations: list[Observation] = []
        ttl_observations: list[Observation] = []

        tasks_count = len(normalized_targets) * (1 + len(self.tcp_probe.ports))
        with ThreadPoolExecutor(
            max_workers=min(self.max_workers, tasks_count),
            thread_name_prefix="watchfuleye-fingerprint",
        ) as executor:
            for target in normalized_targets:
                correlation_id = f"fingerprint:{scan_id}:{target.device_id}"
                future = executor.submit(
                    self.ttl_fingerprinter.fingerprint,
                    ip_address=target.ip_address,
                    scan_id=scan_id,
                    device_id=target.device_id,
                    interface=target.interface_name,
                    timeout_seconds=ttl_timeout,
                    correlation_id=correlation_id,
                    source_ip=target.source_ip,
                )
                futures[future] = ("ttl", target, None, correlation_id)

                for port in self.tcp_probe.ports:
                    future = executor.submit(
                        self.tcp_probe.is_open,
                        target.ip_address,
                        port,
                        self.tcp_timeout_seconds,
                        target.source_ip,
                    )
                    futures[future] = ("port", target, port, correlation_id)

            for future in as_completed(futures):
                task_type, target, port, correlation_id = futures[future]
                try:
                    result = future.result()
                except Exception:
                    logger.debug(
                        "Fingerprint task failed | type=%s | ip=%s | port=%s",
                        task_type,
                        target.ip_address,
                        port,
                        exc_info=True,
                    )
                    continue

                if task_type == "ttl":
                    if isinstance(result, list):
                        ttl_observations.extend(
                            item for item in result if isinstance(item, Observation)
                        )
                    continue

                if result is True:
                    port_observations.append(
                        Observation(
                            scan_id=scan_id,
                            source="TCP_PROBE",
                            type=ObservationType.PORT,
                            value=f"tcp/{port}",
                            device_id=target.device_id,
                            correlation_id=correlation_id,
                            confidence=0.99,
                            interface=target.interface_name,
                        )
                    )

        service_observations = self.service_detector.detect(port_observations)
        observations = ttl_observations + port_observations + service_observations

        # Stable presentation/persistence order makes scan records easier to diff.
        observations.sort(
            key=lambda item: (
                item.device_id or "",
                item.type.value,
                item.value,
                item.source,
            )
        )
        logger.info(
            "Fingerprinting completed | targets=%d | ttl=%d | open_ports=%d | services=%d",
            len(normalized_targets),
            len(ttl_observations),
            len(port_observations),
            len(service_observations),
        )
        return observations
