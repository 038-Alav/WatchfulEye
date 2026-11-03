from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable

from watchfuleye.domain.observation import Observation, ObservationType


logger = logging.getLogger(__name__)


class TTLFingerprinter:
    """Collect an ICMP reply TTL and produce a cautious OS-family hint.

    TTL fingerprinting is deliberately treated as weak evidence. Routers
    decrement TTL values, operating systems can use different defaults, and
    the initial TTL can only be estimated. No OS identification is produced
    when no valid ICMP echo reply is received.
    """

    SOURCE = "TTL_FINGERPRINTER"

    OS_HINTS = (
        (64, "Linux / Unix-like (TTL heuristic)", 0.55),
        (128, "Windows-like (TTL heuristic)", 0.55),
        (255, "Network appliance / embedded (TTL heuristic)", 0.40),
    )

    def __init__(self, sender: Callable[[str, float], int | None] | None = None):
        # Injectable for deterministic tests and alternative platform adapters.
        self.sender = sender

    @staticmethod
    def _send_icmp_echo(
        target_ip: str,
        timeout_seconds: float,
        interface_name: str | None,
        source_ip: str | None,
    ) -> int | None:
        """Send one ICMP echo request through the selected Scapy interface."""
        try:
            from scapy.all import ICMP, IP, conf, sr1
        except ImportError as exc:
            raise RuntimeError(
                "Scapy is required for TTL fingerprinting."
            ) from exc

        scapy_interface = None
        if interface_name:
            scapy_interface = conf.ifaces.dev_from_name(interface_name)
            if scapy_interface is None:
                raise RuntimeError(
                    f"Scapy interface not found: {interface_name}."
                )
            if source_ip:
                try:
                    resolved_source = str(
                        ipaddress.ip_address(getattr(scapy_interface, "ip", None))
                    )
                except ValueError as exc:
                    raise RuntimeError(
                        f"Scapy did not expose an IPv4 address for {interface_name}."
                    ) from exc
                if resolved_source != source_ip:
                    raise RuntimeError(
                        "Scapy interface IPv4 address does not match the selected "
                        f"system interface: expected={source_ip}, actual={resolved_source}."
                    )

        packet = IP(dst=target_ip, src=source_ip) / ICMP()
        reply = sr1(
            packet,
            timeout=timeout_seconds,
            iface=scapy_interface,
            verbose=0,
        )
        if reply is None or not reply.haslayer(IP):
            return None

        if not reply.haslayer(ICMP) or int(reply[ICMP].type) != 0:
            return None

        return int(reply[IP].ttl)

    @classmethod
    def infer_operating_system(cls, observed_ttl: int) -> tuple[str, float] | None:
        """Return a broad, explicitly heuristic OS-family hint."""
        if not isinstance(observed_ttl, int) or not 1 <= observed_ttl <= 255:
            return None

        for upper_bound, label, confidence in cls.OS_HINTS:
            if observed_ttl <= upper_bound:
                return label, confidence

        return None

    def fingerprint(
        self,
        *,
        ip_address: str,
        scan_id: str,
        device_id: str,
        interface: str | None,
        timeout_seconds: float,
        correlation_id: str,
        source_ip: str | None = None,
    ) -> list[Observation]:
        """Return TTL and (when possible) OS-hint observations for one device."""
        try:
            if self.sender is not None:
                ttl = self.sender(ip_address, timeout_seconds)
            else:
                ttl = self._send_icmp_echo(
                    ip_address,
                    timeout_seconds,
                    interface,
                    source_ip,
                )
        except Exception:
            logger.debug(
                "TTL probe failed | ip=%s | device=%s",
                ip_address,
                device_id,
                exc_info=True,
            )
            return []

        if not isinstance(ttl, int) or not 1 <= ttl <= 255:
            return []

        observations = [
            Observation(
                scan_id=scan_id,
                source=self.SOURCE,
                type=ObservationType.TTL,
                value=str(ttl),
                device_id=device_id,
                correlation_id=correlation_id,
                confidence=1.0,
                interface=interface,
            )
        ]

        os_hint = self.infer_operating_system(ttl)
        if os_hint is not None:
            label, confidence = os_hint
            observations.append(
                Observation(
                    scan_id=scan_id,
                    source=self.SOURCE,
                    type=ObservationType.OPERATING_SYSTEM,
                    value=label,
                    device_id=device_id,
                    correlation_id=correlation_id,
                    confidence=confidence,
                    interface=interface,
                )
            )

        return observations
