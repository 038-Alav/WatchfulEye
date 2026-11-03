import logging
from ipaddress import ip_address, ip_network
from time import perf_counter
from uuid import uuid4

from scapy.all import ARP, Ether, srp, conf

from watchfuleye.discovery.base import DiscoveryProvider
from watchfuleye.domain.observation import (
    Observation,
    ObservationType,
)
from watchfuleye.network.interface_resolver import (
    InterfaceResolutionError,
    NetworkInterfaceResolver,
)


logger = logging.getLogger(__name__)


class ArpDiscoveryProvider(DiscoveryProvider):
    name = "ARP"

    def __init__(
        self,
        interface_resolver: NetworkInterfaceResolver | None = None,
    ):
        self.interface_resolver = (
            interface_resolver
            if interface_resolver is not None
            else NetworkInterfaceResolver()
        )
        self.last_scan_duration_ms = 0.0

    def discover(self, context) -> list[Observation]:
        network = ip_network(
            context.network_cidr,
            strict=False,
        )

        if network.version != 4:
            raise ValueError("ARP discovery supports IPv4 networks only.")

        # Safety limit for this POC.
        if network.num_addresses > 1024:
            raise ValueError(
                f"Network {network} contains "
                f"{network.num_addresses} addresses. "
                "The POC limit is 1024."
            )

        # Resolve system interface details independently of Scapy.
        try:
            resolved_interface = self.interface_resolver.resolve(
                context.interface_name,
                str(network),
                require_mac=True,
            )
        except InterfaceResolutionError as exc:
            raise RuntimeError(str(exc)) from exc

        source_ip = resolved_interface.ip
        source_mac = resolved_interface.mac_address

        if not source_ip or not source_mac:
            raise RuntimeError(
                f"Interface {context.interface_name} lacks the IPv4 or MAC "
                "information required for ARP discovery."
            )

        # Map the canonical system interface to Scapy's interface object.
        try:
            scapy_interface = conf.ifaces.dev_from_name(
                resolved_interface.name
            )
        except Exception as exc:
            raise RuntimeError(
                "Could not resolve the selected system interface in Scapy: "
                f"{resolved_interface.name}"
            ) from exc

        if scapy_interface is None:
            raise RuntimeError(
                f"Scapy interface not found: {resolved_interface.name}."
            )

        # Verify that Scapy points to the same adapter and addresses returned
        # by the system-level resolver before transmitting any packets.
        scapy_ip_value = getattr(scapy_interface, "ip", None)
        try:
            scapy_source_ip = str(ip_address(scapy_ip_value))
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                f"Scapy did not expose a valid IPv4 address for "
                f"{resolved_interface.name}."
            ) from exc

        scapy_source_mac = (
            self.interface_resolver.normalize_mac_address(
                getattr(scapy_interface, "mac", None)
            )
        )

        if scapy_source_ip != source_ip:
            raise RuntimeError(
                "Scapy interface IPv4 address does not match the system "
                f"interface resolver: system={source_ip}, scapy={scapy_source_ip}."
            )

        if scapy_source_mac != source_mac:
            raise RuntimeError(
                "Scapy interface MAC address does not match the system "
                f"interface resolver: system={source_mac}, "
                f"scapy={scapy_source_mac or 'unavailable'}."
            )

        logger.debug(
            "ARP interface binding | selected_interface=%s | "
            "interface_index=%s | scapy_interface=%s | "
            "source_ip=%s | source_mac=%s | network=%s",
            resolved_interface.name,
            resolved_interface.interface_index,
            getattr(scapy_interface, "name", str(scapy_interface)),
            source_ip,
            source_mac,
            network,
        )

        # Keep this packet construction unchanged: it fixed Wi-Fi discovery.
        packet = (
            Ether(
                src=source_mac,
                dst="ff:ff:ff:ff:ff:ff",
            )
            / ARP(
                op=1,
                hwsrc=source_mac,
                psrc=source_ip,
                pdst=str(network),
            )
        )

        started = perf_counter()

        answered, unanswered = srp(
            packet,
            timeout=context.timeout_seconds,
            iface=scapy_interface,
            verbose=False,
            inter=0.01,
        )

        observations = []
        discarded_responses = 0

        for sent, received in answered:
            # Ignore invalid or incomplete responses.
            if not received.psrc or not received.hwsrc:
                discarded_responses += 1
                continue

            ip_value = received.psrc
            mac_value = received.hwsrc.lower()
            correlation_id = str(uuid4())

            observations.extend([
                Observation(
                    scan_id=context.scan_id,
                    source=self.name,
                    type=ObservationType.IP_ADDRESS,
                    value=ip_value,
                    confidence=1.0,
                    interface=context.interface_name,
                    correlation_id=correlation_id,
                ),
                Observation(
                    scan_id=context.scan_id,
                    source=self.name,
                    type=ObservationType.MAC_ADDRESS,
                    value=mac_value,
                    confidence=1.0,
                    interface=context.interface_name,
                    correlation_id=correlation_id,
                ),
            ])

        elapsed_ms = (perf_counter() - started) * 1000
        self.last_scan_duration_ms = round(elapsed_ms, 2)

        logger.debug(
            "ARP scan result | interface=%s | network=%s | "
            "answered=%d | unanswered=%d | discarded=%d | "
            "observations=%d | duration_ms=%.2f",
            resolved_interface.name,
            network,
            len(answered),
            len(unanswered),
            discarded_responses,
            len(observations),
            self.last_scan_duration_ms,
        )

        return observations
