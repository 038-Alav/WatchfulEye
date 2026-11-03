from __future__ import annotations

import ipaddress
import re
import socket

import psutil

from watchfuleye.network.interfaces import NetworkInterface


class InterfaceResolutionError(ValueError):
    """Raised when a requested network interface cannot be resolved safely."""


class NetworkInterfaceResolver:
    """Enumerate, resolve and validate local IPv4 network interfaces.

    This component is intentionally independent of Scapy and discovery
    protocols. Providers can use its system-level interface information and
    then adapt that information to their own networking library.
    """

    @staticmethod
    def normalize_mac_address(value: str | None) -> str | None:
        """Normalize common MAC representations to lowercase colon notation."""
        if not value:
            return None

        compact = re.sub(r"[^0-9a-fA-F]", "", value.strip())
        if len(compact) != 12:
            return None
        if not re.fullmatch(r"[0-9a-fA-F]{12}", compact):
            return None

        compact = compact.lower()
        return ":".join(
            compact[index:index + 2]
            for index in range(0, 12, 2)
        )

    @staticmethod
    def _interface_indices() -> dict[str, int]:
        """Return system interface-name to interface-index mappings."""
        try:
            return {
                name: index
                for index, name in socket.if_nameindex()
            }
        except (AttributeError, OSError):
            # Interface indices are useful metadata, but not required for
            # discovery on platforms that do not expose them through Python.
            return {}

    @staticmethod
    def _mac_for_interface(interface_addresses) -> str | None:
        link_families = {getattr(psutil, "AF_LINK", object())}
        packet_family = getattr(socket, "AF_PACKET", None)
        if packet_family is not None:
            link_families.add(packet_family)

        for address in interface_addresses:
            if address.family not in link_families:
                continue
            normalized = NetworkInterfaceResolver.normalize_mac_address(
                address.address
            )
            if normalized:
                return normalized

        return None

    def get_ipv4_interfaces(self) -> list[NetworkInterface]:
        """Return active, non-loopback interfaces with IPv4 configuration.

        Interfaces without a detectable MAC address are still returned for
        compatibility with non-Ethernet discovery methods. ARP explicitly
        requires a MAC address during resolution.
        """
        interfaces: list[NetworkInterface] = []
        stats = psutil.net_if_stats()
        addresses = psutil.net_if_addrs()
        indices = self._interface_indices()

        for name, interface_addresses in addresses.items():
            interface_stats = stats.get(name)
            if interface_stats is None or not interface_stats.isup:
                continue

            mac_address = self._mac_for_interface(interface_addresses)

            for address in interface_addresses:
                if address.family != socket.AF_INET:
                    continue

                ip_value = address.address
                netmask = address.netmask

                if not ip_value or not netmask:
                    continue

                try:
                    interface_address = ipaddress.ip_interface(
                        f"{ip_value}/{netmask}"
                    )
                except ValueError:
                    continue

                if interface_address.ip.is_loopback:
                    continue

                network = interface_address.network
                interfaces.append(
                    NetworkInterface(
                        name=name,
                        display_name=f"{name} — {interface_address.ip}",
                        ip=str(interface_address.ip),
                        netmask=netmask,
                        cidr=str(network),
                        mac_address=mac_address,
                        interface_index=indices.get(name),
                    )
                )

        return interfaces

    def resolve(
        self,
        interface_name: str,
        network_cidr: str | None = None,
        *,
        require_mac: bool = False,
    ) -> NetworkInterface:
        """Resolve an active interface and optionally validate a target subnet.

        The requested target must be an IPv4 subnet contained by the
        interface's directly connected IPv4 network. This prevents a
        provider from accidentally treating a remote network as a local
        Layer-2 scan target.
        """
        if not isinstance(interface_name, str) or not interface_name.strip():
            raise InterfaceResolutionError(
                "A non-empty system interface name is required."
            )

        candidates = [
            interface
            for interface in self.get_ipv4_interfaces()
            if interface.name.casefold() == interface_name.strip().casefold()
        ]

        if not candidates:
            raise InterfaceResolutionError(
                f"Active IPv4 interface not found: {interface_name}."
            )

        target_network = None
        if network_cidr is not None:
            try:
                target_network = ipaddress.ip_network(
                    network_cidr,
                    strict=False,
                )
            except ValueError as exc:
                raise InterfaceResolutionError(
                    f"Invalid target network: {network_cidr}."
                ) from exc

            if target_network.version != 4:
                raise InterfaceResolutionError(
                    "This interface resolver currently supports IPv4 targets only."
                )

            matching_candidates = []
            for candidate in candidates:
                assigned_network = ipaddress.ip_network(
                    candidate.cidr,
                    strict=False,
                )
                if target_network.subnet_of(assigned_network):
                    matching_candidates.append(candidate)

            candidates = matching_candidates
            if not candidates:
                raise InterfaceResolutionError(
                    f"Target network {target_network} is not contained in "
                    f"the IPv4 network configured on interface {interface_name}."
                )

            # Prefer the address that falls inside the requested target when
            # an interface has multiple IPv4 addresses.
            containing_address = [
                candidate
                for candidate in candidates
                if ipaddress.ip_address(candidate.ip) in target_network
            ]
            if containing_address:
                candidates = containing_address

        if len(candidates) > 1:
            descriptions = ", ".join(
                f"{candidate.ip}/{candidate.cidr}"
                for candidate in candidates
            )
            raise InterfaceResolutionError(
                f"Interface {interface_name} has multiple matching IPv4 "
                f"addresses; selection is ambiguous: {descriptions}."
            )

        resolved = candidates[0]

        if require_mac and not resolved.mac_address:
            raise InterfaceResolutionError(
                f"Interface {interface_name} does not expose a valid MAC address."
            )

        return resolved
