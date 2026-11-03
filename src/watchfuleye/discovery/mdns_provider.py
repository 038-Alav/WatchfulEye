import ipaddress
import socket
import time
from uuid import uuid4

import psutil

from zeroconf import (
    ServiceBrowser,
    Zeroconf,
    ZeroconfServiceTypes,
)

from watchfuleye.discovery.base import DiscoveryProvider
from watchfuleye.domain.observation import (
    Observation,
    ObservationType,
)


class _MDNSListener:

    def __init__(self):
        self.services = set()

    def add_service(self, zeroconf, service_type, name):
        self.services.add((service_type, name))

    def update_service(self, zeroconf, service_type, name):
        self.services.add((service_type, name))

    def remove_service(self, zeroconf, service_type, name):
        pass


class MDNSProvider(DiscoveryProvider):

    name = "mDNS"

    def discover(self, context) -> list[Observation]:

        interface_addresses = self._get_interface_addresses(
            context.interface_name
        )

        if not interface_addresses:
            raise RuntimeError(
                f"Interface {context.interface_name} "
                "has no usable IP addresses."
            )

        network = ipaddress.ip_network(
            context.network_cidr,
            strict=False,
        )

        matching_addresses = [
            address
            for address in interface_addresses
            if self._address_belongs_to_network(
                address,
                network,
            )
        ]

        if not matching_addresses:
            raise RuntimeError(
                f"Interface {context.interface_name} "
                f"does not have an address in {network}."
            )

        listener = _MDNSListener()
        observations = []

        zeroconf = None
        browsers = []

        try:

            # Bind mDNS to the selected interface only.
            zeroconf = Zeroconf(
                interfaces=interface_addresses
            )

            # Discover service types advertised on this network.
            service_types = ZeroconfServiceTypes.find(
                zeroconf,
                timeout=context.timeout_seconds,
            )

            if not service_types:
                return observations

            browser = ServiceBrowser(
                zeroconf,
                list(service_types),
                listener=listener,
            )

            browsers.append(browser)

            # Allow service announcements to arrive.
            time.sleep(context.timeout_seconds)

            # Resolve each discovered service instance.
            for service_type, service_name in sorted(
                listener.services
            ):

                try:
                    info = zeroconf.get_service_info(
                        service_type,
                        service_name,
                        timeout=context.timeout_seconds * 1000,
                    )
                except Exception:
                    continue

                if info is None:
                    continue

                observations.extend(
                    self._create_observations(
                        info,
                        service_type,
                        service_name,
                        context,
                    )
                )

        finally:

            for browser in browsers:
                browser.cancel()

            if zeroconf is not None:
                zeroconf.close()

        return observations

    @staticmethod
    def _get_interface_addresses(
        interface_name: str,
    ) -> list[str]:

        interface_records = psutil.net_if_addrs().get(
            interface_name,
            [],
        )

        addresses = []

        for record in interface_records:

            if record.family not in (
                socket.AF_INET,
                socket.AF_INET6,
            ):
                continue

            raw_address = record.address.split("%")[0]

            try:
                address = ipaddress.ip_address(
                    raw_address
                )
            except ValueError:
                continue

            if address.is_unspecified or address.is_loopback:
                continue

            addresses.append(str(address))

        return list(dict.fromkeys(addresses))

    @staticmethod
    def _address_belongs_to_network(
        address: str,
        network,
    ) -> bool:

        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError:
            return False

        return (
            parsed_address.version == network.version
            and parsed_address in network
        )

    @staticmethod
    def _create_observations(
        info,
        service_type: str,
        service_name: str,
        context,
    ) -> list[Observation]:

        correlation_id = str(uuid4())
        observations = []

        hostname = (
            info.server.rstrip(".")
            if info.server
            else None
        )

        if hostname:
            observations.append(
                Observation(
                    scan_id=context.scan_id,
                    source="mDNS",
                    type=ObservationType.HOSTNAME,
                    value=hostname,
                    confidence=1.0,
                    interface=context.interface_name,
                    correlation_id=correlation_id,
                )
            )

        service_value = (
            f"{service_name} | "
            f"{service_type} | "
            f"port={info.port}"
        )

        observations.append(
            Observation(
                scan_id=context.scan_id,
                source="mDNS",
                type=ObservationType.SERVICE,
                value=service_value,
                confidence=1.0,
                interface=context.interface_name,
                correlation_id=correlation_id,
            )
        )

        try:
            addresses = info.parsed_addresses() or []
        except Exception:
            addresses = []

        normalized_addresses = set()

        for address in addresses:
            try:
                normalized_address = str(
                    ipaddress.ip_address(address)
                )
            except (ValueError, TypeError):
                continue

            normalized_addresses.add(normalized_address)

        for address in sorted(normalized_addresses):
            observations.append(
                Observation(
                    scan_id=context.scan_id,
                    source="mDNS",
                    type=ObservationType.IP_ADDRESS,
                    value=address,
                    confidence=1.0,
                    interface=context.interface_name,
                    correlation_id=correlation_id,
                )
            )

        return observations