import ipaddress
import socket

from watchfuleye.domain.observation import Observation, ObservationType


class ReverseDNSResolver:
    """
    Resolves IP addresses to hostnames using reverse DNS (PTR) lookups.

    This resolver creates new observations only. It does not modify
    devices, existing observations, or persistent storage.
    """

    CONFIDENCE = 0.85

    def resolve(self, ip_address: str | None) -> str | None:
        """
        Resolve an IPv4 or IPv6 address to its hostname.

        Returns None if the address is invalid or no PTR record
        can be resolved.
        """
        if not isinstance(ip_address, str) or not ip_address.strip():
            return None

        try:
            normalized_ip = str(
                ipaddress.ip_address(ip_address.strip())
            )
        except ValueError:
            return None

        try:
            hostname, _, _ = socket.gethostbyaddr(normalized_ip)
        except OSError:
            # Includes socket.herror, socket.gaierror and timeouts.
            return None

        if not isinstance(hostname, str):
            return None

        hostname = hostname.strip().rstrip(".")

        return hostname or None

    def enrich(self, observation: Observation) -> Observation | None:
        """
        Convert an IP_ADDRESS observation into a HOSTNAME observation.

        The returned observation retains the original discovery context.
        """
        if not isinstance(observation, Observation):
            raise TypeError(
                "enrich() requires an Observation object."
            )

        if observation.type != ObservationType.IP_ADDRESS:
            raise ValueError(
                "ReverseDNSResolver only accepts IP_ADDRESS observations."
            )

        hostname = self.resolve(observation.value)

        if hostname is None:
            return None

        return Observation(
            scan_id=observation.scan_id,
            source="REVERSE_DNS",
            type=ObservationType.HOSTNAME,
            value=hostname,
            device_id=observation.device_id,
            correlation_id=observation.correlation_id,
            confidence=self.CONFIDENCE,
            interface=observation.interface,
        )
