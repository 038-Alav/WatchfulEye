import ipaddress
import socket
import struct
from time import monotonic
from uuid import uuid4

import psutil

from watchfuleye.discovery.base import DiscoveryProvider
from watchfuleye.domain.observation import (
    Observation,
    ObservationType,
)


class NetBIOSProvider(DiscoveryProvider):

    name = "NetBIOS"

    NBNS_PORT = 137
    NBSTAT_TYPE = 0x0021
    IN_CLASS = 0x0001
    MAX_ADDRESSES = 1024
    RECEIVE_BUFFER_SIZE = 4096

    def discover(self, context) -> list[Observation]:

        network = ipaddress.ip_network(
            context.network_cidr,
            strict=False,
        )

        if network.version != 4:
            raise ValueError(
                "NetBIOS discovery only supports IPv4 networks."
            )

        if network.num_addresses > self.MAX_ADDRESSES:
            raise ValueError(
                f"Network {network} contains "
                f"{network.num_addresses} addresses. "
                f"The limit is {self.MAX_ADDRESSES}."
            )

        source_ip = self._get_interface_ipv4(
            context.interface_name
        )

        if source_ip is None:
            raise RuntimeError(
                f"Interface {context.interface_name} "
                "does not have an IPv4 address."
            )

        if ipaddress.ip_address(source_ip) not in network:
            raise RuntimeError(
                f"Interface IP {source_ip} does not "
                f"belong to network {network}."
            )

        observations = []

        # Each transaction ID identifies one individual request.
        pending_requests = {}

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        ) as sock:

            sock.bind((source_ip, 0))
            sock.settimeout(context.timeout_seconds)

            # Send requests first, then collect responses.
            for address in network.hosts():

                target_ip = str(address)
                transaction_id = uuid4().bytes[:2]

                request = self._build_node_status_request(
                    transaction_id
                )

                try:
                    sock.sendto(
                        request,
                        (target_ip, self.NBNS_PORT),
                    )
                    pending_requests[transaction_id] = target_ip

                except OSError:
                    # One unreachable host must not stop discovery.
                    continue

            if not pending_requests:
                return observations

            deadline = (
                monotonic() + context.timeout_seconds
            )

            while pending_requests:

                remaining = deadline - monotonic()

                if remaining <= 0:
                    break

                sock.settimeout(remaining)

                try:
                    response, sender = sock.recvfrom(
                        self.RECEIVE_BUFFER_SIZE
                    )
                except socket.timeout:
                    break
                except OSError:
                    break

                if len(response) < 12:
                    continue

                transaction_id = response[:2]

                expected_ip = pending_requests.get(
                    transaction_id
                )

                if expected_ip is None:
                    continue

                sender_ip = sender[0]

                # Only accept a response from the queried host.
                if sender_ip != expected_ip:
                    continue

                names = self._parse_node_status_response(
                    response,
                    transaction_id,
                )

                if not names:
                    pending_requests.pop(
                        transaction_id,
                        None,
                    )
                    continue

                # All evidence from one NetBIOS response shares a correlation ID.
                correlation_id = str(uuid4())

                # Preserve the IP address of the host that sent this response.
                observations.append(
                    Observation(
                        scan_id=context.scan_id,
                        source=self.name,
                        type=ObservationType.IP_ADDRESS,
                        value=sender_ip,
                        confidence=1.0,
                        interface=context.interface_name,
                        correlation_id=correlation_id,
                    )
                )

                # Associate every hostname from this response with that IP.
                for hostname in names:
                    observations.append(
                        Observation(
                            scan_id=context.scan_id,
                            source=self.name,
                            type=ObservationType.HOSTNAME,
                            value=hostname,
                            confidence=1.0,
                            interface=context.interface_name,
                            correlation_id=correlation_id,
                        )
                    )

                pending_requests.pop(
                    transaction_id,
                    None,
                )

        return observations

    @staticmethod
    def _get_interface_ipv4(
        interface_name: str,
    ) -> str | None:

        addresses = psutil.net_if_addrs().get(
            interface_name,
            [],
        )

        for address in addresses:
            if address.family == socket.AF_INET:
                return address.address

        return None

    @classmethod
    def _build_node_status_request(
        cls,
        transaction_id: bytes,
    ) -> bytes:

        if len(transaction_id) != 2:
            raise ValueError(
                "NBNS transaction ID must contain 2 bytes."
            )

        # NetBIOS wildcard name:
        # 15 spaces followed by the NetBIOS suffix 0x00.
        netbios_name = b"*" + (b" " * 14) + b"\x00"

        encoded_name = b"".join(
            bytes((
                0x41 + (byte >> 4),
                0x41 + (byte & 0x0F),
            ))
            for byte in netbios_name
        )

        question_name = (
            b"\x20"
            + encoded_name
            + b"\x00"
        )

        header = struct.pack(
            "!HHHHHH",
            int.from_bytes(transaction_id, "big"),
            0x0000,  # Request flags
            1,       # One question
            0,
            0,
            0,
        )

        question = struct.pack(
            "!HH",
            cls.NBSTAT_TYPE,
            cls.IN_CLASS,
        )

        return header + question_name + question

    @classmethod
    def _parse_node_status_response(
        cls,
        packet: bytes,
        expected_transaction_id: bytes,
    ) -> list[str]:

        if len(packet) < 12:
            return []

        transaction_id = packet[:2]

        if transaction_id != expected_transaction_id:
            return []

        flags = struct.unpack_from(
            "!H",
            packet,
            2,
        )[0]

        # Response bit must be set.
        if not flags & 0x8000:
            return []

        # Reject unsuccessful DNS responses.
        if flags & 0x000F:
            return []

        question_count = struct.unpack_from(
            "!H",
            packet,
            4,
        )[0]

        answer_count = struct.unpack_from(
            "!H",
            packet,
            6,
        )[0]

        offset = 12

        try:
            # Skip the question section.
            for _ in range(question_count):
                offset = cls._skip_dns_name(
                    packet,
                    offset,
                )

                offset += 4

                if offset > len(packet):
                    return []

            hostnames = []

            for _ in range(answer_count):

                offset = cls._skip_dns_name(
                    packet,
                    offset,
                )

                if offset + 10 > len(packet):
                    return []

                record_type, record_class = struct.unpack_from(
                    "!HH",
                    packet,
                    offset,
                )

                offset += 8  # Type, class and TTL

                data_length = struct.unpack_from(
                    "!H",
                    packet,
                    offset,
                )[0]

                offset += 2

                data_end = offset + data_length

                if data_end > len(packet):
                    return []

                if (
                    record_type == cls.NBSTAT_TYPE
                    and record_class == cls.IN_CLASS
                ):
                    hostnames.extend(
                        cls._parse_nbstat_names(
                            packet[offset:data_end]
                        )
                    )

                offset = data_end

            # Remove duplicates while preserving order.
            return list(dict.fromkeys(hostnames))

        except (IndexError, struct.error, ValueError):
            return []

    @staticmethod
    def _skip_dns_name(
        packet: bytes,
        offset: int,
    ) -> int:

        while True:

            if offset >= len(packet):
                raise ValueError(
                    "Invalid DNS name."
                )

            length = packet[offset]

            # Compressed DNS name pointer.
            if length & 0xC0 == 0xC0:

                if offset + 1 >= len(packet):
                    raise ValueError(
                        "Invalid DNS compression pointer."
                    )

                return offset + 2

            # Reserved label encodings are invalid.
            if length & 0xC0:
                raise ValueError(
                    "Invalid DNS label."
                )

            offset += 1

            # End of name.
            if length == 0:
                return offset

            if offset + length > len(packet):
                raise ValueError(
                    "DNS label exceeds packet length."
                )

            offset += length

    @staticmethod
    def _parse_nbstat_names(
        data: bytes,
    ) -> list[str]:

        if not data:
            return []

        name_count = data[0]

        entry_size = 18
        required_length = 1 + name_count * entry_size

        if len(data) < required_length:
            return []

        hostnames = []

        for index in range(name_count):

            start = 1 + index * entry_size

            raw_name = data[
                start:start + 15
            ]

            suffix = data[start + 15]

            name_flags = int.from_bytes(
                data[start + 16:start + 18],
                "big",
            )

            # Bit 15 indicates a group name, not a unique host.
            is_group_name = bool(
                name_flags & 0x8000
            )

            # Suffix 0x00 represents the workstation service.
            if suffix != 0x00 or is_group_name:
                continue

            hostname = raw_name.decode(
                "ascii",
                errors="replace",
            ).strip()

            if not hostname:
                continue

            if hostname == "*":
                continue

            hostnames.append(hostname)

        return hostnames