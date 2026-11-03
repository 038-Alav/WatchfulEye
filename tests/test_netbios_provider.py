import socket
import struct

import pytest

from watchfuleye.discovery import netbios_provider
from watchfuleye.discovery.context import DiscoveryContext
from watchfuleye.discovery.netbios_provider import NetBIOSProvider
from watchfuleye.domain.observation import ObservationType


def make_nbstat_response(
    transaction_id: bytes,
    hostname: str = "TEST-PC",
    group_name: str = "WORKGROUP",
) -> bytes:

    # Reuse the question from a real provider-generated request.
    request = NetBIOSProvider._build_node_status_request(
        transaction_id
    )

    question = request[12:]

    def make_name_entry(name, suffix, flags=0):

        encoded_name = name.encode(
            "ascii"
        )[:15].ljust(15, b" ")

        return (
            encoded_name
            + bytes([suffix])
            + struct.pack("!H", flags)
        )

    names = (
        make_name_entry(hostname, 0x00)
        + make_name_entry(group_name, 0x00, 0x8000)
    )

    # NBSTAT RDATA: name count + entries + 46-byte statistics.
    rdata = (
        bytes([2])
        + names
        + (b"\x00" * 46)
    )

    answer = (
        b"\xc0\x0c"  # Compressed name pointer
        + struct.pack(
            "!HHIH",
            0x0021,  # NBSTAT
            0x0001,  # IN
            0,       # TTL
            len(rdata),
        )
        + rdata
    )

    header = struct.pack(
        "!HHHHHH",
        int.from_bytes(transaction_id, "big"),
        0x8500,  # Response flags
        1,       # Question count
        1,       # Answer count
        0,
        0,
    )

    return header + question + answer


def make_context(
    network="192.168.1.0/30",
    timeout=1,
):

    return DiscoveryContext(
        network_cidr=network,
        interface_name="Ethernet",
        scan_id="test-scan",
        timeout_seconds=timeout,
    )


class FakeSocket:

    def __init__(self, response=None, sender=None):
        self.response = response
        self.sender = sender
        self.sent_packets = []
        self.timeout = None
        self.response_received = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def bind(self, address):
        self.bound_address = address

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendto(self, packet, address):
        self.sent_packets.append(
            (packet, address)
        )

    def recvfrom(self, buffer_size):

        if (
            self.response is not None
            and not self.response_received
        ):
            self.response_received = True

            return (
                self.response,
                (self.sender, 137),
            )

        raise socket.timeout()


def test_builds_valid_node_status_request():

    transaction_id = b"\x12\x34"

    request = (
        NetBIOSProvider._build_node_status_request(
            transaction_id
        )
    )

    assert request[:2] == transaction_id

    flags, question_count = struct.unpack_from(
        "!HH",
        request,
        2,
    )

    assert flags == 0
    assert question_count == 1

    assert request[-4:] == b"\x00\x21\x00\x01"


def test_rejects_invalid_transaction_id():

    with pytest.raises(ValueError):
        NetBIOSProvider._build_node_status_request(
            b"\x01"
        )


def test_parses_hostname_from_valid_response():

    transaction_id = b"\x12\x34"

    response = make_nbstat_response(
        transaction_id,
        hostname="TEST-PC",
    )

    result = NetBIOSProvider._parse_node_status_response(
        response,
        transaction_id,
    )

    assert result == ["TEST-PC"]


def test_does_not_return_group_names():

    transaction_id = b"\x12\x34"

    response = make_nbstat_response(
        transaction_id,
        hostname="TEST-PC",
        group_name="WORKGROUP",
    )

    result = NetBIOSProvider._parse_node_status_response(
        response,
        transaction_id,
    )

    assert "TEST-PC" in result
    assert "WORKGROUP" not in result


def test_rejects_wrong_transaction_id():

    response = make_nbstat_response(
        b"\x12\x34"
    )

    result = NetBIOSProvider._parse_node_status_response(
        response,
        b"\x56\x78",
    )

    assert result == []


def test_rejects_non_response_packet():

    response = make_nbstat_response(
        b"\x12\x34"
    )

    response = (
        response[:2]
        + b"\x05\x00"
        + response[4:]
    )

    result = NetBIOSProvider._parse_node_status_response(
        response,
        b"\x12\x34",
    )

    assert result == []


def test_rejects_truncated_response():

    result = NetBIOSProvider._parse_node_status_response(
        b"\x12\x34",
        b"\x12\x34",
    )

    assert result == []


def test_rejects_ipv6_network():

    provider = NetBIOSProvider()

    context = make_context(
        network="2001:db8::/120"
    )

    with pytest.raises(ValueError):
        provider.discover(context)


def test_respects_network_size_limit():

    provider = NetBIOSProvider()

    context = make_context(
        network="192.168.0.0/21"
    )

    with pytest.raises(ValueError, match="limit is 1024"):
        provider.discover(context)


def test_returns_hostname_observation(monkeypatch):

    provider = NetBIOSProvider()
    context = make_context()

    monkeypatch.setattr(
        provider,
        "_get_interface_ipv4",
        lambda interface: "192.168.1.1",
    )

    fake_socket = FakeSocket(
        sender="192.168.1.1"
    )

    original_sendto = fake_socket.sendto

    def sendto_and_prepare_response(packet, address):

        original_sendto(packet, address)

        # Prepare a response only for the first request.
        if fake_socket.response is None:

            transaction_id = packet[:2]

            fake_socket.response = make_nbstat_response(
                transaction_id,
                hostname="TEST-PC",
            )

    fake_socket.sendto = sendto_and_prepare_response

    monkeypatch.setattr(
        netbios_provider.socket,
        "socket",
        lambda *args: fake_socket,
    )

    observations = provider.discover(context)

    assert len(observations) == 2

    ip_observation, hostname_observation = observations

    assert ip_observation.type == ObservationType.IP_ADDRESS
    assert ip_observation.value == "192.168.1.1"

    assert hostname_observation.type == ObservationType.HOSTNAME
    assert hostname_observation.value == "TEST-PC"

    # Both observations must originate from the same response.
    assert (
        ip_observation.correlation_id
        == hostname_observation.correlation_id
    )

    assert ip_observation.scan_id == hostname_observation.scan_id
    assert ip_observation.interface == hostname_observation.interface
def test_returns_empty_list_when_no_hosts_respond(monkeypatch):

    provider = NetBIOSProvider()

    context = make_context()

    monkeypatch.setattr(
        provider,
        "_get_interface_ipv4",
        lambda interface: "192.168.1.1",
    )

    fake_socket = FakeSocket()

    monkeypatch.setattr(
        netbios_provider.socket,
        "socket",
        lambda *args: fake_socket,
    )

    observations = provider.discover(context)

    assert observations == []


def test_rejects_interface_outside_selected_network(monkeypatch):

    provider = NetBIOSProvider()

    context = make_context()

    monkeypatch.setattr(
        provider,
        "_get_interface_ipv4",
        lambda interface: "192.168.2.10",
    )

    with pytest.raises(RuntimeError):
        provider.discover(context)