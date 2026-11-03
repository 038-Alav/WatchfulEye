import ipaddress
import socket
from types import SimpleNamespace

import pytest

from watchfuleye.discovery import mdns_provider
from watchfuleye.discovery.context import DiscoveryContext
from watchfuleye.discovery.mdns_provider import MDNSProvider
from watchfuleye.domain.observation import ObservationType


def make_context(
    network="192.168.100.0/24",
):
    return DiscoveryContext(
        network_cidr=network,
        interface_name="Ethernet",
        scan_id="test-scan",
        timeout_seconds=1,
    )


def make_service_info(
    server="test-pc.local.",
    addresses=None,
    port=8080,
):
    return SimpleNamespace(
        server=server,
        port=port,
        parsed_addresses=lambda: (
            addresses or ["192.168.100.50"]
        ),
    )


def test_get_interface_addresses_returns_ipv4_and_ipv6(
    monkeypatch,
):

    records = [
        SimpleNamespace(
            family=socket.AF_INET,
            address="192.168.100.237",
        ),
        SimpleNamespace(
            family=socket.AF_INET6,
            address="fe80::1234%12",
        ),
        SimpleNamespace(
            family=socket.AF_INET,
            address="127.0.0.1",
        ),
    ]

    monkeypatch.setattr(
        mdns_provider.psutil,
        "net_if_addrs",
        lambda: {"Ethernet": records},
    )

    result = MDNSProvider._get_interface_addresses(
        "Ethernet"
    )

    assert "192.168.100.237" in result
    assert "fe80::1234" in result
    assert "127.0.0.1" not in result


def test_get_interface_addresses_returns_empty_for_unknown_interface(
    monkeypatch,
):

    monkeypatch.setattr(
        mdns_provider.psutil,
        "net_if_addrs",
        lambda: {},
    )

    assert (
        MDNSProvider._get_interface_addresses(
            "Unknown"
        )
        == []
    )


def test_address_belongs_to_matching_network():

    assert MDNSProvider._address_belongs_to_network(
        "192.168.100.50",
        ipaddress.ip_network(
            "192.168.100.0/24"
        ),
    )


def test_address_does_not_belong_to_different_network():

    assert not MDNSProvider._address_belongs_to_network(
        "192.168.101.50",
        ipaddress.ip_network(
            "192.168.100.0/24"
        ),
    )


def test_address_rejects_different_ip_versions():

    assert not MDNSProvider._address_belongs_to_network(
        "2001:db8::1",
        ipaddress.ip_network(
            "192.168.100.0/24"
        ),
    )


def test_creates_hostname_service_and_ip_observations():

    context = make_context()

    info = make_service_info()

    observations = MDNSProvider._create_observations(
        info,
        "_http._tcp.local.",
        "Test Web Server._http._tcp.local.",
        context,
    )

    assert len(observations) == 3

    hostname = next(
        item for item in observations
        if item.type == ObservationType.HOSTNAME
    )

    service = next(
        item for item in observations
        if item.type == ObservationType.SERVICE
    )

    address = next(
        item for item in observations
        if item.type == ObservationType.IP_ADDRESS
    )

    assert hostname.value == "test-pc.local"
    assert service.value.endswith("port=8080")
    assert address.value == "192.168.100.50"


def test_observations_share_correlation_id():

    observations = MDNSProvider._create_observations(
        make_service_info(),
        "_http._tcp.local.",
        "Test._http._tcp.local.",
        make_context(),
    )

    correlation_ids = {
        item.correlation_id
        for item in observations
    }

    assert len(correlation_ids) == 1
    assert None not in correlation_ids


def test_creates_observations_without_hostname():

    info = make_service_info(
        server=None,
    )

    observations = MDNSProvider._create_observations(
        info,
        "_http._tcp.local.",
        "Test._http._tcp.local.",
        make_context(),
    )

    assert all(
        item.type != ObservationType.HOSTNAME
        for item in observations
    )

    assert any(
        item.type == ObservationType.SERVICE
        for item in observations
    )


def test_discovers_service_and_closes_resources(monkeypatch):

    provider = MDNSProvider()
    context = make_context()

    monkeypatch.setattr(
        provider,
        "_get_interface_addresses",
        lambda interface: ["192.168.100.237"],
    )

    info = make_service_info()

    class FakeZeroconf:

        def __init__(self, interfaces):
            self.interfaces = interfaces
            self.closed = False

        def get_service_info(
            self,
            service_type,
            service_name,
            timeout,
        ):
            return info

        def close(self):
            self.closed = True

    class FakeBrowser:

        def __init__(
            self,
            zeroconf,
            service_types,
            listener,
        ):
            self.cancelled = False

            listener.add_service(
                zeroconf,
                "_http._tcp.local.",
                "Test._http._tcp.local.",
            )

        def cancel(self):
            self.cancelled = True

    fake_instances = {}

    def fake_zeroconf_factory(interfaces):

        instance = FakeZeroconf(interfaces)
        fake_instances["zeroconf"] = instance
        return instance

    def fake_browser_factory(
        zeroconf,
        service_types,
        listener,
    ):

        instance = FakeBrowser(
            zeroconf,
            service_types,
            listener,
        )

        fake_instances["browser"] = instance
        return instance

    monkeypatch.setattr(
        mdns_provider,
        "Zeroconf",
        fake_zeroconf_factory,
    )

    monkeypatch.setattr(
        mdns_provider,
        "ServiceBrowser",
        fake_browser_factory,
    )

    monkeypatch.setattr(
        mdns_provider.ZeroconfServiceTypes,
        "find",
        lambda zeroconf, timeout: (
            "_http._tcp.local.",
        ),
    )

    monkeypatch.setattr(
        mdns_provider.time,
        "sleep",
        lambda seconds: None,
    )

    observations = provider.discover(context)

    assert len(observations) == 3

    assert all(
        item.scan_id == context.scan_id
        for item in observations
    )

    assert fake_instances["zeroconf"].closed
    assert fake_instances["browser"].cancelled


def test_returns_empty_when_no_service_types_found(
    monkeypatch,
):

    provider = MDNSProvider()

    monkeypatch.setattr(
        provider,
        "_get_interface_addresses",
        lambda interface: ["192.168.100.237"],
    )

    class FakeZeroconf:

        def __init__(self, interfaces):
            self.closed = False

        def close(self):
            self.closed = True

    instance = FakeZeroconf(
        ["192.168.100.237"]
    )

    monkeypatch.setattr(
        mdns_provider,
        "Zeroconf",
        lambda interfaces: instance,
    )

    monkeypatch.setattr(
        mdns_provider.ZeroconfServiceTypes,
        "find",
        lambda zeroconf, timeout: (),
    )

    observations = provider.discover(
        make_context()
    )

    assert observations == []
    assert instance.closed


def test_rejects_interface_outside_selected_network(
    monkeypatch,
):

    provider = MDNSProvider()

    monkeypatch.setattr(
        provider,
        "_get_interface_addresses",
        lambda interface: ["192.168.101.10"],
    )

    with pytest.raises(RuntimeError):
        provider.discover(
            make_context()
        )


def test_rejects_interface_without_addresses(
    monkeypatch,
):

    provider = MDNSProvider()

    monkeypatch.setattr(
        provider,
        "_get_interface_addresses",
        lambda interface: [],
    )

    with pytest.raises(RuntimeError):
        provider.discover(
            make_context()
        )