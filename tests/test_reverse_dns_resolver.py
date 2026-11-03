
import socket

import pytest

from watchfuleye.domain.observation import Observation, ObservationType
from watchfuleye.enrichment.reverse_dns_resolver import ReverseDNSResolver


@pytest.fixture
def resolver():
    return ReverseDNSResolver()


@pytest.fixture
def ip_observation():
    return Observation(
        scan_id="scan-123",
        source="ARP",
        type=ObservationType.IP_ADDRESS,
        value="192.168.100.201",
        device_id="device-123",
        correlation_id="correlation-123",
        interface="Wi-Fi",
    )


def test_resolves_ipv4_hostname(resolver, monkeypatch):
    def mock_gethostbyaddr(ip):
        assert ip == "192.168.100.201"
        return ("phone.example.local.", [], [ip])

    monkeypatch.setattr(socket, "gethostbyaddr", mock_gethostbyaddr)

    assert resolver.resolve("192.168.100.201") == "phone.example.local"


def test_resolves_ipv6_hostname(resolver, monkeypatch):
    def mock_gethostbyaddr(ip):
        assert ip == "2001:db8::1"
        return ("test-ipv6.example.local", [], [ip])

    monkeypatch.setattr(socket, "gethostbyaddr", mock_gethostbyaddr)

    assert resolver.resolve("2001:db8::1") == "test-ipv6.example.local"


def test_returns_none_when_ptr_record_is_missing(resolver, monkeypatch):
    def mock_gethostbyaddr(ip):
        raise socket.herror("Host not found")

    monkeypatch.setattr(socket, "gethostbyaddr", mock_gethostbyaddr)

    assert resolver.resolve("192.168.100.201") is None


def test_returns_none_for_invalid_ip(resolver, monkeypatch):
    def unexpected_lookup(ip):
        pytest.fail("DNS lookup should not run for an invalid IP")

    monkeypatch.setattr(socket, "gethostbyaddr", unexpected_lookup)

    assert resolver.resolve("not-an-ip") is None


def test_returns_none_for_empty_ip(resolver):
    assert resolver.resolve(None) is None
    assert resolver.resolve("") is None
    assert resolver.resolve("   ") is None


def test_enriches_ip_observation(
    resolver,
    ip_observation,
    monkeypatch,
):
    def mock_gethostbyaddr(ip):
        return ("phone.example.local.", [], [ip])

    monkeypatch.setattr(socket, "gethostbyaddr", mock_gethostbyaddr)

    result = resolver.enrich(ip_observation)

    assert result is not None
    assert result.type == ObservationType.HOSTNAME
    assert result.value == "phone.example.local"
    assert result.source == "REVERSE_DNS"
    assert result.scan_id == ip_observation.scan_id
    assert result.device_id == ip_observation.device_id
    assert result.correlation_id == ip_observation.correlation_id
    assert result.interface == ip_observation.interface
    assert result.confidence == 0.85


def test_does_not_modify_original_observation(
    resolver,
    ip_observation,
    monkeypatch,
):
    def mock_gethostbyaddr(ip):
        return ("phone.example.local", [], [ip])

    monkeypatch.setattr(socket, "gethostbyaddr", mock_gethostbyaddr)

    original_value = ip_observation.value
    original_type = ip_observation.type
    original_source = ip_observation.source

    resolver.enrich(ip_observation)

    assert ip_observation.value == original_value
    assert ip_observation.type == original_type
    assert ip_observation.source == original_source


def test_enrich_returns_none_when_lookup_fails(
    resolver,
    ip_observation,
    monkeypatch,
):
    def mock_gethostbyaddr(ip):
        raise socket.gaierror("DNS lookup failed")

    monkeypatch.setattr(socket, "gethostbyaddr", mock_gethostbyaddr)

    assert resolver.enrich(ip_observation) is None


def test_rejects_non_ip_observation(resolver):
    observation = Observation(
        scan_id="scan-123",
        source="ARP",
        type=ObservationType.MAC_ADDRESS,
        value="fc:d9:08:dd:f4:5b",
    )

    with pytest.raises(ValueError):
        resolver.enrich(observation)


def test_rejects_non_observation(resolver):
    with pytest.raises(TypeError):
        resolver.enrich("192.168.100.201")
