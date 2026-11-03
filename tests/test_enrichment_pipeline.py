import pytest

from watchfuleye.application.enrichment_pipeline import (
    EnrichmentPipeline,
)
from watchfuleye.domain.observation import (
    Observation,
    ObservationType,
)


def make_observation(
    observation_type,
    value,
):
    return Observation(
        scan_id="test-scan",
        source="ARP",
        type=observation_type,
        value=value,
        interface="Ethernet",
        correlation_id="test-correlation",
    )


class FakeResolver:

    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    def enrich(self, observation):
        self.calls.append(observation)

        if self.error:
            raise self.error

        return self.result


def make_enriched_observation(
    observation,
    observation_type,
    value,
    source,
):
    return Observation(
        scan_id=observation.scan_id,
        source=source,
        type=observation_type,
        value=value,
        interface=observation.interface,
        correlation_id=observation.correlation_id,
        confidence=0.95,
    )


def test_enriches_mac_observation():

    original = make_observation(
        ObservationType.MAC_ADDRESS,
        "00:1b:c5:00:00:00",
    )

    manufacturer = make_enriched_observation(
        original,
        ObservationType.MANUFACTURER,
        "Example Manufacturer",
        "OUI",
    )

    oui = FakeResolver(result=manufacturer)
    reverse_dns = FakeResolver()

    pipeline = EnrichmentPipeline(
        oui_resolver=oui,
        reverse_dns_resolver=reverse_dns,
    )

    result = pipeline.run([original])

    assert result == [manufacturer]
    assert oui.calls == [original]
    assert reverse_dns.calls == []


def test_enriches_ip_observation():

    original = make_observation(
        ObservationType.IP_ADDRESS,
        "192.168.100.1",
    )

    hostname = make_enriched_observation(
        original,
        ObservationType.HOSTNAME,
        "gateway.local",
        "REVERSE_DNS",
    )

    oui = FakeResolver()
    reverse_dns = FakeResolver(result=hostname)

    pipeline = EnrichmentPipeline(
        oui_resolver=oui,
        reverse_dns_resolver=reverse_dns,
    )

    result = pipeline.run([original])

    assert result == [hostname]
    assert oui.calls == []
    assert reverse_dns.calls == [original]


def test_ignores_unsupported_observation_types():

    observations = [
        make_observation(
            ObservationType.HOSTNAME,
            "computer.local",
        ),
        make_observation(
            ObservationType.SERVICE,
            "_http._tcp.local.",
        ),
        make_observation(
            ObservationType.PORT,
            "8080",
        ),
    ]

    oui = FakeResolver()
    reverse_dns = FakeResolver()

    pipeline = EnrichmentPipeline(
        oui_resolver=oui,
        reverse_dns_resolver=reverse_dns,
    )

    result = pipeline.run(observations)

    assert result == []
    assert oui.calls == []
    assert reverse_dns.calls == []


def test_enriches_multiple_observations():

    mac = make_observation(
        ObservationType.MAC_ADDRESS,
        "00:1b:c5:00:00:00",
    )

    ip = make_observation(
        ObservationType.IP_ADDRESS,
        "192.168.100.1",
    )

    manufacturer = make_enriched_observation(
        mac,
        ObservationType.MANUFACTURER,
        "Example Manufacturer",
        "OUI",
    )

    hostname = make_enriched_observation(
        ip,
        ObservationType.HOSTNAME,
        "gateway.local",
        "REVERSE_DNS",
    )

    oui = FakeResolver(result=manufacturer)
    reverse_dns = FakeResolver(result=hostname)

    pipeline = EnrichmentPipeline(
        oui_resolver=oui,
        reverse_dns_resolver=reverse_dns,
    )

    result = pipeline.run([mac, ip])

    assert result == [manufacturer, hostname]


def test_preserves_original_observations():

    original = make_observation(
        ObservationType.MAC_ADDRESS,
        "00:1b:c5:00:00:00",
    )

    original_dict = original.to_dict()

    enriched = make_enriched_observation(
        original,
        ObservationType.MANUFACTURER,
        "Example Manufacturer",
        "OUI",
    )

    pipeline = EnrichmentPipeline(
        oui_resolver=FakeResolver(result=enriched),
        reverse_dns_resolver=FakeResolver(),
    )

    pipeline.run([original])

    assert original.to_dict() == original_dict


def test_resolver_failure_does_not_stop_pipeline():

    mac = make_observation(
        ObservationType.MAC_ADDRESS,
        "00:1b:c5:00:00:00",
    )

    ip = make_observation(
        ObservationType.IP_ADDRESS,
        "192.168.100.1",
    )

    hostname = make_enriched_observation(
        ip,
        ObservationType.HOSTNAME,
        "gateway.local",
        "REVERSE_DNS",
    )

    oui = FakeResolver(
        error=RuntimeError("OUI database unavailable")
    )

    reverse_dns = FakeResolver(
        result=hostname
    )

    pipeline = EnrichmentPipeline(
        oui_resolver=oui,
        reverse_dns_resolver=reverse_dns,
    )

    result = pipeline.run([mac, ip])

    assert result == [hostname]
    assert len(oui.calls) == 1
    assert len(reverse_dns.calls) == 1


def test_returns_empty_when_resolver_finds_nothing():

    original = make_observation(
        ObservationType.IP_ADDRESS,
        "192.168.100.1",
    )

    pipeline = EnrichmentPipeline(
        oui_resolver=FakeResolver(),
        reverse_dns_resolver=FakeResolver(result=None),
    )

    assert pipeline.run([original]) == []


def test_rejects_non_list_input():

    pipeline = EnrichmentPipeline(
        oui_resolver=FakeResolver(),
        reverse_dns_resolver=FakeResolver(),
    )

    with pytest.raises(TypeError):
        pipeline.run(None)


def test_rejects_invalid_observation_in_list():

    pipeline = EnrichmentPipeline(
        oui_resolver=FakeResolver(),
        reverse_dns_resolver=FakeResolver(),
    )

    with pytest.raises(TypeError):
        pipeline.run(["not an observation"])


def test_rejects_result_from_another_scan():

    original = make_observation(
        ObservationType.MAC_ADDRESS,
        "00:1b:c5:00:00:00",
    )

    invalid_result = Observation(
        scan_id="different-scan",
        source="OUI",
        type=ObservationType.MANUFACTURER,
        value="Example Manufacturer",
    )

    pipeline = EnrichmentPipeline(
        oui_resolver=FakeResolver(result=invalid_result),
        reverse_dns_resolver=FakeResolver(),
    )

    assert pipeline.run([original]) == []


def test_rejects_wrong_enrichment_type():

    original = make_observation(
        ObservationType.MAC_ADDRESS,
        "00:1b:c5:00:00:00",
    )

    invalid_result = make_enriched_observation(
        original,
        ObservationType.HOSTNAME,
        "wrong.local",
        "OUI",
    )

    pipeline = EnrichmentPipeline(
        oui_resolver=FakeResolver(result=invalid_result),
        reverse_dns_resolver=FakeResolver(),
    )

    assert pipeline.run([original]) == []


def test_rejects_original_observation_as_enrichment():

    original = make_observation(
        ObservationType.MAC_ADDRESS,
        "00:1b:c5:00:00:00",
    )

    pipeline = EnrichmentPipeline(
        oui_resolver=FakeResolver(result=original),
        reverse_dns_resolver=FakeResolver(),
    )

    assert pipeline.run([original]) == []