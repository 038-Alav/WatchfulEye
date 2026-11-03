
from types import SimpleNamespace
from unittest.mock import patch

from watchfuleye.domain.observation import (
    Observation,
    ObservationType,
)
from watchfuleye.discovery.arp_provider import (
    ArpDiscoveryProvider,
)


def test_correlation_id_survives_serialization():
    observation = Observation(
        scan_id="scan-001",
        source="ARP",
        type=ObservationType.IP_ADDRESS,
        value="192.168.100.201",
        correlation_id="correlation-001",
    )

    restored = Observation.from_dict(observation.to_dict())

    assert restored.correlation_id == "correlation-001"
    assert restored.id == observation.id
    assert restored.value == observation.value


def test_old_observation_without_correlation_id_remains_compatible():
    observation = Observation(
        scan_id="scan-001",
        source="ARP",
        type=ObservationType.IP_ADDRESS,
        value="192.168.100.201",
    )

    legacy_data = observation.to_dict()
    legacy_data.pop("correlation_id")

    restored = Observation.from_dict(legacy_data)

    assert restored.correlation_id is None
    assert restored.id == observation.id


def test_empty_correlation_id_is_rejected():
    try:
        Observation(
            scan_id="scan-001",
            source="ARP",
            type=ObservationType.IP_ADDRESS,
            value="192.168.100.201",
            correlation_id="",
        )
        assert False, "Expected ValueError"

    except ValueError:
        pass


def test_arp_provider_correlates_ip_and_mac_observations():
    interface = SimpleNamespace(
        ip="192.168.100.94",
        mac="c8:a3:e8:b2:b3:97",
    )

    responses = [
        (
            None,
            SimpleNamespace(
                psrc="192.168.100.201",
                hwsrc="fc:d9:08:dd:f4:5b",
            ),
        ),
        (
            None,
            SimpleNamespace(
                psrc="192.168.100.202",
                hwsrc="aa:bb:cc:dd:ee:ff",
            ),
        ),
    ]

    context = SimpleNamespace(
        network_cidr="192.168.100.0/24",
        interface_name="Wi-Fi",
        scan_id="scan-001",
        timeout_seconds=2,
    )

    fake_conf = SimpleNamespace(
        ifaces=SimpleNamespace(
            dev_from_name=lambda name: interface
        )
    )

    with (
        patch(
            "watchfuleye.discovery.arp_provider.conf",
            fake_conf,
        ),
        patch(
            "watchfuleye.discovery.arp_provider.srp",
            return_value=(responses, []),
        ),
    ):
        provider = ArpDiscoveryProvider()
        observations = provider.discover(context)

    assert len(observations) == 4

    first_pair = observations[:2]
    second_pair = observations[2:]

    # Each ARP response generates one shared correlation ID.
    assert first_pair[0].correlation_id == first_pair[1].correlation_id
    assert second_pair[0].correlation_id == second_pair[1].correlation_id

    # Different ARP responses must have different correlation IDs.
    assert first_pair[0].correlation_id != second_pair[0].correlation_id

    # Verify the actual evidence remains correctly associated.
    assert first_pair[0].type == ObservationType.IP_ADDRESS
    assert first_pair[0].value == "192.168.100.201"

    assert first_pair[1].type == ObservationType.MAC_ADDRESS
    assert first_pair[1].value == "fc:d9:08:dd:f4:5b"

    assert second_pair[0].value == "192.168.100.202"
    assert second_pair[1].value == "aa:bb:cc:dd:ee:ff"
