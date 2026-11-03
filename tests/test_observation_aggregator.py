from datetime import datetime, timedelta, timezone

import pytest

from watchfuleye.domain.device import Device
from watchfuleye.domain.observation import (
    Observation,
    ObservationType,
)
from watchfuleye.identity.observation_aggregator import (
    ObservationAggregator,
)


BASE_TIME = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def aggregator():
    return ObservationAggregator()


def create_pair(
    correlation_id,
    ip,
    mac,
    timestamp=BASE_TIME,
):
    return [
        Observation(
            scan_id="scan-001",
            source="ARP",
            type=ObservationType.IP_ADDRESS,
            value=ip,
            correlation_id=correlation_id,
            timestamp=timestamp,
        ),
        Observation(
            scan_id="scan-001",
            source="ARP",
            type=ObservationType.MAC_ADDRESS,
            value=mac,
            correlation_id=correlation_id,
            timestamp=timestamp,
        ),
    ]


def test_creates_new_device_from_correlated_observations(aggregator):
    observations = create_pair(
        "correlation-001",
        "192.168.100.201",
        "fc:d9:08:dd:f4:5b",
    )

    result = aggregator.aggregate(observations, [])

    assert len(result.devices) == 1

    device = result.devices[0]

    assert device.id
    assert device.ip == "192.168.100.201"
    assert device.mac == "fc:d9:08:dd:f4:5b"
    assert device.status == "UNKNOWN"

    assert all(
        observation.device_id == device.id
        for observation in result.observations
    )

    assert result.unresolved_observations == []


def test_matches_existing_device_and_preserves_uuid(aggregator):
    existing = Device(
        id="device-001",
        ip="192.168.100.100",
        mac="fc:d9:08:dd:f4:5b",
        first_seen=BASE_TIME - timedelta(days=5),
        last_seen=BASE_TIME,
    )

    observations = create_pair(
        "correlation-001",
        "192.168.100.201",
        "FC-D9-08-DD-F4-5B",
        BASE_TIME + timedelta(minutes=5),
    )

    result = aggregator.aggregate(observations, [existing])

    assert len(result.devices) == 1

    updated = result.devices[0]

    assert updated.id == "device-001"
    assert updated.ip == "192.168.100.201"
    assert updated.mac == "fc:d9:08:dd:f4:5b"

    assert all(
        observation.device_id == "device-001"
        for observation in result.observations
    )


def test_existing_device_is_not_mutated(aggregator):
    existing = Device(
        id="device-001",
        ip="192.168.100.100",
        mac="fc:d9:08:dd:f4:5b",
        last_seen=BASE_TIME,
    )

    observations = create_pair(
        "correlation-001",
        "192.168.100.201",
        "fc:d9:08:dd:f4:5b",
        BASE_TIME + timedelta(minutes=5),
    )

    original_ip = existing.ip
    original_last_seen = existing.last_seen

    result = aggregator.aggregate(observations, [existing])

    assert existing.ip == original_ip
    assert existing.last_seen == original_last_seen

    assert result.devices[0] is not existing


def test_input_observations_are_not_mutated(aggregator):
    observations = create_pair(
        "correlation-001",
        "192.168.100.201",
        "fc:d9:08:dd:f4:5b",
    )

    result = aggregator.aggregate(observations, [])

    assert observations[0].device_id is None
    assert observations[1].device_id is None

    assert result.observations[0].device_id is not None


def test_ip_only_observation_remains_unresolved(aggregator):
    observation = Observation(
        scan_id="scan-001",
        source="ARP",
        type=ObservationType.IP_ADDRESS,
        value="192.168.100.201",
    )

    result = aggregator.aggregate([observation], [])

    assert result.devices == []
    assert len(result.unresolved_observations) == 1
    assert result.observations[0].device_id is None


def test_mac_without_ip_can_create_device(aggregator):
    observation = Observation(
        scan_id="scan-001",
        source="ARP",
        type=ObservationType.MAC_ADDRESS,
        value="fc:d9:08:dd:f4:5b",
    )

    result = aggregator.aggregate([observation], [])

    assert len(result.devices) == 1
    assert result.devices[0].mac == "fc:d9:08:dd:f4:5b"
    assert result.devices[0].ip is None
    assert result.observations[0].device_id == result.devices[0].id


def test_conflicting_macs_are_not_merged(aggregator):
    observations = create_pair(
        "correlation-001",
        "192.168.100.201",
        "fc:d9:08:dd:f4:5b",
    )

    observations.append(
        Observation(
            scan_id="scan-001",
            source="ARP",
            type=ObservationType.MAC_ADDRESS,
            value="aa:bb:cc:dd:ee:ff",
            correlation_id="correlation-001",
        )
    )

    result = aggregator.aggregate(observations, [])

    assert result.devices == []
    assert result.ambiguous_group_count == 1
    assert len(result.unresolved_observations) == 3


def test_conflicting_ips_are_not_merged(aggregator):
    observations = create_pair(
        "correlation-001",
        "192.168.100.201",
        "fc:d9:08:dd:f4:5b",
    )

    observations.append(
        Observation(
            scan_id="scan-001",
            source="ARP",
            type=ObservationType.IP_ADDRESS,
            value="192.168.100.202",
            correlation_id="correlation-001",
        )
    )

    result = aggregator.aggregate(observations, [])

    assert result.devices == []
    assert result.ambiguous_group_count == 1


def test_duplicate_mac_groups_reuse_created_device(aggregator):
    first_group = create_pair(
        "correlation-001",
        "192.168.100.201",
        "fc:d9:08:dd:f4:5b",
        BASE_TIME + timedelta(minutes=5),
    )

    second_group = create_pair(
        "correlation-002",
        "192.168.100.202",
        "fc:d9:08:dd:f4:5b",
        BASE_TIME,
    )

    result = aggregator.aggregate(
        first_group + second_group,
        [],
    )

    assert len(result.devices) == 1

    device = result.devices[0]

    assert device.first_seen == BASE_TIME
    assert device.last_seen == BASE_TIME + timedelta(minutes=5)

    # Older evidence must not overwrite the newer IP.
    assert device.ip == "192.168.100.201"

    assigned_ids = {
        observation.device_id
        for observation in result.observations
    }

    assert assigned_ids == {device.id}


def test_ambiguous_existing_mac_match_is_not_merged(aggregator):
    devices = [
        Device(
            id="device-001",
            mac="fc:d9:08:dd:f4:5b",
        ),
        Device(
            id="device-002",
            mac="FC-D9-08-DD-F4-5B",
        ),
    ]

    observations = create_pair(
        "correlation-001",
        "192.168.100.201",
        "fc:d9:08:dd:f4:5b",
    )

    result = aggregator.aggregate(observations, devices)

    assert result.devices == []
    assert result.ambiguous_group_count == 1
    assert len(result.unresolved_observations) == 2


def test_uncorrelated_ip_and_mac_are_not_grouped(aggregator):
    observations = [
        Observation(
            scan_id="scan-001",
            source="ARP",
            type=ObservationType.IP_ADDRESS,
            value="192.168.100.201",
        ),
        Observation(
            scan_id="scan-001",
            source="ARP",
            type=ObservationType.MAC_ADDRESS,
            value="fc:d9:08:dd:f4:5b",
        ),
    ]

    result = aggregator.aggregate(observations, [])

    assert len(result.devices) == 1
    assert result.devices[0].ip is None
    assert result.devices[0].mac == "fc:d9:08:dd:f4:5b"

    assert len(result.unresolved_observations) == 1
    assert result.unresolved_observations[0].type == (
        ObservationType.IP_ADDRESS
    )


def test_invalid_mac_evidence_remains_unresolved(aggregator):
    observation = Observation(
        scan_id="scan-001",
        source="ARP",
        type=ObservationType.MAC_ADDRESS,
        value="not-a-valid-mac",
    )

    result = aggregator.aggregate([observation], [])

    assert result.devices == []
    assert result.ambiguous_group_count == 1
    assert len(result.unresolved_observations) == 1


def test_duplicate_observation_ids_are_rejected(aggregator):
    observation = Observation(
        scan_id="scan-001",
        source="ARP",
        type=ObservationType.MAC_ADDRESS,
        value="fc:d9:08:dd:f4:5b",
    )

    with pytest.raises(ValueError):
        aggregator.aggregate(
            [observation, observation],
            [],
        )
