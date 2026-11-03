import pytest

from watchfuleye.domain.observation import (
    Observation,
    ObservationType,
)

from watchfuleye.persistence.observation_repository import (
    ObservationRepository,
)


def create_observation(
    scan_id="scan-1",
    device_id=None,
    value="192.168.100.1",
):

    return Observation(
        scan_id=scan_id,
        source="ARP",
        type=ObservationType.IP_ADDRESS,
        value=value,
        device_id=device_id,
        confidence=1.0,
        interface="Ethernet",
    )


def test_add_and_get_observation(tmp_path):

    repository = ObservationRepository(
        tmp_path / "observations.json"
    )

    observation = create_observation()

    repository.add(observation)

    observations = repository.get_all()

    assert len(observations) == 1
    assert observations[0].id == observation.id
    assert observations[0].scan_id == "scan-1"
    assert observations[0].value == "192.168.100.1"


def test_get_by_id(tmp_path):

    repository = ObservationRepository(
        tmp_path / "observations.json"
    )

    observation = create_observation()

    repository.add(observation)

    result = repository.get_by_id(observation.id)

    assert result is not None
    assert result.id == observation.id


def test_get_by_scan(tmp_path):

    repository = ObservationRepository(
        tmp_path / "observations.json"
    )

    first = create_observation(scan_id="scan-1")
    second = create_observation(
        scan_id="scan-2",
        value="192.168.100.2",
    )

    repository.add_many([first, second])

    result = repository.get_by_scan("scan-1")

    assert len(result) == 1
    assert result[0].id == first.id


def test_get_by_device(tmp_path):

    repository = ObservationRepository(
        tmp_path / "observations.json"
    )

    first = create_observation(
        device_id="device-1"
    )

    second = create_observation(
        device_id="device-2",
        value="192.168.100.2",
    )

    repository.add_many([first, second])

    result = repository.get_by_device("device-1")

    assert len(result) == 1
    assert result[0].id == first.id


def test_add_many_preserves_existing_observations(tmp_path):

    repository = ObservationRepository(
        tmp_path / "observations.json"
    )

    first = create_observation(scan_id="scan-1")
    second = create_observation(
        scan_id="scan-2",
        value="192.168.100.2",
    )

    repository.add(first)
    repository.add(second)

    observations = repository.get_all()

    assert len(observations) == 2


def test_duplicate_observation_id_is_not_saved_twice(tmp_path):

    repository = ObservationRepository(
        tmp_path / "observations.json"
    )

    observation = create_observation()

    repository.add(observation)
    repository.add(observation)

    assert len(repository.get_all()) == 1


def test_duplicate_ids_inside_batch_are_rejected(tmp_path):

    repository = ObservationRepository(
        tmp_path / "observations.json"
    )

    observation = create_observation()

    with pytest.raises(ValueError):
        repository.add_many([
            observation,
            observation,
        ])


def test_invalid_object_is_rejected(tmp_path):

    repository = ObservationRepository(
        tmp_path / "observations.json"
    )

    with pytest.raises(TypeError):
        repository.add_many([
            {"scan_id": "scan-1"}
        ])


def test_observations_survive_repository_restart(tmp_path):

    path = tmp_path / "observations.json"

    first_repository = ObservationRepository(path)

    observation = create_observation()

    first_repository.add(observation)

    # Simulate opening the repository again.
    second_repository = ObservationRepository(path)

    result = second_repository.get_all()

    assert len(result) == 1
    assert result[0].id == observation.id
    assert result[0].timestamp == observation.timestamp
