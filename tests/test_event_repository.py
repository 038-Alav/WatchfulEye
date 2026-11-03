
from datetime import datetime, timezone

import pytest

from watchfuleye.domain.device_event import (
    DeviceEvent,
    DeviceEventType,
)
from watchfuleye.persistence.event_repository import (
    EventRepository,
)


@pytest.fixture
def repository(tmp_path):
    return EventRepository(
        tmp_path / "events.json"
    )


def create_event(
    device_id="device-001",
    event_type=DeviceEventType.DISCOVERED,
):
    return DeviceEvent(
        device_id=device_id,
        event_type=event_type,
        timestamp=datetime.now(timezone.utc),
        description="Test event",
        details={"ip_address": "192.168.100.201"},
    )


def test_add_and_get_all(repository):
    event = create_event()

    repository.add(event)

    events = repository.get_all()

    assert len(events) == 1
    assert events[0].id == event.id


def test_get_by_id(repository):
    event = create_event()
    repository.add(event)

    result = repository.get_by_id(event.id)

    assert result is not None
    assert result.device_id == event.device_id


def test_get_by_device(repository):
    repository.add(create_event("device-001"))
    repository.add(create_event("device-002"))
    repository.add(create_event("device-001"))

    events = repository.get_by_device("device-001")

    assert len(events) == 2


def test_get_by_type(repository):
    repository.add(
        create_event(
            event_type=DeviceEventType.DISCOVERED
        )
    )
    repository.add(
        create_event(
            event_type=DeviceEventType.STATUS_CHANGED
        )
    )

    events = repository.get_by_type(
        DeviceEventType.DISCOVERED
    )

    assert len(events) == 1
    assert events[0].event_type == DeviceEventType.DISCOVERED


def test_add_duplicate_is_ignored(repository):
    event = create_event()

    repository.add(event)
    repository.add(event)

    assert len(repository.get_all()) == 1


def test_add_many(repository):
    events = [
        create_event("device-001"),
        create_event("device-002"),
    ]

    repository.add_many(events)

    assert len(repository.get_all()) == 2


def test_add_many_rejects_duplicate_ids(repository):
    event = create_event()

    with pytest.raises(ValueError):
        repository.add_many([event, event])

    assert repository.get_all() == []


def test_delete(repository):
    event = create_event()
    repository.add(event)

    assert repository.delete(event.id) is True
    assert repository.get_all() == []


def test_delete_missing_event(repository):
    assert repository.delete("missing-id") is False


def test_persistence_after_restart(repository):
    event = create_event()
    repository.add(event)

    new_repository = EventRepository(
        repository.storage.file_path
    )

    events = new_repository.get_all()

    assert len(events) == 1
    assert events[0].id == event.id
    assert events[0].details == event.details


def test_save_all_rejects_duplicate_ids(repository):
    event = create_event()

    with pytest.raises(ValueError):
        repository.save_all([event, event])
