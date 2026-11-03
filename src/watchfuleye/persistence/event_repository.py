from pathlib import Path

from watchfuleye.domain.device_event import (
    DeviceEvent,
    DeviceEventType,
)
from watchfuleye.persistence.json_storage import JsonStorage


class EventRepository:

    def __init__(self, file_path: str | Path):
        self.storage = JsonStorage(file_path)

    # --------------------------------------------------
    # Internal serialization
    # --------------------------------------------------

    @staticmethod
    def _event_to_dict(event: DeviceEvent) -> dict:
        return event.to_dict()

    @staticmethod
    def _event_from_dict(data: dict) -> DeviceEvent:
        return DeviceEvent.from_dict(data)

    def _load_events(self) -> list[DeviceEvent]:
        data = self.storage.read(default_data=[])

        if not isinstance(data, list):
            raise ValueError(
                "Invalid event storage format. Expected a list."
            )

        return [
            self._event_from_dict(item)
            for item in data
        ]

    def _save_events(self, events: list[DeviceEvent]) -> None:
        self.storage.write([
            self._event_to_dict(event)
            for event in events
        ])

    # --------------------------------------------------
    # Read operations
    # --------------------------------------------------

    def get_all(self) -> list[DeviceEvent]:
        return self._load_events()

    def get_by_id(self, event_id: str) -> DeviceEvent | None:
        for event in self._load_events():
            if event.id == event_id:
                return event

        return None

    def get_by_device(self, device_id: str) -> list[DeviceEvent]:
        return [
            event
            for event in self._load_events()
            if event.device_id == device_id
        ]

    def get_by_type(
        self,
        event_type: DeviceEventType
    ) -> list[DeviceEvent]:
        return [
            event
            for event in self._load_events()
            if event.event_type == event_type
        ]

    # --------------------------------------------------
    # Write operations
    # --------------------------------------------------

    def add(self, event: DeviceEvent) -> None:
        events = self._load_events()

        if any(existing.id == event.id for existing in events):
            return

        events.append(event)
        self._save_events(events)

    def add_many(self, new_events: list[DeviceEvent]) -> None:
        events = self._load_events()

        existing_ids = {
            event.id
            for event in events
        }

        incoming_ids = [
            event.id
            for event in new_events
        ]

        if len(incoming_ids) != len(set(incoming_ids)):
            raise ValueError(
                "Duplicate event IDs in input batch."
            )

        if existing_ids.intersection(incoming_ids):
            raise ValueError(
                "One or more events already exist."
            )

        events.extend(new_events)
        self._save_events(events)

    def delete(self, event_id: str) -> bool:
        events = self._load_events()

        filtered_events = [
            event
            for event in events
            if event.id != event_id
        ]

        if len(filtered_events) == len(events):
            return False

        self._save_events(filtered_events)
        return True

    def save_all(self, events: list[DeviceEvent]) -> None:
        event_ids = [
            event.id
            for event in events
        ]

        if len(event_ids) != len(set(event_ids)):
            raise ValueError(
                "Duplicate event IDs are not allowed."
            )

        self._save_events(events)
