from pathlib import Path

from watchfuleye.domain.observation import Observation
from watchfuleye.persistence.json_storage import JsonStorage


class ObservationRepository:

    def __init__(self, file_path: str | Path):

        self.storage = JsonStorage(file_path)

    # --------------------------------------------------
    # Internal loading
    # --------------------------------------------------

    def _load(self) -> list[Observation]:

        raw = self.storage.read(default_data=[])

        if not isinstance(raw, list):
            raise RuntimeError(
                "Invalid observation storage: expected a list."
            )

        try:

            return [
                Observation.from_dict(item)
                for item in raw
            ]

        except (KeyError, TypeError, ValueError) as exc:

            raise RuntimeError(
                f"Invalid observation record: {exc}"
            ) from exc

    # --------------------------------------------------
    # Public operations
    # --------------------------------------------------

    def get_all(self) -> list[Observation]:

        return self._load()

    def get_by_id(self, observation_id: str):

        return next(
            (
                observation
                for observation in self.get_all()
                if observation.id == observation_id
            ),
            None
        )

    def get_by_scan(self, scan_id: str) -> list[Observation]:

        return [
            observation
            for observation in self.get_all()
            if observation.scan_id == scan_id
        ]

    def get_by_device(self, device_id: str) -> list[Observation]:

        return [
            observation
            for observation in self.get_all()
            if observation.device_id == device_id
        ]

    def add(self, observation: Observation):

        self.add_many([observation])

    def add_many(self, observations: list[Observation]):

        if not all(
            isinstance(item, Observation)
            for item in observations
        ):
            raise TypeError(
                "add_many() only accepts Observation objects."
            )

        existing = self._load()

        existing_ids = {
            observation.id
            for observation in existing
        }

        incoming_ids = set()

        for observation in observations:

            if observation.id in incoming_ids:
                raise ValueError(
                    f"Duplicate observation ID in batch: "
                    f"{observation.id}"
                )

            incoming_ids.add(observation.id)

        # Repeated submissions of an already stored observation
        # are ignored rather than creating duplicate records.
        new_observations = [
            observation
            for observation in observations
            if observation.id not in existing_ids
        ]

        if not new_observations:
            return

        combined = existing + new_observations

        self.storage.write([
            observation.to_dict()
            for observation in combined
        ])

    def save_all(self, observations: list[Observation]):

        if not all(
            isinstance(item, Observation)
            for item in observations
        ):
            raise TypeError(
                "save_all() only accepts Observation objects."
            )

        ids = [
            observation.id
            for observation in observations
        ]

        if len(ids) != len(set(ids)):
            raise ValueError(
                "Duplicate observation IDs are not allowed."
            )

        self.storage.write([
            observation.to_dict()
            for observation in observations
        ])
