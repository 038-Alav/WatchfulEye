import json

from pathlib import Path

from watchfuleye.domain.device import Device
from watchfuleye.persistence.json_storage import JsonStorage


class DeviceRepository:

    def __init__(self, file_path: str | Path):

        self.file_path = Path(file_path)

        self.storage = JsonStorage(self.file_path)

        self.legacy_observations_path = (
            self.file_path.parent / "legacy_observations.json"
        )

    # --------------------------------------------------
    # Internal loading
    # --------------------------------------------------

    def _load_legacy_data(self):

        try:

            with self.file_path.open(
                "r",
                encoding="utf-8"
            ) as file:

                raw = json.load(file)

        except (json.JSONDecodeError, OSError) as exc:

            raise RuntimeError(
                f"Could not read legacy device inventory: {exc}"
            ) from exc

        if not isinstance(raw, list):

            raise RuntimeError(
                "Legacy device inventory must contain a JSON array."
            )

        devices = []
        legacy_observations = []

        try:

            for item in raw:

                if not isinstance(item, dict):
                    raise ValueError(
                        "Device record must be a JSON object."
                    )

                devices.append(
                    Device.from_dict(item)
                )

                for observation in item.get("observations", []):

                    legacy_observations.append({
                        "device_id": item.get("id"),
                        "observation": observation,
                    })

        except (KeyError, TypeError, ValueError) as exc:

            raise RuntimeError(
                f"Could not migrate legacy device inventory: {exc}"
            ) from exc

        # Preserve the original embedded observations.
        # They cannot yet be converted into typed Observation
        # objects because the old format has no scan_id.
        if legacy_observations:

            archive = JsonStorage(
                self.legacy_observations_path
            )

            archive.write(legacy_observations)

        # Write the new device format only after the archive
        # has been successfully written.
        self.storage.write([
            device.to_dict()
            for device in devices
        ])

        return devices

    def _load(self):

        if not self.file_path.exists():
            return []

        try:

            with self.file_path.open(
                "r",
                encoding="utf-8"
            ) as file:

                first_character = file.read(1)

        except OSError as exc:

            raise RuntimeError(
                f"Could not inspect device inventory: {exc}"
            ) from exc

        if first_character == "[":
            return self._load_legacy_data()

        try:

            raw = self.storage.read(default_data=[])

        except Exception as exc:

            raise RuntimeError(
                f"Could not read device inventory: {exc}"
            ) from exc

        if not isinstance(raw, list):

            raise RuntimeError(
                "Invalid device inventory: expected a list."
            )

        try:

            return [
                Device.from_dict(item)
                for item in raw
            ]

        except (KeyError, TypeError, ValueError) as exc:

            raise RuntimeError(
                f"Invalid device record: {exc}"
            ) from exc

    # --------------------------------------------------
    # Public operations
    # --------------------------------------------------

    def get_all(self):

        return self._load()

    def get_by_id(self, device_id: str):

        return next(
            (
                device
                for device in self.get_all()
                if device.id == device_id
            ),
            None
        )

    def get_by_mac(self, mac: str):

        if not mac:
            return None

        normalized = mac.lower()

        return next(
            (
                device
                for device in self.get_all()
                if device.mac
                and device.mac.lower() == normalized
            ),
            None
        )

    def add(self, device: Device):

        devices = self.get_all()

        if any(
            current.id == device.id
            for current in devices
        ):
            raise ValueError(
                f"Device ID already exists: {device.id}"
            )

        if device.mac and any(
            current.mac
            and current.mac.lower() == device.mac.lower()
            for current in devices
        ):
            raise ValueError(
                f"A device with MAC {device.mac} already exists."
            )

        devices.append(device)

        self.save_all(devices)

    def update(self, device: Device):

        devices = self.get_all()

        for index, current in enumerate(devices):

            if current.id == device.id:

                devices[index] = device

                self.save_all(devices)

                return

        raise KeyError(
            f"Device not found: {device.id}"
        )

    def save_all(self, devices: list[Device]):

        if not all(
            isinstance(device, Device)
            for device in devices
        ):
            raise TypeError(
                "save_all() only accepts Device objects."
            )

        ids = [device.id for device in devices]

        if len(ids) != len(set(ids)):
            raise ValueError(
                "Duplicate device IDs are not allowed."
            )

        macs = [
            device.mac.lower()
            for device in devices
            if device.mac
        ]

        if len(macs) != len(set(macs)):
            raise ValueError(
                "Duplicate MAC addresses are not allowed."
            )

        self.storage.write([
            device.to_dict()
            for device in devices
        ])
