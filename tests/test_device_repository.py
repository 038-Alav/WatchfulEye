import json

import pytest

from datetime import datetime, timezone

from watchfuleye.domain.device import Device
from watchfuleye.persistence.device_repository import DeviceRepository
from watchfuleye.persistence.json_storage import JsonStorage


def test_add_and_get_device(tmp_path):

    repository = DeviceRepository(
        tmp_path / "devices.json"
    )

    device = Device(
        ip="192.168.1.10",
        mac="aa:bb:cc:dd:ee:ff",
    )

    repository.add(device)

    devices = repository.get_all()

    assert len(devices) == 1
    assert devices[0].id == device.id
    assert devices[0].ip == "192.168.1.10"


def test_get_by_mac_is_case_insensitive(tmp_path):

    repository = DeviceRepository(
        tmp_path / "devices.json"
    )

    device = Device(
        ip="192.168.1.10",
        mac="AA:BB:CC:DD:EE:FF",
    )

    repository.add(device)

    result = repository.get_by_mac(
        "aa:bb:cc:dd:ee:ff"
    )

    assert result is not None
    assert result.id == device.id


def test_duplicate_device_id_is_rejected(tmp_path):

    repository = DeviceRepository(
        tmp_path / "devices.json"
    )

    device = Device(
        mac="aa:bb:cc:dd:ee:ff"
    )

    repository.add(device)

    with pytest.raises(ValueError):
        repository.add(device)


def test_duplicate_mac_is_rejected(tmp_path):

    repository = DeviceRepository(
        tmp_path / "devices.json"
    )

    repository.add(
        Device(mac="aa:bb:cc:dd:ee:ff")
    )

    with pytest.raises(ValueError):
        repository.add(
            Device(mac="AA:BB:CC:DD:EE:FF")
        )


def test_update_device(tmp_path):

    repository = DeviceRepository(
        tmp_path / "devices.json"
    )

    device = Device(
        ip="192.168.1.10",
        mac="aa:bb:cc:dd:ee:ff",
    )

    repository.add(device)

    device.hostname = "MY-PC"

    repository.update(device)

    result = repository.get_by_id(device.id)

    assert result.hostname == "MY-PC"


def test_legacy_inventory_is_migrated(tmp_path):

    path = tmp_path / "devices.json"

    legacy_data = [
        {
            "id": "legacy-device-1",
            "ip": "192.168.100.1",
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "",
            "manufacturer": "Unknown",
            "device_type": "Unknown",
            "status": "ONLINE",
            "first_seen": "2026-10-30T05:57:23+00:00",
            "last_seen": "2026-10-30T06:01:00+00:00",
            "latency_ms": None,
            "observations": [
                {
                    "provider": "ARP",
                    "timestamp": "2026-10-30T05:57:23+00:00",
                    "confidence": "high",
                    "ip": "192.168.100.1",
                }
            ],
        }
    ]

    path.write_text(
        json.dumps(legacy_data),
        encoding="utf-8",
    )

    repository = DeviceRepository(path)

    devices = repository.get_all()

    assert len(devices) == 1
    assert devices[0].id == "legacy-device-1"

    # The new file uses the versioned format.
    migrated = JsonStorage(path).read()

    assert len(migrated) == 1

    # The old evidence is preserved separately.
    archive_path = tmp_path / "legacy_observations.json"
    archive = JsonStorage(archive_path).read()

    assert len(archive) == 1
    assert archive[0]["device_id"] == "legacy-device-1"
    assert archive[0]["observation"]["provider"] == "ARP"


def test_missing_inventory_returns_empty_list(tmp_path):

    repository = DeviceRepository(
        tmp_path / "devices.json"
    )

    assert repository.get_all() == []
