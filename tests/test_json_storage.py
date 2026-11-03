
import json

import pytest

from watchfuleye.persistence.json_storage import (
    JsonStorage,
    JsonStorageError,
)


def test_write_and_read(tmp_path):

    path = tmp_path / "devices.json"
    storage = JsonStorage(path)

    expected = [
        {"id": "device-1", "ip": "192.168.1.10"}
    ]

    storage.write(expected)

    assert storage.read() == expected


def test_creates_parent_directories(tmp_path):

    path = tmp_path / "data" / "nested" / "devices.json"
    storage = JsonStorage(path)

    storage.write([])

    assert path.exists()
    assert storage.read() == []


def test_missing_file_returns_default(tmp_path):

    storage = JsonStorage(
        tmp_path / "missing.json"
    )

    assert storage.read([]) == []


def test_corrupted_json_raises_error(tmp_path):

    path = tmp_path / "corrupted.json"
    path.write_text("{invalid json", encoding="utf-8")

    storage = JsonStorage(path)

    with pytest.raises(JsonStorageError):
        storage.read()


def test_unsupported_schema_version_raises_error(tmp_path):

    path = tmp_path / "future.json"

    path.write_text(
        json.dumps({
            "schema_version": 999,
            "data": [],
        }),
        encoding="utf-8",
    )

    storage = JsonStorage(path)

    with pytest.raises(JsonStorageError):
        storage.read()


def test_legacy_json_structure_raises_error(tmp_path):

    path = tmp_path / "legacy.json"

    path.write_text(
        json.dumps([]),
        encoding="utf-8",
    )

    storage = JsonStorage(path)

    with pytest.raises(JsonStorageError):
        storage.read()
