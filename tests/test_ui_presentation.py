from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from watchfuleye.domain.observation import ObservationType
from watchfuleye.ui.presentation import (
    classification_payload,
    format_local_datetime,
    format_observation_value,
)


def test_utc_timestamp_is_rendered_in_supplied_local_timezone():
    value = datetime(2026, 11, 3, 2, 46, 24, tzinfo=timezone.utc)
    local_zone = timezone(timedelta(hours=-3))
    assert format_local_datetime(value, local_timezone=local_zone) == "2026-11-02 23:46:24"


def test_naive_legacy_timestamp_is_assumed_to_be_utc():
    value = datetime(2026, 11, 3, 2, 46, 24)
    local_zone = timezone(timedelta(hours=-3))
    assert format_local_datetime(value, local_timezone=local_zone) == "2026-11-02 23:46:24"


def test_none_timestamp_renders_as_dash():
    assert format_local_datetime(None) == "—"


def test_classifier_explanation_is_rendered_as_readable_summary():
    observation = SimpleNamespace(
        source="DEVICE_CLASSIFIER",
        type=ObservationType.OTHER,
        value='{"kind":"classification_evidence","device_type":"Computer","evidence":["SMB is open", "Windows-like hostname"]}',
    )
    assert classification_payload(observation)["device_type"] == "Computer"
    assert format_observation_value(observation) == "Computer: 2 supporting signal(s)"


def test_unrelated_other_observation_is_not_parsed_as_classifier_data():
    observation = SimpleNamespace(
        source="ARP", type=ObservationType.OTHER, value="diagnostic payload"
    )
    assert classification_payload(observation) is None
    assert format_observation_value(observation) == "diagnostic payload"


def test_legacy_json_stores_are_migrated_only_when_missing(tmp_path):
    from watchfuleye.infrastructure.paths import migrate_legacy_data

    legacy = tmp_path / "legacy"
    current = tmp_path / "current"
    legacy.mkdir()
    (legacy / "devices.json").write_text("[]", encoding="utf-8")
    (legacy / "scans.json").write_text("[1]", encoding="utf-8")
    current.mkdir()
    (current / "devices.json").write_text("[2]", encoding="utf-8")

    migrated = migrate_legacy_data(legacy, current)
    assert migrated == ["scans.json"]
    assert (current / "devices.json").read_text(encoding="utf-8") == "[2]"
    assert (current / "scans.json").read_text(encoding="utf-8") == "[1]"
