from __future__ import annotations

import json
from datetime import datetime, timezone, tzinfo
from typing import Any


def to_local_datetime(value: datetime | None, local_timezone: tzinfo | None = None) -> datetime | None:
    """Convert stored timestamps to local time for presentation.

    Historical naive timestamps are interpreted as UTC because the domain
    model has always created timestamps in UTC. New persisted timestamps
    should remain timezone-aware.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    if local_timezone is None:
        local_timezone = datetime.now().astimezone().tzinfo
    return value.astimezone(local_timezone)


def format_local_datetime(
    value: datetime | None,
    *,
    include_date: bool = True,
    local_timezone: tzinfo | None = None,
) -> str:
    local_value = to_local_datetime(value, local_timezone)
    if local_value is None:
        return "—"
    pattern = "%Y-%m-%d %H:%M:%S" if include_date else "%H:%M:%S"
    return local_value.strftime(pattern)


def classification_payload(observation: Any) -> dict[str, Any] | None:
    """Return a validated classifier explanation payload, if present."""
    if (
        getattr(getattr(observation, "type", None), "value", None) != "other"
        or getattr(observation, "source", None) != "DEVICE_CLASSIFIER"
    ):
        return None
    try:
        payload = json.loads(observation.value)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("kind") != "classification_evidence":
        return None
    return payload


def format_observation_value(observation: Any) -> str:
    payload = classification_payload(observation)
    if payload is None:
        return str(getattr(observation, "value", ""))
    evidence = payload.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = []
    device_type = payload.get("device_type", "Unknown")
    count = len(evidence)
    return f"{device_type}: {count} supporting signal(s)" if count else f"{device_type}: no decisive supporting signals"
