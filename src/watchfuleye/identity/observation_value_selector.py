from enum import Enum
from typing import Iterable

from watchfuleye.domain.observation import Observation, ObservationType


class ObservationSelectionStrategy(str, Enum):
    """Available policies for choosing a representative observation."""

    HIGHEST_CONFIDENCE = "highest_confidence"


class ObservationValueSelector:
    """Select preferred descriptive evidence without discarding observations.

    The selector is intentionally independent of Device and persistence.
    It returns an original Observation so callers can retain its source,
    confidence, timestamp and other provenance.

    Hostname observations are selected only to populate a legacy/single-value
    Device.hostname field. The caller must preserve the full hostname
    observation collection separately.
    """

    SELECTION_POLICIES = {
        ObservationType.MANUFACTURER: (
            ObservationSelectionStrategy.HIGHEST_CONFIDENCE
        ),
        ObservationType.OPERATING_SYSTEM: (
            ObservationSelectionStrategy.HIGHEST_CONFIDENCE
        ),
        ObservationType.DEVICE_TYPE: (
            ObservationSelectionStrategy.HIGHEST_CONFIDENCE
        ),
        ObservationType.HOSTNAME: (
            ObservationSelectionStrategy.HIGHEST_CONFIDENCE
        ),
    }

    _UNUSABLE_VALUES = {
        "",
        "unknown",
        "none",
        "n/a",
        "not available",
    }

    def select(
        self,
        observations: Iterable[Observation],
        observation_type: ObservationType,
    ) -> Observation | None:
        """Return the best observation for a category, or None.

        Ranking is highest confidence first, followed by newest timestamp.
        Observation ID is the final deterministic tie-breaker.
        """
        if observation_type not in self.SELECTION_POLICIES:
            raise ValueError(
                f"No descriptive selection policy is defined for "
                f"{observation_type!r}."
            )

        items = list(observations)
        if not all(isinstance(item, Observation) for item in items):
            raise TypeError(
                "observations must contain only Observation objects."
            )

        policy = self.SELECTION_POLICIES[observation_type]
        if policy != ObservationSelectionStrategy.HIGHEST_CONFIDENCE:
            raise NotImplementedError(
                f"Unsupported selection strategy: {policy.value}."
            )

        candidates = [
            item
            for item in items
            if (
                item.type == observation_type
                and item.value.strip().casefold() not in self._UNUSABLE_VALUES
            )
        ]

        if not candidates:
            return None

        return max(
            candidates,
            key=lambda item: (
                item.confidence,
                item.timestamp,
                item.id,
            ),
        )

    def select_value(
        self,
        observations: Iterable[Observation],
        observation_type: ObservationType,
    ) -> str | None:
        """Return the selected value while keeping selection policy centralized."""
        selected = self.select(observations, observation_type)
        return selected.value.strip() if selected is not None else None
