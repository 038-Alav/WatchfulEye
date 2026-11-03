from __future__ import annotations

from typing import Protocol

from watchfuleye.domain.observation import Observation


class ObservationEnricher(Protocol):
    """Structural contract for components that add observations.

    Enrichers return new evidence. They must not mutate devices, existing
    observations, or repositories. Implementations may expose a more
    specialized method when they need additional scan context.
    """

    def enrich(self, observation: Observation) -> Observation | None:
        """Return one new observation, or ``None`` when no evidence is found."""
        ...
