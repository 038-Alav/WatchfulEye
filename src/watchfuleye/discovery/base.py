from abc import ABC, abstractmethod

from watchfuleye.discovery.context import DiscoveryContext
from watchfuleye.domain.observation import Observation


class DiscoveryProvider(ABC):
    """
    Base contract for all discovery providers.

    Providers collect evidence and return observations.

    They must not:
    - Modify Device objects.
    - Perform identity resolution.
    - Persist data.
    - Modify application state.
    """

    name = "Base provider"

    def is_available(self) -> bool:
        """
        Determines whether this provider can currently run.

        Override this when a provider has specific
        system or dependency requirements.
        """
        return True

    @abstractmethod
    def discover(
        self,
        context: DiscoveryContext
    ) -> list[Observation]:
        """
        Execute discovery and return collected observations.
        """
        raise NotImplementedError