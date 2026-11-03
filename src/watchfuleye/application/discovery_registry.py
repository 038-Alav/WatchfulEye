from watchfuleye.discovery.base import DiscoveryProvider


class DiscoveryRegistry:
    """
    Stores registered discovery providers.

    Registration and execution are intentionally separate.
    """

    def __init__(self):
        self._providers: dict[str, DiscoveryProvider] = {}
        self._enabled: set[str] = set()

    def register(
        self,
        provider: DiscoveryProvider,
        enabled: bool = True
    ) -> None:
        name = provider.name.strip().lower()

        if not name:
            raise ValueError("Provider name cannot be empty.")

        if name in self._providers:
            raise ValueError(
                f"Provider '{provider.name}' is already registered."
            )

        self._providers[name] = provider

        if enabled:
            self._enabled.add(name)

    def get_all(self) -> list[DiscoveryProvider]:
        return list(self._providers.values())

    def get_enabled(self) -> list[DiscoveryProvider]:
        return [
            provider
            for name, provider in self._providers.items()
            if name in self._enabled
        ]

    def enable(self, provider_name: str) -> None:
        name = provider_name.strip().lower()

        if name not in self._providers:
            raise KeyError(f"Unknown provider: {provider_name}")

        self._enabled.add(name)

    def disable(self, provider_name: str) -> None:
        name = provider_name.strip().lower()

        if name not in self._providers:
            raise KeyError(f"Unknown provider: {provider_name}")

        self._enabled.discard(name)
