import logging
from time import perf_counter

from watchfuleye.domain.observation import Observation
from watchfuleye.application.discovery_registry import DiscoveryRegistry
from watchfuleye.discovery.context import DiscoveryContext
from watchfuleye.domain.scan import (
    ProviderExecutionResult,
    ProviderStatus,
)


logger = logging.getLogger(__name__)


class DiscoveryCoordinator:
    """
    Executes registered discovery providers.

    It is responsible only for provider execution,
    error isolation and execution timing.
    """

    def __init__(self, registry: DiscoveryRegistry):
        self.registry = registry

    def execute(
        self,
        context: DiscoveryContext,
    ) -> list[ProviderExecutionResult]:
        results = []

        for provider in self.registry.get_enabled():
            started = perf_counter()

            try:
                if not provider.is_available():
                    detail = getattr(provider, "availability_error", None)
                    error = detail or "Provider is not available."
                    logger.warning(
                        "Discovery provider unavailable | provider=%s | reason=%s",
                        provider.name,
                        error,
                    )
                    results.append(
                        ProviderExecutionResult(
                            provider=provider.name,
                            status=ProviderStatus.UNAVAILABLE,
                            error=error,
                            duration_ms=(perf_counter() - started) * 1000,
                        )
                    )
                    continue

                observations = provider.discover(context)

                if not isinstance(observations, list):
                    raise TypeError(
                        f"{provider.name} must return a list "
                        "of Observation objects."
                    )

                if not all(isinstance(item, Observation) for item in observations):
                    raise TypeError(
                        f"{provider.name} returned an invalid observation."
                    )

                for observation in observations:
                    if observation.scan_id != context.scan_id:
                        raise ValueError(
                            f"{provider.name} returned an observation "
                            "belonging to another scan."
                        )

                results.append(
                    ProviderExecutionResult(
                        provider=provider.name,
                        status=ProviderStatus.SUCCESS,
                        observations=observations,
                        duration_ms=(perf_counter() - started) * 1000,
                    )
                )

                completed = results[-1]
                logger.info(
                    "Discovery provider '%s': status=%s, observations=%d, "
                    "duration=%.2fms, error=%s",
                    completed.provider,
                    completed.status,
                    len(completed.observations or []),
                    completed.duration_ms,
                    completed.error,
                )

            except Exception as exc:
                logger.exception(
                    "Discovery provider execution failed | provider=%s",
                    provider.name,
                )
                results.append(
                    ProviderExecutionResult(
                        provider=provider.name,
                        status=ProviderStatus.FAILED,
                        error=f"{type(exc).__name__}: {exc}",
                        duration_ms=(perf_counter() - started) * 1000,
                    )
                )

        return results
