import logging
from concurrent.futures import ThreadPoolExecutor

from watchfuleye.domain.observation import (
    Observation,
    ObservationType,
)
from watchfuleye.enrichment.oui_resolver import OUIResolver
from watchfuleye.enrichment.reverse_dns_resolver import (
    ReverseDNSResolver,
)


logger = logging.getLogger(__name__)


class EnrichmentPipeline:
    """
    Executes enrichment components against discovery observations.

    The pipeline creates additional observations only.
    It never modifies devices, existing observations,
    or persistent storage.
    """

    def __init__(
        self,
        oui_resolver=None,
        reverse_dns_resolver=None,
    ):
        self.oui_resolver = (
            oui_resolver
            if oui_resolver is not None
            else OUIResolver()
        )

        self.reverse_dns_resolver = (
            reverse_dns_resolver
            if reverse_dns_resolver is not None
            else ReverseDNSResolver()
        )

    
    def run(
        self,
        observations: list[Observation],
    ) -> list[Observation]:

        if not isinstance(observations, list):
            raise TypeError(
                "EnrichmentPipeline requires a list of observations."
            )

        if not all(
            isinstance(item, Observation)
            for item in observations
        ):
            raise TypeError(
                "EnrichmentPipeline received an invalid observation."
            )

        tasks = []

        for observation in observations:

            if observation.type == ObservationType.MAC_ADDRESS:

                tasks.append((
                    self.oui_resolver,
                    observation,
                    ObservationType.MANUFACTURER,
                ))

            elif observation.type == ObservationType.IP_ADDRESS:

                tasks.append((
                    self.reverse_dns_resolver,
                    observation,
                    ObservationType.HOSTNAME,
                ))

        if not tasks:
            return []

        enriched_observations = []

        # Independent enrichment lookups can execute concurrently.
        # Results are collected in their original input order.
        with ThreadPoolExecutor(
            max_workers=min(8, len(tasks)),
            thread_name_prefix="watchfuleye-enrichment",
        ) as executor:

            futures = [
                executor.submit(
                    self._execute_resolver,
                    resolver,
                    observation,
                    expected_type,
                )
                for resolver, observation, expected_type in tasks
            ]

            for future in futures:

                enriched = future.result()

                if enriched is not None:
                    enriched_observations.append(enriched)

        return enriched_observations


    @staticmethod
    def _execute_resolver(
        resolver,
        observation: Observation,
        expected_type: ObservationType,
    ) -> Observation | None:

        try:
            enriched = resolver.enrich(observation)

            if enriched is None:
                return None

            if not isinstance(enriched, Observation):
                raise TypeError(
                    f"{type(resolver).__name__} returned "
                    "a non-Observation result."
                )

            if enriched is observation:
                raise ValueError(
                    f"{type(resolver).__name__} returned "
                    "the original observation instead of new evidence."
                )

            if enriched.scan_id != observation.scan_id:
                raise ValueError(
                    f"{type(resolver).__name__} returned an observation "
                    "belonging to another scan."
                )

            if enriched.type != expected_type:
                raise ValueError(
                    f"{type(resolver).__name__} returned "
                    f"{enriched.type.value}; expected "
                    f"{expected_type.value}."
                )

            return enriched

        except Exception:
            logger.exception(
                "Enrichment failed: resolver=%s observation_id=%s",
                type(resolver).__name__,
                observation.id,
            )

            return None