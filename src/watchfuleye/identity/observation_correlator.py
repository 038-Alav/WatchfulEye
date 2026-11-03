from collections import defaultdict
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Iterable

from watchfuleye.domain.observation import (
    Observation,
    ObservationType,
)
from watchfuleye.identity.device_identity_resolver import (
    DeviceIdentityResolver,
)


@dataclass(frozen=True)
class CorrelatedObservationGroup:
    """Observations associated through unambiguous evidence."""

    observations: tuple[Observation, ...]
    matched_ips: tuple[str, ...] = ()

    @property
    def mac_addresses(self) -> tuple[str, ...]:
        return tuple(sorted({
            normalized
            for item in self.observations
            if item.type == ObservationType.MAC_ADDRESS
            if (normalized := DeviceIdentityResolver.normalize_mac(item.value))
        }))

    @property
    def ip_addresses(self) -> tuple[str, ...]:
        addresses = set()

        for item in self.observations:
            if item.type != ObservationType.IP_ADDRESS:
                continue

            try:
                addresses.add(str(ip_address(item.value)))
            except ValueError:
                continue

        return tuple(sorted(addresses))


@dataclass(frozen=True)
class AmbiguousRelationship:
    """Provider groups share an IP but have conflicting MAC evidence."""

    ip_address: str
    observation_ids: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class CorrelationResult:
    # Groups containing observations from multiple provider responses.
    groups: tuple[CorrelatedObservationGroup, ...]

    # Groups that were not automatically correlated.
    independent_groups: tuple[CorrelatedObservationGroup, ...]

    # Relationships deliberately left unresolved due to conflicting evidence.
    ambiguous_relationships: tuple[AmbiguousRelationship, ...]


class ObservationCorrelator:
    """
    Correlates independent provider responses using unambiguous IP evidence.

    Correlation is limited to the same scan and interface.

    Original observations and correlation IDs are never modified.
    Hostnames are never used as identity evidence.
    Groups containing multiple IP addresses cannot participate in
    automatic cross-provider correlation.
    """

    @staticmethod
    def _provider_groups(
        observations: list[Observation],
    ) -> list[list[Observation]]:
        groups = {}
        independent = []

        for observation in observations:
            if observation.correlation_id is None:
                independent.append([observation])
                continue

            key = (
                observation.scan_id,
                observation.interface,
                observation.correlation_id,
            )
            groups.setdefault(key, []).append(observation)

        return list(groups.values()) + independent

    @staticmethod
    def _extract_ips(group: list[Observation]) -> set[str]:
        addresses = set()

        for observation in group:
            if observation.type != ObservationType.IP_ADDRESS:
                continue

            try:
                addresses.add(str(ip_address(observation.value)))
            except ValueError:
                continue

        return addresses

    @staticmethod
    def _extract_macs(group: list[Observation]) -> set[str]:
        addresses = set()

        for observation in group:
            if observation.type != ObservationType.MAC_ADDRESS:
                continue

            normalized = DeviceIdentityResolver.normalize_mac(
                observation.value
            )

            if normalized:
                addresses.add(normalized)

        return addresses

    @staticmethod
    def _group_scope(
        group: list[Observation],
    ) -> tuple[str, str | None]:
        first = group[0]
        return first.scan_id, first.interface

    def correlate(
        self,
        observations: Iterable[Observation],
    ) -> CorrelationResult:
        items = list(observations)

        if not all(isinstance(item, Observation) for item in items):
            raise TypeError(
                "observations must contain only Observation objects."
            )

        ids = [item.id for item in items]

        if len(ids) != len(set(ids)):
            raise ValueError(
                "Duplicate observation IDs are not allowed."
            )

        provider_groups = self._provider_groups(items)

        # Build candidate buckets using (scan, interface, IP).
        # Only groups containing exactly one valid IP are eligible.
        candidates = defaultdict(list)

        for index, group in enumerate(provider_groups):
            addresses = self._extract_ips(group)

            if len(addresses) != 1:
                continue

            scope = self._group_scope(group)
            address = next(iter(addresses))

            candidates[(*scope, address)].append(index)

        correlated_groups = []
        correlated_indices = set()
        ambiguous_relationships = []

        for key, indices in candidates.items():
            if len(indices) < 2:
                continue

            address = key[2]

            mac_sets = [
                self._extract_macs(provider_groups[index])
                for index in indices
            ]

            all_macs = set().union(*mac_sets)

            has_internal_conflict = any(
                len(mac_set) > 1
                for mac_set in mac_sets
            )

            if len(all_macs) > 1 or has_internal_conflict:
                observation_ids = tuple(sorted(
                    item.id
                    for index in indices
                    for item in provider_groups[index]
                ))

                ambiguous_relationships.append(
                    AmbiguousRelationship(
                        ip_address=address,
                        observation_ids=observation_ids,
                        reason=(
                            "Conflicting MAC addresses were found "
                            "among provider responses sharing this IP."
                        ),
                    )
                )
                continue

            combined = tuple(
                item
                for index in indices
                for item in provider_groups[index]
            )

            correlated_groups.append(
                CorrelatedObservationGroup(
                    observations=combined,
                    matched_ips=(address,),
                )
            )

            correlated_indices.update(indices)

        independent_groups = tuple(
            CorrelatedObservationGroup(
                observations=tuple(group),
            )
            for index, group in enumerate(provider_groups)
            if index not in correlated_indices
        )

        return CorrelationResult(
            groups=tuple(correlated_groups),
            independent_groups=independent_groups,
            ambiguous_relationships=tuple(ambiguous_relationships),
        )
