from dataclasses import dataclass, replace
from ipaddress import ip_address
from typing import Iterable

from watchfuleye.domain.device import Device
from watchfuleye.domain.observation import (
    Observation,
    ObservationType,
)
from watchfuleye.identity.device_identity_resolver import (
    DeviceIdentityResolver,
)
from watchfuleye.identity.observation_correlator import (
    ObservationCorrelator,
)
from watchfuleye.identity.observation_value_selector import (
    ObservationValueSelector,
)

@dataclass
class AggregationResult:
    """
    Output produced by ObservationAggregator.

    devices:
        Newly created devices and updated copies of existing devices.

    observations:
        Copies of all input observations, including assigned device IDs.

    unresolved_observations:
        Observations that could not be safely associated with a device.

    ambiguous_group_count:
        Number of evidence groups containing conflicting identity data.
    """

    devices: list[Device]
    observations: list[Observation]
    unresolved_observations: list[Observation]
    ambiguous_group_count: int = 0


class ObservationAggregator:
    """
    Groups related observations and associates them with devices.

    This component does not persist data or mutate its input objects.
    """

    def __init__(
        self,
        identity_resolver: DeviceIdentityResolver | None = None,
        observation_correlator: ObservationCorrelator | None = None,
        observation_value_selector: ObservationValueSelector | None = None,
    ):
        self.identity_resolver = (
            identity_resolver or DeviceIdentityResolver()
        )
        self.observation_correlator = (
            observation_correlator or ObservationCorrelator()
        )
        self.observation_value_selector = (
            observation_value_selector
            if observation_value_selector is not None
            else ObservationValueSelector()
        )

    @staticmethod
    def _group_observations(
        observations: list[Observation],
    ) -> list[list[Observation]]:
        """
        Group observations originating from the same correlation.

        Correlation IDs are scoped by scan, provider and interface.

        Observations without correlation IDs remain independent.
        """

        groups = {}
        
        for index, observation in enumerate(observations):

            if observation.correlation_id is None:
                # Never group unrelated observations just because
                # they have no correlation ID.
                key = ("individual", index)

            else:
                key = (
                    observation.scan_id,
                    observation.interface,
                    observation.correlation_id,
                )

            groups.setdefault(key, []).append(observation)

        return list(groups.values())

    @staticmethod
    def _extract_preferred_value(
        group: list[Observation],
        observation_type: ObservationType,
    ) -> str | None:
        """
        Select the strongest available value for a device field.

        Higher-confidence evidence takes precedence. When confidence
        is equal, the most recent observation takes precedence.
        """
        return ObservationValueSelector().select_value(
            group,
            observation_type,
        )

    def _apply_preferred_values(
        self,
        device: Device,
        evidence: list[Observation],
    ) -> None:
        """Populate empty device fields from the strongest associated evidence.

        Evidence is selected across all groups resolved to this device during
        the current aggregation run. Existing non-placeholder values are
        preserved because Device does not yet retain the confidence and
        provenance behind previously stored field values.
        """
        field_policies = (
            ("manufacturer", ObservationType.MANUFACTURER),
            ("hostname", ObservationType.HOSTNAME),
            ("operating_system", ObservationType.OPERATING_SYSTEM),
            ("device_type", ObservationType.DEVICE_TYPE),
        )
        placeholders = {"", "unknown", "none", "n/a", "not available"}

        for field_name, observation_type in field_policies:
            selected_value = self.observation_value_selector.select_value(
                evidence,
                observation_type,
            )
            if selected_value is None:
                continue

            current_value = getattr(device, field_name, None)
            if (
                current_value is None
                or str(current_value).strip().casefold() in placeholders
            ):
                setattr(device, field_name, selected_value)
    
    @staticmethod
    def _extract_mac(
        group: list[Observation],
        resolver: DeviceIdentityResolver,
    ) -> tuple[str | None, bool]:
        """
        Return the single normalized MAC address in a group.

        The boolean indicates conflicting or invalid MAC evidence.
        """

        mac_observations = [
            observation
            for observation in group
            if observation.type == ObservationType.MAC_ADDRESS
        ]

        if not mac_observations:
            return None, False

        normalized_macs = {
            resolver.normalize_mac(observation.value)
            for observation in mac_observations
        }

        if None in normalized_macs or len(normalized_macs) != 1:
            return None, True

        return next(iter(normalized_macs)), False

    @staticmethod
    def _extract_ip(
        group: list[Observation],
    ) -> tuple[str | None, bool]:
        """
        Return the single normalized IP address in a group.

        The boolean indicates conflicting or invalid IP evidence.
        """

        ip_observations = [
            observation
            for observation in group
            if observation.type == ObservationType.IP_ADDRESS
        ]

        if not ip_observations:
            return None, False

        try:
            addresses = {
                str(ip_address(observation.value))
                for observation in ip_observations
            }
        except ValueError:
            return None, True

        if len(addresses) != 1:
            return None, True

        return next(iter(addresses)), False

    @staticmethod
    def _observation_times(
        group: list[Observation],
    ):
        timestamps = [
            observation.timestamp
            for observation in group
        ]

        return min(timestamps), max(timestamps)

    def _aggregate(
        self,
        observations: Iterable[Observation],
        devices: Iterable[Device],
        groups: list[list[Observation]] | None = None,
    ) -> AggregationResult:
        """
        Associate correlated observations with existing or new devices.

        Existing devices are matched using DeviceIdentityResolver.
        New devices require one valid MAC address.

        Input devices and observations are never modified.
        """

        observations = list(observations)
        devices = list(devices)

        if not all(
            isinstance(item, Observation)
            for item in observations
        ):
            raise TypeError(
                "observations must contain only Observation objects."
            )

        if not all(
            isinstance(item, Device)
            for item in devices
        ):
            raise TypeError(
                "devices must contain only Device objects."
            )

        observation_ids = [
            observation.id
            for observation in observations
        ]

        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError(
                "Duplicate observation IDs are not allowed."
            )

        device_ids = [
            device.id
            for device in devices
        ]


        if len(device_ids) != len(set(device_ids)):
            raise ValueError(
                "Duplicate device IDs are not allowed."
            )

        # Create independent copies. Aggregation must not mutate
        # the objects owned by the caller or repositories.
        aggregated_observations = [
            replace(observation)
            for observation in observations
        ]

        observations_by_id = {
            observation.id: observation
            for observation in aggregated_observations
        }

        working_devices = list(devices)

        affected_devices: dict[str, Device] = {}
        device_evidence_by_id: dict[str, list[Observation]] = {}
        unresolved_observations = []
        ambiguous_group_count = 0

        if groups is None:
            groups = self._group_observations(observations)

        for group in groups:

            mac_address, invalid_mac = self._extract_mac(
                group,
                self.identity_resolver,
            )

            ip_address_value, invalid_ip = self._extract_ip(group)

            if invalid_mac or invalid_ip:
                unresolved_observations.extend(
                    observations_by_id[item.id]
                    for item in group
                )

                ambiguous_group_count += 1
                continue

            if mac_address is None:
                # An IP address alone is insufficient to establish
                # permanent device identity.
                unresolved_observations.extend(
                    observations_by_id[item.id]
                    for item in group
                )
                continue

            resolution = self.identity_resolver.resolve(
                mac_address,
                working_devices,
            )

            if resolution.ambiguous:
                unresolved_observations.extend(
                    observations_by_id[item.id]
                    for item in group
                )

                ambiguous_group_count += 1
                continue

            first_observed, last_observed = (
                self._observation_times(group)
            )

            if resolution.matched_existing:

                existing_device = next(
                    device
                    for device in working_devices
                    if device.id == resolution.device_id
                )

                # Update a copy, preserving the original object.
                device = replace(existing_device)

                device.mac = mac_address

                if (
                    ip_address_value is not None
                    and last_observed >= device.last_seen
                ):
                    device.ip = ip_address_value

                # Preserve the earliest known observation.
                device.first_seen = min(
                    device.first_seen,
                    first_observed,
                )

                # Preserve the most recent observation.
                device.last_seen = max(
                    device.last_seen,
                    last_observed,
                )

                # Replace the working copy so subsequent evidence
                # can resolve against the updated device.
                for index, candidate in enumerate(working_devices):
                    if candidate.id == device.id:
                        working_devices[index] = device
                        break

            else:

                # Create a provisional device with a new UUID.
                # Its status remains UNKNOWN until monitoring logic
                # determines availability in a later phase.
                device = Device(
                    mac=mac_address,
                    ip=ip_address_value,
                    first_seen=first_observed,
                    last_seen=last_observed,
                )

                working_devices.append(device)

            affected_devices[device.id] = device

            # Associate every observation in this group with the
            # resolved permanent device UUID.
            for observation in group:
                associated_observation = observations_by_id[observation.id]
                associated_observation.device_id = device.id
                device_evidence_by_id.setdefault(
                    device.id,
                    [],
                ).append(associated_observation)

        # Select descriptive fields only after every evidence group has been
        # associated. This allows evidence from separate provider responses
        # to compete using the same confidence/timestamp policy.
        for device_id, device_evidence in device_evidence_by_id.items():
            device = next(
                candidate
                for candidate in working_devices
                if candidate.id == device_id
            )

            self._apply_preferred_values(
                device,
                device_evidence,
            )
            affected_devices[device_id] = device

        return AggregationResult(
            devices=list(affected_devices.values()),
            observations=aggregated_observations,
            unresolved_observations=unresolved_observations,
            ambiguous_group_count=ambiguous_group_count,
        )
    
    def aggregate(
        self,
        observations: Iterable[Observation],
        devices: Iterable[Device],
    ) -> AggregationResult:
        """
        Aggregate observations using their existing correlation IDs.

        Preserves the original aggregation behavior.
        """
        return self._aggregate(
            observations=observations,
            devices=devices,
        )


    def aggregate_correlated(
        self,
        observations: Iterable[Observation],
        devices: Iterable[Device],
    ) -> AggregationResult:
        """
        Correlate independent provider responses before aggregation.

        Cross-provider relationships are determined by ObservationCorrelator.
        Device association remains the responsibility of this aggregator.
        """
        observations = list(observations)

        correlation_result = self.observation_correlator.correlate(
            observations
        )

        groups = [
            list(group.observations)
            for group in (
                *correlation_result.groups,
                *correlation_result.independent_groups,
            )
        ]

        return self._aggregate(
            observations=observations,
            devices=devices,
            groups=groups,
        )
    
    
