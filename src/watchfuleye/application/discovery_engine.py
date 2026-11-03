from __future__ import annotations

import ipaddress
import json
import logging
import time
from collections import defaultdict

from watchfuleye.application.discovery_coordinator import DiscoveryCoordinator
from watchfuleye.application.enrichment_pipeline import EnrichmentPipeline
from watchfuleye.application.fingerprinting_service import (
    FingerprintTarget,
    FingerprintingService,
)
from watchfuleye.classification.device_classifier import DeviceClassifier
from watchfuleye.discovery.context import DiscoveryContext
from watchfuleye.domain.device import Device
from watchfuleye.domain.observation import Observation, ObservationType
from watchfuleye.domain.scan import (
    DiscoveryResult,
    ProviderStatus,
    ScanRun,
    ScanStatus,
)
from watchfuleye.identity.observation_aggregator import ObservationAggregator
from watchfuleye.persistence.device_repository import DeviceRepository
from watchfuleye.persistence.observation_repository import ObservationRepository
from watchfuleye.persistence.scan_repository import ScanRepository


logger = logging.getLogger(__name__)


class DiscoveryEngine:
    """Orchestrate discovery, enrichment, identity, fingerprinting and storage.

    Discovery providers and enrichers only return observations. The
    ObservationAggregator remains the sole owner of identity association.
    Fingerprinting runs after aggregation and can only target IP addresses
    associated with a device during the current scan.
    """

    PLACEHOLDERS = {"", "unknown", "none", "n/a", "not available", "unclassified"}

    def __init__(
        self,
        coordinator: DiscoveryCoordinator,
        scan_repository: ScanRepository,
        observation_repository: ObservationRepository,
        device_repository: DeviceRepository,
        enrichment_pipeline: EnrichmentPipeline | None = None,
        observation_aggregator: ObservationAggregator | None = None,
        fingerprinting_service: FingerprintingService | None = None,
        device_classifier: DeviceClassifier | None = None,
    ):
        self.coordinator = coordinator
        self.scan_repository = scan_repository
        self.observation_repository = observation_repository
        self.device_repository = device_repository
        self.enrichment_pipeline = enrichment_pipeline or EnrichmentPipeline()
        self.observation_aggregator = observation_aggregator or ObservationAggregator()
        self.fingerprinting_service = fingerprinting_service or FingerprintingService()
        self.device_classifier = device_classifier or DeviceClassifier()

    @staticmethod
    def _build_fingerprinting_targets(
        observations: list[Observation],
        *,
        scan_id: str,
        network_cidr: str,
        interface_name: str,
    ) -> list[FingerprintTarget]:
        """Use only current-scan IP observations already associated to UUIDs."""
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
        except ValueError:
            logger.warning("Fingerprinting skipped: invalid network CIDR %r", network_cidr)
            return []

        if network.version != 4:
            return []

        unique: dict[tuple[str, str], FingerprintTarget] = {}
        for observation in observations:
            if (
                observation.scan_id != scan_id
                or observation.type != ObservationType.IP_ADDRESS
                or not observation.device_id
            ):
                continue

            try:
                address = ipaddress.ip_address(observation.value)
            except ValueError:
                continue

            if address.version != 4 or address not in network:
                continue

            target = FingerprintTarget(
                device_id=observation.device_id,
                ip_address=str(address),
                interface_name=interface_name,
            )
            unique.setdefault((target.device_id, target.ip_address), target)

        return list(unique.values())

    @staticmethod
    def _merge_inventory(
        existing_devices: list[Device],
        affected_devices: list[Device],
    ) -> list[Device]:
        updated = {device.id: device for device in affected_devices}
        complete_inventory = []

        for existing_device in existing_devices:
            complete_inventory.append(
                updated.pop(existing_device.id, existing_device)
            )

        complete_inventory.extend(updated.values())
        return complete_inventory

    @classmethod
    def _is_placeholder(cls, value: str | None) -> bool:
        return value is None or str(value).strip().casefold() in cls.PLACEHOLDERS

    @staticmethod
    def _latest_classifier_observation(
        observations: list[Observation],
    ) -> Observation | None:
        candidates = [
            observation
            for observation in observations
            if observation.type == ObservationType.DEVICE_TYPE
            and observation.source == "DEVICE_CLASSIFIER"
        ]
        return max(candidates, key=lambda item: item.timestamp, default=None)

    @staticmethod
    def _latest_classifier_explanation(
        observations: list[Observation],
        classification_observation: Observation | None,
    ) -> dict | None:
        if classification_observation is None:
            return None
        for observation in observations:
            if (
                observation.source == "DEVICE_CLASSIFIER"
                and observation.type == ObservationType.OTHER
                and observation.scan_id == classification_observation.scan_id
                and observation.correlation_id == classification_observation.correlation_id
            ):
                try:
                    payload = json.loads(observation.value)
                except (TypeError, ValueError):
                    return None
                return payload if isinstance(payload, dict) else None
        return None

    @staticmethod
    def _classification_support_changed(
        previous_payload: dict | None,
        current_observations: list[Observation],
    ) -> bool:
        if previous_payload is None:
            return True
        current_payload = next(
            (
                payload
                for item in current_observations
                if (payload := DiscoveryEngine._safe_json_object(item.value)) is not None
                and item.source == "DEVICE_CLASSIFIER"
                and item.type == ObservationType.OTHER
            ),
            None,
        )
        if current_payload is None:
            return False
        if (
            previous_payload.get("device_type") != current_payload.get("device_type")
            or previous_payload.get("reason") != current_payload.get("reason")
            or previous_payload.get("evidence") != current_payload.get("evidence")
        ):
            return True
        previous_scores = previous_payload.get("scores", {})
        current_scores = current_payload.get("scores", {})
        if not isinstance(previous_scores, dict) or not isinstance(current_scores, dict):
            return previous_scores != current_scores
        keys = set(previous_scores) | set(current_scores)
        for key in keys:
            try:
                old_score = float(previous_scores.get(key, 0.0))
                new_score = float(current_scores.get(key, 0.0))
            except (TypeError, ValueError):
                return True
            if abs(new_score - old_score) >= 0.10:
                return True
        return False

    @staticmethod
    def _safe_json_object(value: str) -> dict | None:
        try:
            payload = json.loads(value)
        except (TypeError, ValueError):
            return None
        return payload if isinstance(payload, dict) else None

    def _classify_inventory(
        self,
        *,
        scan_id: str,
        interface_name: str,
        devices: list[Device],
        current_observations: list[Observation],
        historical_observations: list[Observation],
    ) -> tuple[list[Observation], float]:
        started = time.perf_counter()
        observations_by_device: dict[str, list[Observation]] = defaultdict(list)

        for observation in historical_observations + current_observations:
            if observation.device_id:
                observations_by_device[observation.device_id].append(observation)

        devices_by_id = {device.id: device for device in devices}
        generated_observations: list[Observation] = []

        for device_id, evidence in observations_by_device.items():
            device = devices_by_id.get(device_id)
            if device is None:
                continue

            classification = self.device_classifier.classify(evidence)

            # The current device summary is populated only from the strongest
            # available OS evidence and never erases an existing known value.
            if self._is_placeholder(device.operating_system):
                os_observations = [
                    item for item in evidence
                    if item.type == ObservationType.OPERATING_SYSTEM
                ]
                if os_observations:
                    selected_os = max(
                        os_observations,
                        key=lambda item: (item.confidence, item.timestamp),
                    )
                    device.operating_system = selected_os.value

            if not classification.is_classified and self._is_placeholder(device.device_type):
                # Unknown is an explicit, upgradeable inventory state. The
                # explanation is persisted below so users can see why.
                device.device_type = "Unknown"

            previous = self._latest_classifier_observation(evidence)
            previous_explanation = self._latest_classifier_explanation(
                evidence, previous
            )
            has_existing_type = not self._is_placeholder(device.device_type)
            can_replace_type = (
                not has_existing_type
                or previous is not None
                and (
                    previous.value == classification.device_type
                    or classification.confidence >= previous.confidence
                )
            )

            if classification.is_classified and can_replace_type:
                device.device_type = classification.device_type
            elif not classification.is_classified and self._is_placeholder(device.device_type):
                device.device_type = "Unknown"

            candidate_snapshot = classification.to_observations(
                scan_id=scan_id,
                device_id=device_id,
                interface=interface_name,
            )
            should_record = (
                previous is None
                or previous.value != classification.device_type
                or classification.confidence >= previous.confidence + 0.03
                or self._classification_support_changed(
                    previous_explanation, candidate_snapshot
                )
            )
            if should_record and can_replace_type:
                generated_observations.extend(candidate_snapshot)

        elapsed = time.perf_counter() - started
        return generated_observations, elapsed

    def discover(
        self,
        network_cidr: str,
        interface_name: str,
        timeout_seconds: int = 2,
    ) -> DiscoveryResult:
        total_started = time.perf_counter()

        scan = ScanRun(
            network_cidr=network_cidr,
            interface_name=interface_name,
        )
        context = DiscoveryContext(
            network_cidr=network_cidr,
            interface_name=interface_name,
            scan_id=scan.id,
            timeout_seconds=timeout_seconds,
        )

        # 1. Execute discovery providers.
        provider_started = time.perf_counter()
        provider_results = self.coordinator.execute(context)
        provider_elapsed = time.perf_counter() - provider_started
        scan.provider_results = provider_results

        provider_observations: list[Observation] = []
        successful = 0
        unsuccessful = 0
        for result in provider_results:
            if result.status == ProviderStatus.SUCCESS:
                successful += 1
                scan.providers_executed.append(result.provider)
                provider_observations.extend(result.observations)
            else:
                unsuccessful += 1
                scan.errors.append(
                    f"{result.provider}: {result.error or result.status.value}"
                )

        # 2. Determine discovery-provider scan status.
        if successful == 0:
            status = ScanStatus.FAILED
        elif unsuccessful > 0:
            status = ScanStatus.PARTIAL
        else:
            status = ScanStatus.SUCCESS

        # 3. Run the existing enrichment pipeline.
        enrichment_started = time.perf_counter()
        enriched_observations: list[Observation] = []
        if provider_observations:
            try:
                enriched_observations = self.enrichment_pipeline.run(
                    provider_observations
                )
            except Exception:
                logger.exception("Enrichment pipeline failed for scan %s.", scan.id)
        enrichment_elapsed = time.perf_counter() - enrichment_started
        all_observations = provider_observations + enriched_observations

        # 4. Load current inventory and resolve observation identity.
        inventory_started = time.perf_counter()
        existing_devices = self.device_repository.get_all()
        inventory_load_elapsed = time.perf_counter() - inventory_started

        aggregation_started = time.perf_counter()
        aggregation_result = self.observation_aggregator.aggregate_correlated(
            observations=all_observations,
            devices=existing_devices,
        )
        aggregation_elapsed = time.perf_counter() - aggregation_started

        # 5. Merge updated device copies into the complete inventory.
        complete_inventory = self._merge_inventory(
            existing_devices,
            aggregation_result.devices,
        )

        # 6. Fingerprint only current-scan addresses already associated with
        #    a stable device UUID. Never probe a stale Device.ip by itself.
        fingerprint_started = time.perf_counter()
        targets = self._build_fingerprinting_targets(
            aggregation_result.observations,
            scan_id=scan.id,
            network_cidr=network_cidr,
            interface_name=interface_name,
        )
        fingerprint_observations: list[Observation] = []
        if targets:
            try:
                fingerprint_observations = self.fingerprinting_service.run(
                    targets,
                    network_cidr=network_cidr,
                    scan_id=scan.id,
                    timeout_seconds=timeout_seconds,
                )
            except Exception as exc:
                # Fingerprinting is optional enrichment. A failure must not
                # invalidate successful device discovery or inventory updates,
                # but it should remain visible in the scan's warning summary.
                logger.exception("Fingerprinting failed for scan %s.", scan.id)
                scan.errors.append(f"Fingerprinting: {type(exc).__name__}: {exc}")
        fingerprint_elapsed = time.perf_counter() - fingerprint_started

        # 7. Load history once, then classify all devices with current evidence.
        historical_observations = self.observation_repository.get_all()
        evidence_observations = (
            aggregation_result.observations + fingerprint_observations
        )
        classification_observations, classification_elapsed = (
            self._classify_inventory(
                scan_id=scan.id,
                interface_name=interface_name,
                devices=complete_inventory,
                current_observations=evidence_observations,
                historical_observations=historical_observations,
            )
        )

        # 8. Finish scan metadata and persist all evidence.
        scan.finish(status)
        persistence_started = time.perf_counter()
        new_observations = (
            aggregation_result.observations
            + fingerprint_observations
            + classification_observations
        )
        self.device_repository.save_all(complete_inventory)
        self.observation_repository.add_many(new_observations)
        self.scan_repository.add(scan)
        persistence_elapsed = time.perf_counter() - persistence_started

        total_elapsed = time.perf_counter() - total_started
        logger.debug(
            "Discovery performance | scan=%s | providers=%.2fs | "
            "enrichment=%.2fs | inventory_load=%.2fs | aggregation=%.2fs | "
            "fingerprinting=%.2fs | classification=%.2fs | "
            "persistence=%.2fs | total=%.2fs",
            scan.id,
            provider_elapsed,
            enrichment_elapsed,
            inventory_load_elapsed,
            aggregation_elapsed,
            fingerprint_elapsed,
            classification_elapsed,
            persistence_elapsed,
            total_elapsed,
        )

        for result in provider_results:
            logger.debug(
                "Provider performance | provider=%s | duration=%.2fs | status=%s",
                result.provider,
                result.duration_ms / 1000,
                result.status.value,
            )

        return DiscoveryResult(
            scan=scan,
            observations=new_observations,
            provider_results=provider_results,
        )

    def get_devices(self) -> list[Device]:
        """Return the current persisted device inventory."""
        return self.device_repository.get_all()

    def get_device_observations(self, device_id: str) -> list[Observation]:
        """Return the complete persisted evidence history for one device."""
        if not isinstance(device_id, str) or not device_id.strip():
            raise ValueError("device_id must be a non-empty string.")
        return self.observation_repository.get_by_device(device_id)
