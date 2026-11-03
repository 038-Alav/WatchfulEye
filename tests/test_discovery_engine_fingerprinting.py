from watchfuleye.application.discovery_engine import DiscoveryEngine
from watchfuleye.domain.device import Device
from watchfuleye.domain.observation import Observation, ObservationType
from watchfuleye.domain.scan import ProviderExecutionResult, ProviderStatus
from watchfuleye.persistence.device_repository import DeviceRepository
from watchfuleye.persistence.observation_repository import ObservationRepository
from watchfuleye.persistence.scan_repository import ScanRepository


class FakeCoordinator:
    def __init__(self, observation_factory):
        self.observation_factory = observation_factory

    def execute(self, context):
        return [
            ProviderExecutionResult(
                provider="TEST_PROVIDER",
                status=ProviderStatus.SUCCESS,
                observations=self.observation_factory(context),
            )
        ]


class NoopEnrichment:
    def run(self, observations):
        return []


class FakeFingerprinting:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def run(self, targets, *, network_cidr, scan_id, timeout_seconds):
        self.calls.append((targets, network_cidr, scan_id, timeout_seconds))
        if self.fail:
            raise RuntimeError("probe failure")

        target = targets[0]
        return [
            Observation(
                scan_id=scan_id,
                source="TCP_PROBE",
                type=ObservationType.PORT,
                value="tcp/554",
                device_id=target.device_id,
                correlation_id=f"fingerprint:{scan_id}:{target.device_id}",
                confidence=0.99,
                interface=target.interface_name,
            )
        ]


def make_identity_observations(context):
    return [
        Observation(
            scan_id=context.scan_id,
            source="TEST_PROVIDER",
            type=ObservationType.MAC_ADDRESS,
            value="00:11:22:33:44:55",
            correlation_id="same-response",
            interface=context.interface_name,
        ),
        Observation(
            scan_id=context.scan_id,
            source="TEST_PROVIDER",
            type=ObservationType.IP_ADDRESS,
            value="192.168.100.20",
            correlation_id="same-response",
            interface=context.interface_name,
        ),
        Observation(
            scan_id=context.scan_id,
            source="TEST_PROVIDER",
            type=ObservationType.HOSTNAME,
            value="front-camera-01",
            correlation_id="same-response",
            interface=context.interface_name,
        ),
    ]


def build_engine(tmp_path, fingerprinting, observation_factory=make_identity_observations):
    return DiscoveryEngine(
        coordinator=FakeCoordinator(observation_factory),
        scan_repository=ScanRepository(tmp_path / "scans.json"),
        observation_repository=ObservationRepository(tmp_path / "observations.json"),
        device_repository=DeviceRepository(tmp_path / "devices.json"),
        enrichment_pipeline=NoopEnrichment(),
        fingerprinting_service=fingerprinting,
    )


def test_engine_fingerprints_resolved_device_and_persists_classification(tmp_path):
    fingerprinting = FakeFingerprinting()
    engine = build_engine(tmp_path, fingerprinting)

    result = engine.discover(
        network_cidr="192.168.100.0/24",
        interface_name="Wi-Fi",
    )

    devices = engine.get_devices()
    assert len(devices) == 1
    device = devices[0]
    assert device.ip == "192.168.100.20"
    assert device.device_type == "Camera / video device"

    assert len(fingerprinting.calls) == 1
    targets = fingerprinting.calls[0][0]
    assert len(targets) == 1
    assert targets[0].device_id == device.id
    assert targets[0].ip_address == "192.168.100.20"

    persisted = engine.observation_repository.get_by_device(device.id)
    assert any(item.type == ObservationType.PORT and item.value == "tcp/554" for item in persisted)
    assert any(item.type == ObservationType.DEVICE_TYPE for item in persisted)
    assert any(item.type == ObservationType.OTHER and item.source == "DEVICE_CLASSIFIER" for item in persisted)
    assert all(item.scan_id == result.scan.id for item in result.observations)


def test_engine_does_not_fingerprint_ip_only_unresolved_observation(tmp_path):
    fingerprinting = FakeFingerprinting()

    def ip_only(context):
        return [
            Observation(
                scan_id=context.scan_id,
                source="TEST_PROVIDER",
                type=ObservationType.IP_ADDRESS,
                value="192.168.100.20",
                interface=context.interface_name,
            )
        ]

    engine = build_engine(tmp_path, fingerprinting, ip_only)
    result = engine.discover(
        network_cidr="192.168.100.0/24",
        interface_name="Wi-Fi",
    )

    assert fingerprinting.calls == []
    assert result.observations[0].device_id is None
    assert engine.get_devices() == []


def test_engine_does_not_fingerprint_stale_inventory_ip(tmp_path):
    fingerprinting = FakeFingerprinting()

    def no_observations(context):
        return []

    engine = build_engine(tmp_path, fingerprinting, no_observations)
    stale_device = Device(
        ip="192.168.100.20",
        mac="00:11:22:33:44:55",
    )
    engine.device_repository.save_all([stale_device])

    engine.discover(
        network_cidr="192.168.100.0/24",
        interface_name="Wi-Fi",
    )

    assert fingerprinting.calls == []
    assert engine.get_devices()[0].ip == "192.168.100.20"


def test_fingerprinting_failure_does_not_fail_successful_discovery(tmp_path):
    fingerprinting = FakeFingerprinting(fail=True)
    engine = build_engine(tmp_path, fingerprinting)

    result = engine.discover(
        network_cidr="192.168.100.0/24",
        interface_name="Wi-Fi",
    )

    assert result.successful is True
    assert result.scan.status.value == "SUCCESS"
    assert any(error.startswith("Fingerprinting:") for error in result.errors)
    assert len(engine.get_devices()) == 1
    # Hostname evidence can still classify the device even though active
    # fingerprinting failed; discovery itself remains successful.
    assert engine.get_devices()[0].device_type == "Camera / video device"
    persisted = engine.observation_repository.get_all()
    assert not any(item.type == ObservationType.PORT for item in persisted)


def test_engine_does_not_append_identical_classifier_result_every_scan(tmp_path):
    fingerprinting = FakeFingerprinting()
    engine = build_engine(tmp_path, fingerprinting)

    engine.discover(
        network_cidr="192.168.100.0/24",
        interface_name="Wi-Fi",
    )
    first_history = engine.observation_repository.get_all()
    first_classifications = [
        item for item in first_history
        if item.type == ObservationType.DEVICE_TYPE
        and item.source == "DEVICE_CLASSIFIER"
    ]
    assert len(first_classifications) == 1

    engine.discover(
        network_cidr="192.168.100.0/24",
        interface_name="Wi-Fi",
    )
    second_history = engine.observation_repository.get_all()
    second_classifications = [
        item for item in second_history
        if item.type == ObservationType.DEVICE_TYPE
        and item.source == "DEVICE_CLASSIFIER"
    ]

    assert len(second_classifications) == 1
    assert engine.get_devices()[0].device_type == "Camera / video device"


def test_engine_persists_unknown_then_upgrades_when_new_evidence_arrives(tmp_path):
    fingerprinting = FakeFingerprinting(fail=True)

    def mac_ip_only(context):
        return [
            Observation(
                scan_id=context.scan_id,
                source="TEST_PROVIDER",
                type=ObservationType.MAC_ADDRESS,
                value="00:11:22:33:44:66",
                correlation_id="same-response",
                interface=context.interface_name,
            ),
            Observation(
                scan_id=context.scan_id,
                source="TEST_PROVIDER",
                type=ObservationType.IP_ADDRESS,
                value="192.168.100.21",
                correlation_id="same-response",
                interface=context.interface_name,
            ),
        ]

    engine = build_engine(tmp_path, fingerprinting, mac_ip_only)
    engine.discover("192.168.100.0/24", "Wi-Fi")
    device = engine.get_devices()[0]
    assert device.device_type == "Unknown"

    def add_server_hostname(context):
        return mac_ip_only(context) + [
            Observation(
                scan_id=context.scan_id,
                source="TEST_PROVIDER",
                type=ObservationType.HOSTNAME,
                value="database-server-01",
                correlation_id="same-response",
                interface=context.interface_name,
            )
        ]

    engine.coordinator.observation_factory = add_server_hostname
    engine.discover("192.168.100.0/24", "Wi-Fi")

    updated = engine.get_devices()[0]
    assert updated.id == device.id
    assert updated.device_type == "Server"


def test_engine_exposes_device_observation_history(tmp_path):
    engine = build_engine(tmp_path, FakeFingerprinting())
    engine.discover(
        network_cidr="192.168.100.0/24",
        interface_name="Wi-Fi",
    )
    device = engine.get_devices()[0]
    observations = engine.get_device_observations(device.id)
    assert observations
    assert all(item.device_id == device.id for item in observations)


def test_engine_persists_unknown_classification_explanation(tmp_path):
    fingerprinting = FakeFingerprinting(fail=True)

    def mac_ip_manufacturer(context):
        return [
            Observation(
                scan_id=context.scan_id, source="TEST_PROVIDER",
                type=ObservationType.MAC_ADDRESS, value="00:11:22:33:44:77",
                correlation_id="same-response", interface=context.interface_name,
            ),
            Observation(
                scan_id=context.scan_id, source="TEST_PROVIDER",
                type=ObservationType.IP_ADDRESS, value="192.168.100.22",
                correlation_id="same-response", interface=context.interface_name,
            ),
            Observation(
                scan_id=context.scan_id, source="TEST_PROVIDER",
                type=ObservationType.MANUFACTURER, value="Xiaomi Communications Co Ltd",
                correlation_id="same-response", interface=context.interface_name,
            ),
        ]

    engine = build_engine(tmp_path, fingerprinting, mac_ip_manufacturer)
    engine.discover("192.168.100.0/24", "Wi-Fi")
    device = engine.get_devices()[0]
    assert device.device_type == "Unknown"

    history = engine.get_device_observations(device.id)
    unknown_type = [
        item for item in history
        if item.source == "DEVICE_CLASSIFIER"
        and item.type == ObservationType.DEVICE_TYPE
    ]
    explanations = [
        item for item in history
        if item.source == "DEVICE_CLASSIFIER"
        and item.type == ObservationType.OTHER
    ]
    assert len(unknown_type) == 1
    assert len(explanations) == 1
    assert "No known classification rule" in explanations[0].value


def test_engine_does_not_append_identical_unknown_classification_each_scan(tmp_path):
    fingerprinting = FakeFingerprinting(fail=True)

    def no_classifier_signal(context):
        return [
            Observation(
                scan_id=context.scan_id,
                source="TEST_PROVIDER",
                type=ObservationType.MAC_ADDRESS,
                value="00:11:22:33:44:88",
                correlation_id="same-response",
                interface=context.interface_name,
            ),
            Observation(
                scan_id=context.scan_id,
                source="TEST_PROVIDER",
                type=ObservationType.IP_ADDRESS,
                value="192.168.100.23",
                correlation_id="same-response",
                interface=context.interface_name,
            ),
            Observation(
                scan_id=context.scan_id,
                source="TEST_PROVIDER",
                type=ObservationType.MANUFACTURER,
                value="Generic Network Adapter Manufacturer",
                correlation_id="same-response",
                interface=context.interface_name,
            ),
        ]

    engine = build_engine(tmp_path, fingerprinting, no_classifier_signal)
    engine.discover("192.168.100.0/24", "Wi-Fi")
    first = engine.get_device_observations(engine.get_devices()[0].id)
    engine.discover("192.168.100.0/24", "Wi-Fi")
    second = engine.get_device_observations(engine.get_devices()[0].id)

    first_unknown = [
        item for item in first
        if item.source == "DEVICE_CLASSIFIER" and item.type == ObservationType.DEVICE_TYPE
    ]
    second_unknown = [
        item for item in second
        if item.source == "DEVICE_CLASSIFIER" and item.type == ObservationType.DEVICE_TYPE
    ]
    assert len(first_unknown) == 1
    assert len(second_unknown) == 1
