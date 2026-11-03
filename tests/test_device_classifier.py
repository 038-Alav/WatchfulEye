from watchfuleye.classification.device_classifier import DeviceClassifier
from watchfuleye.domain.observation import Observation, ObservationType


def make_observation(observation_type, value, source="test", confidence=1.0):
    return Observation(
        scan_id="scan-1",
        source=source,
        type=observation_type,
        value=value,
        device_id="device-1",
        confidence=confidence,
        interface="Wi-Fi",
    )


def test_classifies_camera_from_independent_signals_and_explains_why():
    evidence = [
        make_observation(ObservationType.HOSTNAME, "front-camera-01"),
        make_observation(ObservationType.MANUFACTURER, "Dahua Technology"),
        make_observation(ObservationType.PORT, "tcp/554", source="TCP_PROBE"),
        make_observation(ObservationType.SERVICE, "rtsp", source="SERVICE_DETECTOR"),
    ]

    result = DeviceClassifier().classify(evidence)

    assert result.device_type == "Camera / video device"
    assert result.confidence > 0.8
    assert any("Hostname" in item for item in result.evidence)
    assert any("RTSP" in item for item in result.evidence)


def test_classifier_does_not_count_port_and_service_as_two_independent_signals():
    classifier = DeviceClassifier()
    one_signal = [make_observation(ObservationType.PORT, "tcp/554")]
    duplicated_signal = one_signal + [
        make_observation(ObservationType.SERVICE, "rtsp", source="SERVICE_DETECTOR")
    ]

    first = classifier.classify(one_signal)
    second = classifier.classify(duplicated_signal)

    assert first.device_type == "Camera / video device"
    assert second.device_type == first.device_type
    assert second.confidence == first.confidence
    assert second.scores == first.scores


def test_classifier_returns_unknown_for_weak_or_conflicting_evidence():
    classifier = DeviceClassifier()
    weak = classifier.classify([
        make_observation(ObservationType.MANUFACTURER, "Apple, Inc.")
    ])
    conflict = classifier.classify([
        make_observation(ObservationType.HOSTNAME, "printer-camera")
    ])

    assert weak.device_type == "Unknown"
    assert conflict.device_type == "Unknown"


def test_previous_classifier_result_cannot_reinforce_itself():
    evidence = [
        make_observation(ObservationType.DEVICE_TYPE, "Camera / video device", source="DEVICE_CLASSIFIER"),
        make_observation(ObservationType.OTHER, '{"kind":"classification_evidence"}', source="DEVICE_CLASSIFIER"),
    ]

    result = DeviceClassifier().classify(evidence)

    assert result.device_type == "Unknown"
    assert result.scores == {}


def test_classification_observations_preserve_explanation():
    result = DeviceClassifier().classify([
        make_observation(ObservationType.PORT, "tcp/9100")
    ])

    observations = result.to_observations(
        scan_id="scan-2",
        device_id="device-1",
        interface="Ethernet",
    )

    assert [item.type for item in observations] == [
        ObservationType.DEVICE_TYPE,
        ObservationType.OTHER,
    ]
    assert observations[0].value == "Printer"
    assert '"kind": "classification_evidence"' in observations[1].value


def test_classifier_uses_mdns_service_type_embedded_in_composite_value():
    result = DeviceClassifier().classify([
        make_observation(
            ObservationType.SERVICE,
            "Front Door Camera | _rtsp._tcp.local. | port=554",
            source="mDNS",
        )
    ])

    assert result.device_type == "Camera / video device"
    assert any("RTSP service" in item for item in result.evidence)


def test_unknown_classification_can_be_explained_and_persisted():
    evidence = [make_observation(ObservationType.MANUFACTURER, "Xiaomi Communications Co Ltd")]
    result = DeviceClassifier().classify(evidence)
    assert result.device_type == "Unknown"
    assert "No known classification rule" in result.reason
    snapshots = result.to_observations(
        scan_id="scan-2", device_id="device-1", interface="Wi-Fi"
    )
    assert len(snapshots) == 2
    assert snapshots[0].value == "Unknown"
    assert '"status": "insufficient_evidence"' in snapshots[1].value
