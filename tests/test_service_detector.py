from watchfuleye.domain.observation import Observation, ObservationType
from watchfuleye.enrichment.service_detector import ServiceDetector


def test_service_detector_maps_open_ports_without_losing_context():
    observations = [
        Observation(
            scan_id="scan-1",
            source="TCP_PROBE",
            type=ObservationType.PORT,
            value="tcp/554",
            device_id="device-1",
            correlation_id="fp-1",
            interface="Wi-Fi",
        ),
        Observation(
            scan_id="scan-1",
            source="TCP_PROBE",
            type=ObservationType.PORT,
            value="tcp/554",
            device_id="device-1",
            correlation_id="fp-1",
            interface="Wi-Fi",
        ),
        Observation(
            scan_id="scan-1",
            source="TCP_PROBE",
            type=ObservationType.PORT,
            value="tcp/65000",
            device_id="device-1",
            correlation_id="fp-1",
            interface="Wi-Fi",
        ),
    ]

    result = ServiceDetector().detect(observations)

    assert len(result) == 1
    assert result[0].type == ObservationType.SERVICE
    assert result[0].value == "rtsp"
    assert result[0].device_id == "device-1"
    assert result[0].correlation_id == "fp-1"


def test_service_detector_ignores_non_tcp_service_observations():
    observation = Observation(
        scan_id="scan-1",
        source="mDNS",
        type=ObservationType.SERVICE,
        value="_http._tcp.local.",
    )

    assert ServiceDetector().detect([observation]) == []
