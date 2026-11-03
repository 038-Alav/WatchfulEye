from watchfuleye.application.fingerprinting_service import (
    FingerprintTarget,
    FingerprintingService,
)
from watchfuleye.domain.observation import Observation, ObservationType
from watchfuleye.enrichment.service_detector import ServiceDetector
from types import SimpleNamespace


class FakeTTL:
    def fingerprint(self, **kwargs):
        return [
            Observation(
                scan_id=kwargs["scan_id"],
                source="TTL_FINGERPRINTER",
                type=ObservationType.TTL,
                value="60",
                device_id=kwargs["device_id"],
                correlation_id=kwargs["correlation_id"],
                interface=kwargs["interface"],
            )
        ]


class FakeTCP:
    ports = (554, 80)

    def __init__(self):
        self.calls = []

    def is_open(self, ip_address, port, timeout_seconds, source_ip=None):
        self.calls.append((ip_address, port, source_ip))
        return port == 554


class FakeInterfaceResolver:
    def resolve(self, interface_name, network_cidr):
        return SimpleNamespace(ip="192.168.100.1")


def test_fingerprinting_service_scans_only_targets_inside_selected_network():
    tcp_probe = FakeTCP()
    service = FingerprintingService(
        ttl_fingerprinter=FakeTTL(),
        tcp_probe=tcp_probe,
        service_detector=ServiceDetector(),
        interface_resolver=FakeInterfaceResolver(),
        max_workers=4,
    )

    results = service.run(
        [
            FingerprintTarget("device-1", "192.168.100.20", "Wi-Fi"),
            FingerprintTarget("device-2", "192.168.101.20", "Wi-Fi"),
        ],
        network_cidr="192.168.100.0/24",
        scan_id="scan-1",
        timeout_seconds=2,
    )

    assert {item.device_id for item in results} == {"device-1"}
    assert any(item.type == ObservationType.TTL for item in results)
    assert any(item.type == ObservationType.PORT and item.value == "tcp/554" for item in results)
    assert any(item.type == ObservationType.SERVICE and item.value == "rtsp" for item in results)
    assert tcp_probe.calls
    assert all(source_ip == "192.168.100.1" for _, _, source_ip in tcp_probe.calls)
