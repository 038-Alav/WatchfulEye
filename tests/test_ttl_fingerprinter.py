from watchfuleye.domain.observation import ObservationType
from watchfuleye.enrichment.ttl_fingerprinter import TTLFingerprinter


def test_ttl_fingerprint_creates_ttl_and_cautious_os_hint():
    fingerprinter = TTLFingerprinter(sender=lambda ip, timeout: 61)

    observations = fingerprinter.fingerprint(
        ip_address="192.168.100.20",
        scan_id="scan-1",
        device_id="device-1",
        interface="Wi-Fi",
        timeout_seconds=1.0,
        correlation_id="fingerprint-1",
    )

    assert [item.type for item in observations] == [
        ObservationType.TTL,
        ObservationType.OPERATING_SYSTEM,
    ]
    assert observations[0].value == "61"
    assert observations[1].value == "Linux / Unix-like (TTL heuristic)"
    assert all(item.device_id == "device-1" for item in observations)
    assert all(item.scan_id == "scan-1" for item in observations)


def test_ttl_fingerprint_returns_nothing_when_no_reply():
    fingerprinter = TTLFingerprinter(sender=lambda ip, timeout: None)

    observations = fingerprinter.fingerprint(
        ip_address="192.168.100.20",
        scan_id="scan-1",
        device_id="device-1",
        interface="Wi-Fi",
        timeout_seconds=1.0,
        correlation_id="fingerprint-1",
    )

    assert observations == []


def test_ttl_fingerprint_rejects_invalid_ttl():
    fingerprinter = TTLFingerprinter(sender=lambda ip, timeout: 300)

    observations = fingerprinter.fingerprint(
        ip_address="192.168.100.20",
        scan_id="scan-1",
        device_id="device-1",
        interface="Wi-Fi",
        timeout_seconds=1.0,
        correlation_id="fingerprint-1",
    )

    assert observations == []
