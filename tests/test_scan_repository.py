
import pytest

from watchfuleye.domain.scan import (
    ScanRun,
    ScanStatus,
    ProviderStatus,
    ProviderExecutionResult,
)

from watchfuleye.persistence.scan_repository import (
    ScanRepository,
)


def create_scan():

    scan = ScanRun(
        network_cidr="192.168.100.0/24",
        interface_name="Ethernet",
    )

    scan.provider_results = [
        ProviderExecutionResult(
            provider="ARP",
            status=ProviderStatus.SUCCESS,
            duration_ms=125.5,
        ),
        ProviderExecutionResult(
            provider="mDNS",
            status=ProviderStatus.UNAVAILABLE,
            duration_ms=0.0,
            error="Provider is not available.",
        ),
    ]

    scan.providers_executed = ["ARP"]
    scan.errors = ["Provider is not available."]
    scan.finish(ScanStatus.PARTIAL)

    return scan


def test_add_and_get_scan(tmp_path):

    repository = ScanRepository(
        tmp_path / "scans.json"
    )

    scan = create_scan()

    repository.add(scan)

    result = repository.get_all()

    assert len(result) == 1
    assert result[0].id == scan.id
    assert result[0].network_cidr == scan.network_cidr


def test_get_by_id(tmp_path):

    repository = ScanRepository(
        tmp_path / "scans.json"
    )

    scan = create_scan()
    repository.add(scan)

    result = repository.get_by_id(scan.id)

    assert result is not None
    assert result.id == scan.id


def test_get_by_status(tmp_path):

    repository = ScanRepository(
        tmp_path / "scans.json"
    )

    successful = ScanRun(
        network_cidr="192.168.1.0/24",
        interface_name="Ethernet",
    )
    successful.finish(ScanStatus.SUCCESS)

    failed = ScanRun(
        network_cidr="192.168.2.0/24",
        interface_name="Wi-Fi",
    )
    failed.finish(ScanStatus.FAILED)

    repository.add_many([successful, failed])

    result = repository.get_by_status(
        ScanStatus.FAILED
    )

    assert len(result) == 1
    assert result[0].id == failed.id


def test_provider_results_are_preserved(tmp_path):

    repository = ScanRepository(
        tmp_path / "scans.json"
    )

    scan = create_scan()
    repository.add(scan)

    result = repository.get_by_id(scan.id)

    assert len(result.provider_results) == 2

    arp = result.provider_results[0]

    assert arp.provider == "ARP"
    assert arp.status == ProviderStatus.SUCCESS
    assert arp.duration_ms == 125.5

    mdns = result.provider_results[1]

    assert mdns.provider == "mDNS"
    assert mdns.status == ProviderStatus.UNAVAILABLE
    assert mdns.error == "Provider is not available."


def test_scan_history_survives_restart(tmp_path):

    path = tmp_path / "scans.json"

    first_repository = ScanRepository(path)

    scan = create_scan()
    first_repository.add(scan)

    second_repository = ScanRepository(path)

    result = second_repository.get_by_id(scan.id)

    assert result is not None
    assert result.status == ScanStatus.PARTIAL


def test_duplicate_scan_is_not_added_twice(tmp_path):

    repository = ScanRepository(
        tmp_path / "scans.json"
    )

    scan = create_scan()

    repository.add(scan)
    repository.add(scan)

    assert len(repository.get_all()) == 1


def test_duplicate_ids_inside_batch_are_rejected(tmp_path):

    repository = ScanRepository(
        tmp_path / "scans.json"
    )

    scan = create_scan()

    with pytest.raises(ValueError):
        repository.add_many([scan, scan])


def test_update_scan(tmp_path):

    repository = ScanRepository(
        tmp_path / "scans.json"
    )

    scan = create_scan()
    repository.add(scan)

    scan.errors = ["Updated error"]

    repository.update(scan)

    result = repository.get_by_id(scan.id)

    assert result.errors == ["Updated error"]


def test_missing_scan_raises_key_error(tmp_path):

    repository = ScanRepository(
        tmp_path / "scans.json"
    )

    scan = create_scan()

    with pytest.raises(KeyError):
        repository.update(scan)
