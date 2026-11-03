
from types import SimpleNamespace

import pytest

from watchfuleye.identity.device_identity_resolver import (
    DeviceIdentityResolver,
)


@pytest.fixture
def resolver():
    return DeviceIdentityResolver()


@pytest.fixture
def existing_device():
    return SimpleNamespace(
        id="device-001",
        ip="192.168.100.201",
        mac="fc:d9:08:dd:f4:5b",
    )


def test_exact_mac_match(resolver, existing_device):
    result = resolver.resolve(
        "fc:d9:08:dd:f4:5b",
        [existing_device],
    )

    assert result.matched_existing
    assert result.device_id == "device-001"
    assert result.matched_by == "MAC_ADDRESS"
    assert result.confidence == 0.90
    assert not result.ambiguous


def test_mac_matching_is_case_insensitive(
    resolver,
    existing_device,
):
    result = resolver.resolve(
        "FC:D9:08:DD:F4:5B",
        [existing_device],
    )

    assert result.device_id == "device-001"


@pytest.mark.parametrize(
    "mac_address",
    [
        "fc-d9-08-dd-f4-5b",
        "FCD9.08DD.F45B",
        "FCD908DDF45B",
    ],
)
def test_mac_format_normalization(
    resolver,
    existing_device,
    mac_address,
):
    result = resolver.resolve(
        mac_address,
        [existing_device],
    )

    assert result.device_id == "device-001"


def test_unknown_mac_does_not_match(
    resolver,
    existing_device,
):
    result = resolver.resolve(
        "aa:bb:cc:dd:ee:ff",
        [existing_device],
    )

    assert not result.matched_existing
    assert result.device_id is None
    assert not result.ambiguous


def test_ip_address_alone_is_insufficient(resolver):
    result = resolver.resolve(
        None,
        [
            SimpleNamespace(
                id="device-001",
                ip="192.168.100.201",
                mac=None,
            )
        ],
    )

    assert not result.matched_existing


def test_hostname_is_not_used_for_matching(resolver):
    result = resolver.resolve(
        None,
        [
            SimpleNamespace(
                id="device-001",
                ip="192.168.100.201",
                mac=None,
                hostname="DESKTOP-001",
            )
        ],
    )

    assert not result.matched_existing


def test_invalid_mac_is_rejected(
    resolver,
    existing_device,
):
    result = resolver.resolve(
        "not-a-mac-address",
        [existing_device],
    )

    assert not result.matched_existing
    assert "Invalid" in result.reason


def test_multiple_matching_devices_are_ambiguous(resolver):
    devices = [
        SimpleNamespace(
            id="device-001",
            mac="aa:bb:cc:dd:ee:ff",
        ),
        SimpleNamespace(
            id="device-002",
            mac="AA-BB-CC-DD-EE-FF",
        ),
    ]

    result = resolver.resolve(
        "aa:bb:cc:dd:ee:ff",
        devices,
    )

    assert result.device_id is None
    assert result.ambiguous
    assert not result.matched_existing


def test_empty_device_inventory_returns_no_match(resolver):
    result = resolver.resolve(
        "aa:bb:cc:dd:ee:ff",
        [],
    )

    assert not result.matched_existing


def test_invalid_mac_format_normalizes_to_none(resolver):
    assert resolver.normalize_mac("invalid") is None
    assert resolver.normalize_mac(None) is None
    assert resolver.normalize_mac("aa:bb:cc") is None
