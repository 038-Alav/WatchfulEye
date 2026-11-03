from dataclasses import dataclass


@dataclass(frozen=True)
class NetworkInterface:
    """System-level IPv4 interface information used by Watchful Eye."""

    name: str
    display_name: str
    ip: str
    netmask: str
    cidr: str
    mac_address: str | None = None
    interface_index: int | None = None


def get_ipv4_interfaces() -> list[NetworkInterface]:
    """Return active IPv4 interfaces (compatibility entry point).

    Existing GUI code can continue calling ``get_ipv4_interfaces``. The
    implementation is delegated to NetworkInterfaceResolver so interface
    enumeration has one source of truth.
    """
    from watchfuleye.network.interface_resolver import (
        NetworkInterfaceResolver,
    )

    return NetworkInterfaceResolver().get_ipv4_interfaces()
