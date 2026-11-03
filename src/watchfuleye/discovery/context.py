from dataclasses import dataclass


@dataclass(frozen=True)
class DiscoveryContext:
    """
    Immutable configuration for a discovery execution.

    Shared with all providers participating in the scan.
    """

    network_cidr: str

    interface_name: str

    scan_id: str

    timeout_seconds: int = 2

    def __post_init__(self):
        if not self.network_cidr:
            raise ValueError("Network CIDR cannot be empty.")

        if not self.interface_name:
            raise ValueError("Interface name cannot be empty.")

        if not self.scan_id:
            raise ValueError("Scan ID cannot be empty.")

        if self.timeout_seconds <= 0:
            raise ValueError("Timeout must be greater than zero.")
