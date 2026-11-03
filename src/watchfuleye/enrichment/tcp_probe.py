from __future__ import annotations

import socket


class TCPProbe:
    """Perform bounded TCP connect probes against a curated port set.

    This is a lightweight service-discovery probe, not a full port scanner.
    Only a successful TCP connection is reported as an open port. Closed,
    filtered, and timed-out ports do not produce observations.
    """

    DEFAULT_PORTS = (
        22, 23, 53, 80, 139, 443, 445, 515, 554, 631,
        1883, 1433, 179, 2601, 2604, 3306, 3389, 5432,
        62078, 7000, 8008, 8009, 8080, 8291, 8443, 8883,
        9100, 9200, 27017, 37777, 4786, 6379,
    )

    def __init__(self, ports: tuple[int, ...] | list[int] | None = None):
        selected = self.DEFAULT_PORTS if ports is None else tuple(ports)
        normalized = []
        for port in selected:
            if isinstance(port, bool) or not isinstance(port, int):
                raise TypeError("TCP probe ports must be integers.")
            if not 1 <= port <= 65535:
                raise ValueError(f"Invalid TCP port: {port}")
            if port not in normalized:
                normalized.append(port)
        self.ports = tuple(normalized)

    @staticmethod
    def is_open(
        ip_address: str,
        port: int,
        timeout_seconds: float = 0.4,
        source_ip: str | None = None,
    ) -> bool:
        """Return True only when a TCP connection succeeds."""
        if not 0.0 < timeout_seconds <= 10.0:
            raise ValueError("TCP timeout must be greater than 0 and <= 10 seconds.")

        connection = None
        try:
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connection.settimeout(timeout_seconds)
            if source_ip:
                connection.bind((source_ip, 0))
            return connection.connect_ex((ip_address, port)) == 0
        except OSError:
            return False
        finally:
            if connection is not None:
                connection.close()
