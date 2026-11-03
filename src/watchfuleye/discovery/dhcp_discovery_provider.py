from __future__ import annotations

import importlib.util
import logging
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from watchfuleye.discovery.base import DiscoveryProvider
from watchfuleye.discovery.context import DiscoveryContext
from watchfuleye.domain.observation import Observation, ObservationType


logger = logging.getLogger(__name__)

# These values are provisional. They describe the strength of a DHCP claim,
# not a globally calibrated comparison against mDNS, NetBIOS or reverse DNS.
_HOSTNAME_OPTION_CONFIDENCE = 0.90
_CLIENT_FQDN_OPTION_CONFIDENCE = 0.95

# AsyncSniffer invokes started_callback after Scapy has opened its capture
# socket. This timeout lets us distinguish an actual startup failure from a
# listener that has merely started its Python thread.
_DEFAULT_STARTUP_TIMEOUT_SECONDS = 8.0

_DHCP_MESSAGE_NAMES = {
    "discover": 1,
    "dhcpdiscover": 1,
    "offer": 2,
    "dhcpoffer": 2,
    "request": 3,
    "dhcprequest": 3,
    "decline": 4,
    "dhcpdecline": 4,
    "ack": 5,
    "dhcpack": 5,
    "nak": 6,
    "dhcpnak": 6,
    "release": 7,
    "dhcprelease": 7,
    "inform": 8,
    "dhcpinform": 8,
}


@dataclass(frozen=True)
class _CapturedDhcpEvent:
    """A DHCP packet containing at least one decoded naming value."""

    captured_at: datetime
    interface_name: str
    correlation_id: str
    mac_address: str | None
    ip_address: str | None
    names: tuple[tuple[str, str, float], ...]


@dataclass(frozen=True)
class _PacketInspection:
    """Capture-side facts about one packet delivered by the BPF filter."""

    is_dhcp: bool
    hostname_option_present: bool = False
    fqdn_option_present: bool = False
    hostname_values_extracted: int = 0
    fqdn_values_extracted: int = 0
    event: _CapturedDhcpEvent | None = None


@dataclass(frozen=True)
class DhcpCaptureStats:
    """Immutable snapshot of the passive DHCP listener's health and yield."""

    status: str
    interface_name: str | None
    capture_backend: str | None
    capture_started_at: datetime | None
    last_capture_error: str | None
    packets_received: int  # packets delivered by the capture filter
    dhcp_packets_received: int
    hostname_option_packets: int
    fqdn_option_packets: int
    hostname_values_extracted: int
    fqdn_values_extracted: int
    dhcp_packets_without_names: int
    observations_generated: int
    parse_errors: int
    capture_errors: int
    buffered_events: int
    dropped_events: int
    last_packet_at: datetime | None
    last_dhcp_packet_at: datetime | None
    last_hostname_at: datetime | None


class DhcpDiscoveryProvider(DiscoveryProvider):
    """Passively capture DHCPv4 naming evidence in the background.

    The first ``discover(context)`` starts an asynchronous Scapy capture on
    the selected interface. Capture continues between scans. Each subsequent
    call drains naming events into ordinary Observation objects.

    ``capture_status`` and ``stats`` distinguish a running listener with no
    filter-matched packets, packets without DHCP, DHCP without names, successful
    name capture, and a failed capture backend. Packet counts refer to packets
    delivered by the configured BPF filter, not all traffic on the interface.

    This provider does not request or renew leases, query router APIs, mutate
    devices, or persist information.
    """

    name = "DHCP"
    capture_filter = "udp and (port 67 or port 68)"

    def __init__(
        self,
        max_buffer_size: int = 5000,
        startup_timeout_seconds: float = _DEFAULT_STARTUP_TIMEOUT_SECONDS,
    ):
        if max_buffer_size < 1:
            raise ValueError("max_buffer_size must be greater than zero.")
        if startup_timeout_seconds <= 0:
            raise ValueError("startup_timeout_seconds must be greater than zero.")

        self._events: deque[_CapturedDhcpEvent] = deque(maxlen=max_buffer_size)
        self._events_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self._lifecycle_lock = threading.RLock()

        self._max_buffer_size = max_buffer_size
        self._startup_timeout_seconds = startup_timeout_seconds
        self._sniffer: Any = None
        self._started_event: threading.Event | None = None
        self._capture_interface_name: str | None = None
        self._capture_error: str | None = None
        self._last_capture_error: str | None = None
        self._capture_backend: str | None = None
        self._capture_started_at: datetime | None = None
        self._availability_error: str | None = None
        self._dropped_event_count = 0

        self._metrics = {
            "packets_received": 0,
            "dhcp_packets_received": 0,
            "hostname_option_packets": 0,
            "fqdn_option_packets": 0,
            "hostname_values_extracted": 0,
            "fqdn_values_extracted": 0,
            "dhcp_packets_without_names": 0,
            "observations_generated": 0,
            "parse_errors": 0,
            "capture_errors": 0,
            "dropped_events": 0,
        }
        self._last_packet_at: datetime | None = None
        self._last_dhcp_packet_at: datetime | None = None
        self._last_hostname_at: datetime | None = None

    # ------------------------------------------------------------------
    # Availability and status
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Check capture prerequisites without claiming capture is active.

        Scapy/Npcap availability cannot be conclusively established until the
        selected interface's capture socket is opened in ``_ensure_capture``.
        The coordinator can inspect ``availability_error`` for diagnostics.
        """
        self._availability_error = None
        try:
            if importlib.util.find_spec("scapy") is None:
                raise RuntimeError("Scapy is not installed in this environment.")

            from scapy.all import AsyncSniffer, conf

            if not callable(AsyncSniffer):
                raise RuntimeError("Scapy AsyncSniffer is unavailable.")
            if not callable(getattr(conf, "L2listen", None)):
                raise RuntimeError(
                    "Scapy has no Layer-2 capture backend configured. "
                    "On Windows, install or repair Npcap."
                )
            return True
        except (ImportError, ModuleNotFoundError, OSError, ValueError, RuntimeError) as exc:
            self._availability_error = f"{type(exc).__name__}: {exc}"
            logger.error("DHCP capture prerequisites unavailable: %s", self._availability_error)
            return False

    @property
    def availability_error(self) -> str | None:
        """Explain why the basic capture prerequisites are unavailable."""
        return self._availability_error

    @property
    def is_listening(self) -> bool:
        return self.capture_status.startswith("LISTENING_")

    @property
    def listening_interface(self) -> str | None:
        with self._lifecycle_lock:
            return self._capture_interface_name

    @property
    def dropped_event_count(self) -> int:
        """Total buffered events discarded because the bounded queue filled."""
        with self._stats_lock:
            return self._metrics["dropped_events"]

    @property
    def capture_error(self) -> str | None:
        self._refresh_async_capture_error()
        with self._lifecycle_lock:
            return self._capture_error

    @property
    def last_capture_error(self) -> str | None:
        """Most recent capture startup/runtime error, retained after stop."""
        with self._lifecycle_lock:
            return self._last_capture_error

    @property
    def capture_status(self) -> str:
        """Return the current capture state, including no-data states."""
        self._refresh_async_capture_error()

        with self._lifecycle_lock:
            sniffer = self._sniffer
            started_event = self._started_event
            error = self._capture_error
            availability_error = self._availability_error

        if error is not None or availability_error is not None:
            return "FAILED"
        if sniffer is None:
            return "STOPPED"
        if started_event is None or not started_event.is_set():
            return "STARTING"
        if not bool(getattr(sniffer, "running", False)):
            return "FAILED"

        with self._stats_lock:
            packets = self._metrics["packets_received"]
            dhcp_packets = self._metrics["dhcp_packets_received"]
            names = (
                self._metrics["hostname_values_extracted"]
                + self._metrics["fqdn_values_extracted"]
            )

        if packets == 0:
            return "LISTENING_NO_PACKETS"
        if dhcp_packets == 0:
            return "LISTENING_NO_DHCP"
        if names == 0:
            return "LISTENING_DHCP_NO_NAMES"
        return "LISTENING_WITH_HOSTNAMES"

    @property
    def stats(self) -> DhcpCaptureStats:
        """Return a consistent-enough, immutable snapshot for logs or UI."""
        status = self.capture_status
        with self._lifecycle_lock:
            interface_name = self._capture_interface_name
            capture_backend = self._capture_backend
            capture_started_at = self._capture_started_at
            last_capture_error = (
                self._last_capture_error or self._capture_error or self._availability_error
            )
        with self._stats_lock:
            metrics = dict(self._metrics)
            last_packet_at = self._last_packet_at
            last_dhcp_packet_at = self._last_dhcp_packet_at
            last_hostname_at = self._last_hostname_at
        with self._events_lock:
            buffered_events = len(self._events)
            dropped_events = metrics["dropped_events"]

        return DhcpCaptureStats(
            status=status,
            interface_name=interface_name,
            capture_backend=capture_backend,
            capture_started_at=capture_started_at,
            last_capture_error=last_capture_error,
            packets_received=metrics["packets_received"],
            dhcp_packets_received=metrics["dhcp_packets_received"],
            hostname_option_packets=metrics["hostname_option_packets"],
            fqdn_option_packets=metrics["fqdn_option_packets"],
            hostname_values_extracted=metrics["hostname_values_extracted"],
            fqdn_values_extracted=metrics["fqdn_values_extracted"],
            dhcp_packets_without_names=metrics["dhcp_packets_without_names"],
            observations_generated=metrics["observations_generated"],
            parse_errors=metrics["parse_errors"],
            capture_errors=metrics["capture_errors"],
            buffered_events=buffered_events,
            dropped_events=dropped_events,
            last_packet_at=last_packet_at,
            last_dhcp_packet_at=last_dhcp_packet_at,
            last_hostname_at=last_hostname_at,
        )

    def _increment_metrics(self, **increments: int) -> None:
        with self._stats_lock:
            for name, amount in increments.items():
                self._metrics[name] += amount

    def _record_capture_error(self, exc: BaseException) -> None:
        message = f"{type(exc).__name__}: {exc}"
        with self._lifecycle_lock:
            if self._capture_error is None:
                self._capture_error = message
                self._last_capture_error = message
                self._increment_metrics(capture_errors=1)

    def _refresh_async_capture_error(self) -> None:
        with self._lifecycle_lock:
            sniffer = self._sniffer
            current_error = self._capture_error
        if sniffer is None or current_error is not None:
            return

        error = getattr(sniffer, "exception", None)
        if error is not None:
            self._record_capture_error(error)
            return

        with self._lifecycle_lock:
            started_event = self._started_event
        if (
            started_event is not None
            and started_event.is_set()
            and not bool(getattr(sniffer, "running", False))
        ):
            self._record_capture_error(
                RuntimeError("Scapy capture thread stopped unexpectedly.")
            )

    # ------------------------------------------------------------------
    # Listener lifecycle
    # ------------------------------------------------------------------

    def start(self, interface_name: str) -> None:
        """Start or move the listener to ``interface_name`` and verify startup."""
        if not interface_name or not interface_name.strip():
            raise ValueError("A network interface name is required.")
        self._ensure_capture(interface_name.strip())

    def stop(self) -> None:
        """Stop capture cleanly while retaining queued events and counters."""
        with self._lifecycle_lock:
            sniffer = self._sniffer

        if sniffer is not None and bool(getattr(sniffer, "running", False)):
            try:
                sniffer.stop(join=True)
            except Exception as exc:
                # Scapy can report that a sniffer already stopped between the
                # running check and stop(). Preserve this as diagnostic data.
                logger.debug("DHCP sniffer stop returned an error: %s", exc)

        with self._lifecycle_lock:
            if self._sniffer is sniffer:
                self._sniffer = None
                self._started_event = None
                self._capture_interface_name = None
                self._capture_error = None
                self._capture_backend = None
                self._capture_started_at = None

    close = stop

    def _ensure_capture(self, interface_name: str) -> None:
        with self._lifecycle_lock:
            current = self._sniffer
            same_interface = self._capture_interface_name == interface_name
            started = self._started_event
            healthy = (
                current is not None
                and same_interface
                and started is not None
                and started.is_set()
                and bool(getattr(current, "running", False))
                and self._capture_error is None
            )
            if healthy:
                return

        # Stop/release any previous listener before changing interfaces or
        # restarting a failed capture.
        self.stop()

        # Retain the requested interface in diagnostics even when resolving
        # the Scapy device or opening Npcap fails.
        with self._lifecycle_lock:
            self._capture_interface_name = interface_name

        try:
            from scapy.all import AsyncSniffer, conf

            interface = conf.ifaces.dev_from_name(interface_name)
            if interface is None:
                raise RuntimeError(f"Scapy interface not found: {interface_name}")

            listen_backend = getattr(conf, "L2listen", None)
            if not callable(listen_backend):
                raise RuntimeError(
                    "Scapy has no Layer-2 capture backend configured. "
                    "On Windows, install or repair Npcap."
                )
            backend_name = getattr(listen_backend, "__name__", type(listen_backend).__name__)

            started_event = threading.Event()
            sniffer = AsyncSniffer(
                iface=interface,
                filter=self.capture_filter,
                store=False,
                prn=lambda packet: self._handle_packet(packet, interface_name),
                promisc=True,
                started_callback=started_event.set,
            )

            with self._lifecycle_lock:
                self._capture_error = None
                self._capture_interface_name = interface_name
                self._capture_backend = backend_name
                self._capture_started_at = None
                self._started_event = started_event
                self._sniffer = sniffer

            sniffer.start()

            if not started_event.wait(self._startup_timeout_seconds):
                async_error = getattr(sniffer, "exception", None)
                if async_error is None:
                    async_error = TimeoutError(
                        "Scapy did not confirm that the capture socket opened "
                        f"within {self._startup_timeout_seconds:.1f} seconds."
                    )
                self._record_capture_error(async_error)
                if bool(getattr(sniffer, "running", False)):
                    try:
                        sniffer.stop(join=True)
                    except Exception:
                        logger.debug("Could not stop failed DHCP sniffer.", exc_info=True)
                raise RuntimeError(
                    f"DHCP capture could not start on {interface_name}: "
                    f"{self.capture_error}"
                ) from async_error

            async_error = getattr(sniffer, "exception", None)
            if async_error is not None:
                self._record_capture_error(async_error)
                raise RuntimeError(
                    f"DHCP capture failed on {interface_name}: {self.capture_error}"
                ) from async_error

            if not bool(getattr(sniffer, "running", False)):
                error = RuntimeError(
                    "Scapy reported capture startup, but the sniffer is not running."
                )
                self._record_capture_error(error)
                raise RuntimeError(
                    f"DHCP capture failed on {interface_name}: {self.capture_error}"
                ) from error

            with self._lifecycle_lock:
                self._capture_started_at = datetime.now(timezone.utc)

            logger.info(
                "DHCP capture started | interface=%s | backend=%s | "
                "status=%s | filter=%s",
                interface_name,
                backend_name,
                self.capture_status,
                self.capture_filter,
            )

        except Exception as exc:
            self._record_capture_error(exc)
            logger.exception(
                "DHCP capture startup failed | interface=%s",
                interface_name,
            )
            raise RuntimeError(
                f"DHCP capture startup failed on {interface_name}: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Provider execution and packet accounting
    # ------------------------------------------------------------------

    def discover(self, context: DiscoveryContext) -> list[Observation]:
        """Maintain passive capture and return observations buffered so far."""
        self._ensure_capture(context.interface_name)

        with self._events_lock:
            events = list(self._events)
            self._events.clear()
            dropped_events = self._dropped_event_count
            self._dropped_event_count = 0

        observations: list[Observation] = []
        for event in events:
            observations.extend(self._event_to_observations(event, context.scan_id))

        if observations:
            self._increment_metrics(observations_generated=len(observations))

        if dropped_events:
            logger.warning(
                "DHCP passive buffer overflow | dropped_events=%d | interface=%s",
                dropped_events,
                context.interface_name,
            )

        snapshot = self.stats
        logger.info(
            "DHCP capture diagnostics | interface=%s | backend=%s | status=%s | "
            "packets=%d | dhcp_packets=%d | option12_packets=%d | "
            "option81_packets=%d | option12_values=%d | option81_values=%d | "
            "dhcp_without_names=%d | buffered=%d | observations_this_scan=%d | "
            "observations_total=%d | parse_errors=%d | capture_errors=%d | "
            "dropped_events=%d | last_capture_error=%s",
            context.interface_name,
            snapshot.capture_backend,
            snapshot.status,
            snapshot.packets_received,
            snapshot.dhcp_packets_received,
            snapshot.hostname_option_packets,
            snapshot.fqdn_option_packets,
            snapshot.hostname_values_extracted,
            snapshot.fqdn_values_extracted,
            snapshot.dhcp_packets_without_names,
            snapshot.buffered_events,
            len(observations),
            snapshot.observations_generated,
            snapshot.parse_errors,
            snapshot.capture_errors,
            snapshot.dropped_events,
            snapshot.last_capture_error,
        )
        return observations

    def _handle_packet(self, packet: Any, interface_name: str) -> None:
        now = datetime.now(timezone.utc)
        with self._stats_lock:
            self._metrics["packets_received"] += 1
            self._last_packet_at = now

        try:
            inspection = self._inspect_packet(packet, interface_name, captured_at=now)
        except Exception:
            self._increment_metrics(parse_errors=1)
            logger.debug(
                "DHCP packet parsing failed | interface=%s",
                interface_name,
                exc_info=True,
            )
            return

        if not inspection.is_dhcp:
            return

        increments = {"dhcp_packets_received": 1}
        if inspection.hostname_option_present:
            increments["hostname_option_packets"] = 1
        if inspection.fqdn_option_present:
            increments["fqdn_option_packets"] = 1
        if inspection.hostname_values_extracted:
            increments["hostname_values_extracted"] = inspection.hostname_values_extracted
        if inspection.fqdn_values_extracted:
            increments["fqdn_values_extracted"] = inspection.fqdn_values_extracted
        if inspection.event is None:
            increments["dhcp_packets_without_names"] = 1
        self._increment_metrics(**increments)

        with self._stats_lock:
            self._last_dhcp_packet_at = now
            if inspection.hostname_values_extracted or inspection.fqdn_values_extracted:
                self._last_hostname_at = now

        if inspection.event is None:
            return

        was_full = False
        with self._events_lock:
            if len(self._events) == self._max_buffer_size:
                self._dropped_event_count += 1
                was_full = True
            self._events.append(inspection.event)
        if was_full:
            self._increment_metrics(dropped_events=1)

    # ------------------------------------------------------------------
    # DHCP packet parsing
    # ------------------------------------------------------------------

    @classmethod
    def _inspect_packet(
        cls,
        packet: Any,
        interface_name: str,
        captured_at: datetime | None = None,
    ) -> _PacketInspection:
        """Inspect a packet and report DHCP/name counters plus an optional event."""
        try:
            from scapy.layers.dhcp import BOOTP, DHCP
        except ImportError:
            from scapy.all import BOOTP, DHCP

        if not packet.haslayer(BOOTP) or not packet.haslayer(DHCP):
            return _PacketInspection(is_dhcp=False)

        bootp = packet[BOOTP]
        dhcp = packet[DHCP]
        options = getattr(dhcp, "options", ()) or ()

        message_type = cls._read_message_type(options)
        hostname_option = cls._read_option(options, {"hostname", "host_name"}, 12)
        fqdn_option = cls._read_option(
            options,
            {"client_fqdn", "clientfqdn", "fqdn"},
            81,
        )

        hostname_present = hostname_option is not None
        fqdn_present = fqdn_option is not None

        # Preserve naming evidence from any DHCP message type. Some clients
        # include useful names in RELEASE/DECLINE messages as well. Unknown
        # message types are labelled UNKNOWN rather than assumed to be client
        # traffic.
        names: list[tuple[str, str, float]] = []
        if message_type in {2, 5, 6}:
            message_origin = "SERVER"
        elif message_type in {1, 3, 4, 7, 8}:
            message_origin = "CLIENT"
        else:
            message_origin = "UNKNOWN"

        for raw_value in cls._option_values(hostname_option):
            hostname = cls._decode_hostname(raw_value)
            if hostname:
                names.append((
                    f"DHCP_{message_origin}_OPTION_12",
                    hostname,
                    _HOSTNAME_OPTION_CONFIDENCE,
                ))

        for raw_value in cls._option_values(fqdn_option):
            fqdn = cls._decode_client_fqdn(raw_value)
            if fqdn:
                names.append((
                    f"DHCP_{message_origin}_OPTION_81",
                    fqdn,
                    _CLIENT_FQDN_OPTION_CONFIDENCE,
                ))

        names = list(dict.fromkeys(names))
        hostname_count = sum(1 for source, _, _ in names if source.endswith("OPTION_12"))
        fqdn_count = sum(1 for source, _, _ in names if source.endswith("OPTION_81"))

        if not names:
            return _PacketInspection(
                is_dhcp=True,
                hostname_option_present=hostname_present,
                fqdn_option_present=fqdn_present,
            )

        mac_address = cls._decode_client_mac(
            getattr(bootp, "chaddr", None),
            hardware_type=getattr(bootp, "htype", None),
            hardware_length=getattr(bootp, "hlen", None),
        )
        ip_address = cls._decode_client_ip(bootp, message_type)

        event = _CapturedDhcpEvent(
            captured_at=captured_at or datetime.now(timezone.utc),
            interface_name=interface_name,
            correlation_id=str(uuid4()),
            mac_address=mac_address,
            ip_address=ip_address,
            names=tuple(names),
        )

        return _PacketInspection(
            is_dhcp=True,
            hostname_option_present=hostname_present,
            fqdn_option_present=fqdn_present,
            hostname_values_extracted=hostname_count,
            fqdn_values_extracted=fqdn_count,
            event=event,
        )

    @classmethod
    def _parse_packet(
        cls,
        packet: Any,
        interface_name: str,
        captured_at: datetime | None = None,
    ) -> _CapturedDhcpEvent | None:
        """Compatibility helper used by parser-focused tests."""
        return cls._inspect_packet(packet, interface_name, captured_at).event

    @staticmethod
    def _read_option(
        options: Any,
        accepted_names: set[str],
        option_number: int,
    ) -> Any:
        values = []
        for item in options:
            if not isinstance(item, (tuple, list)) or len(item) < 2:
                continue
            key, value = item[0], item[1]
            if isinstance(key, int) and key == option_number:
                values.append(value)
                continue
            if isinstance(key, bytes):
                key = key.decode("ascii", errors="ignore")
            if isinstance(key, str):
                normalized = key.strip().lower().replace("-", "_").replace(" ", "_")
                if normalized in accepted_names:
                    values.append(value)
        if not values:
            return None
        # Preserve repeated raw fragments for option 81 concatenation.
        if len(values) > 1 and all(isinstance(value, (bytes, bytearray)) for value in values):
            return b"".join(bytes(value) for value in values)
        return values if len(values) > 1 else values[0]

    @staticmethod
    def _option_values(value: Any) -> tuple[Any, ...]:
        if value is None:
            return ()
        if isinstance(value, list):
            return tuple(value)
        return (value,)

    @staticmethod
    def _read_message_type(options: Any) -> int | None:
        for item in options:
            if not isinstance(item, (tuple, list)) or len(item) < 2:
                continue
            key, value = item[0], item[1]
            if isinstance(key, bytes):
                key = key.decode("ascii", errors="ignore")
            if isinstance(key, str):
                normalized = key.strip().lower().replace("_", "-")
                if normalized not in {"message-type", "messagetype", "dhcp-message-type"}:
                    continue
            elif key != 53:
                continue

            if isinstance(value, int):
                return value
            if isinstance(value, (bytes, bytearray)) and value:
                return int(value[0])
            if isinstance(value, str):
                return _DHCP_MESSAGE_NAMES.get(value.strip().lower())
        return None

    @staticmethod
    def _decode_hostname(value: Any) -> str | None:
        if isinstance(value, (tuple, list)) and len(value) == 1:
            value = value[0]
        if isinstance(value, bytes):
            try:
                text = value.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                return None
        elif isinstance(value, str):
            text = value
        else:
            return None
        return DhcpDiscoveryProvider._clean_name(text)

    @classmethod
    def _decode_client_fqdn(cls, value: Any) -> str | None:
        if isinstance(value, (tuple, list)):
            # Some dissectors expose (flags, rcode1, rcode2, domain-name).
            if len(value) >= 4 and all(isinstance(part, int) for part in value[:3]):
                value = bytes(value[:3]) + cls._as_bytes(value[3])
            elif len(value) == 1:
                value = value[0]
            else:
                return None

        if isinstance(value, str):
            return cls._clean_name(value)
        if not isinstance(value, (bytes, bytearray)):
            return None

        raw = bytes(value)
        if len(raw) < 3:
            return None

        flags = raw[0]
        domain_data = raw[3:]  # flags, RCODE1 and RCODE2 precede the name
        if not domain_data:
            return None

        # RFC 4702: E=1 indicates DNS wire-format labels; E=0 indicates ASCII.
        if flags & 0x04:
            decoded = cls._decode_dns_wire_name(domain_data)
        else:
            decoded = domain_data.decode("ascii", errors="replace").rstrip("\x00")
        return cls._clean_name(decoded) if decoded else None

    @staticmethod
    def _decode_dns_wire_name(data: bytes) -> str | None:
        labels: list[str] = []
        offset = 0

        while offset < len(data):
            length = data[offset]
            offset += 1
            if length == 0:
                break
            if length & 0xC0 or length > 63 or offset + length > len(data):
                return None
            label = data[offset:offset + length]
            offset += length
            try:
                labels.append(label.decode("ascii"))
            except UnicodeDecodeError:
                return None

        return ".".join(labels) if labels else None

    @staticmethod
    def _clean_name(value: str | None) -> str | None:
        if not value:
            return None
        cleaned = value.strip().strip("\x00").rstrip(".")
        if not cleaned or len(cleaned) > 255:
            return None
        if any(ord(character) < 32 or ord(character) == 127 for character in cleaned):
            return None
        return cleaned

    @staticmethod
    def _as_bytes(value: Any) -> bytes:
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, str):
            return value.encode("ascii", errors="replace")
        if isinstance(value, int):
            return bytes([value])
        return b""

    @staticmethod
    def _decode_client_mac(
        value: Any,
        hardware_type: int | None = None,
        hardware_length: int | None = None,
    ) -> str | None:
        # Ethernet hardware addresses are six bytes. Do not misinterpret a
        # non-Ethernet BOOTP chaddr as a MAC address.
        if hardware_type not in (None, 1):
            return None
        if hardware_length not in (None, 6):
            return None

        if isinstance(value, str):
            compact = value.replace(":", "").replace("-", "").replace(".", "")
            if len(compact) < 12:
                return None
            try:
                raw = bytes.fromhex(compact[:12])
            except ValueError:
                return None
        elif isinstance(value, (bytes, bytearray)):
            raw = bytes(value[:6])
        else:
            return None

        if len(raw) != 6 or raw == b"\x00" * 6 or raw == b"\xff" * 6:
            return None
        return ":".join(f"{byte:02x}" for byte in raw)

    @staticmethod
    def _decode_client_ip(bootp: Any, message_type: int | None) -> str | None:
        """Return only an address evidenced as current/assigned, not requested.

        Option 50 is intentionally ignored: a requested IP is not proof of an
        assignment. A DHCPACK yiaddr or client ciaddr during renewal/INFORM is
        usable evidence.
        """
        import ipaddress

        candidates = []
        if message_type == 5:
            candidates.append(getattr(bootp, "yiaddr", None))
        if message_type in {3, 5, 8}:
            candidates.append(getattr(bootp, "ciaddr", None))

        for candidate in candidates:
            if not candidate or candidate == "0.0.0.0":
                continue
            try:
                parsed = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if parsed.version == 4 and not parsed.is_unspecified:
                return str(parsed)
        return None

    @staticmethod
    def _event_to_observations(
        event: _CapturedDhcpEvent,
        scan_id: str,
    ) -> list[Observation]:
        observations: list[Observation] = []

        if event.mac_address:
            observations.append(Observation(
                scan_id=scan_id,
                source="DHCP",
                type=ObservationType.MAC_ADDRESS,
                value=event.mac_address,
                confidence=1.0,
                timestamp=event.captured_at,
                interface=event.interface_name,
                correlation_id=event.correlation_id,
            ))

        if event.ip_address:
            observations.append(Observation(
                scan_id=scan_id,
                source="DHCP",
                type=ObservationType.IP_ADDRESS,
                value=event.ip_address,
                confidence=0.95,
                timestamp=event.captured_at,
                interface=event.interface_name,
                correlation_id=event.correlation_id,
            ))

        for source, hostname, confidence in event.names:
            observations.append(Observation(
                scan_id=scan_id,
                source=source,
                type=ObservationType.HOSTNAME,
                value=hostname,
                confidence=confidence,
                timestamp=event.captured_at,
                interface=event.interface_name,
                correlation_id=event.correlation_id,
            ))

        return observations
