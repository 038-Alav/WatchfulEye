import re
from dataclasses import dataclass
from typing import Iterable

from watchfuleye.domain.device import Device


@dataclass(frozen=True)
class IdentityResolution:
    """
    Describes whether identity evidence matches an existing device.

    This class does not create, update, or persist devices.
    """

    device_id: str | None
    confidence: float
    matched_by: str | None = None
    ambiguous: bool = False
    reason: str = ""

    @property
    def matched_existing(self) -> bool:
        return self.device_id is not None


class DeviceIdentityResolver:
    """
    Resolves discovered identity evidence against known devices.

    Current matching strategy:
    - Exact normalized MAC address.

    IP addresses and hostnames are deliberately not used as
    permanent identity keys.
    """

    MATCH_CONFIDENCE = 0.90

    @staticmethod
    def normalize_mac(mac_address: str | None) -> str | None:
        """
        Normalize common MAC address representations.

        Supported examples:
        AA:BB:CC:DD:EE:FF
        aa-bb-cc-dd-ee-ff
        AABB.CCDD.EEFF
        AABBCCDDEEFF
        """

        if not isinstance(mac_address, str):
            return None

        compact = re.sub(
            r"[:.\-\s]",
            "",
            mac_address.strip(),
        )

        if not re.fullmatch(r"[0-9a-fA-F]{12}", compact):
            return None

        compact = compact.lower()

        return ":".join(
            compact[index:index + 2]
            for index in range(0, 12, 2)
        )

    def resolve(
        self,
        mac_address: str | None,
        devices: Iterable[Device],
    ) -> IdentityResolution:
        """
        Find an existing device using MAC address evidence.

        Returns an unmatched resolution when evidence is missing,
        invalid, unknown, or ambiguous.
        """

        normalized_mac = self.normalize_mac(mac_address)

        if mac_address is None or not str(mac_address).strip():
            return IdentityResolution(
                device_id=None,
                confidence=0.0,
                reason="No MAC address evidence available.",
            )

        if normalized_mac is None:
            return IdentityResolution(
                device_id=None,
                confidence=0.0,
                reason="Invalid MAC address.",
            )

        matches = [
            device
            for device in devices
            if self.normalize_mac(device.mac) == normalized_mac
        ]

        if len(matches) == 1:
            return IdentityResolution(
                device_id=matches[0].id,
                confidence=self.MATCH_CONFIDENCE,
                matched_by="MAC_ADDRESS",
                reason="Exact normalized MAC address match.",
            )

        if len(matches) > 1:
            return IdentityResolution(
                device_id=None,
                confidence=0.0,
                ambiguous=True,
                reason=(
                    "Multiple devices share the same MAC address. "
                    "Identity resolution is ambiguous."
                ),
            )

        return IdentityResolution(
            device_id=None,
            confidence=0.0,
            reason="No existing device matches this MAC address.",
        )
