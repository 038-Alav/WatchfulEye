import re
from importlib.resources import files
from pathlib import Path

from watchfuleye.domain.observation import Observation, ObservationType
from watchfuleye.identity.device_identity_resolver import DeviceIdentityResolver


class OUIResolver:
    """
    Resolves MAC addresses to manufacturers using the local IEEE registry.

    Supports:
        MA-L: 24-bit prefixes (6 hexadecimal characters)
        MA-M: 28-bit prefixes (7 hexadecimal characters)
        MA-S: 36-bit prefixes (9 hexadecimal characters)

    The bundled registry is used by default. A custom path can be
    provided for testing or alternative registry files.
    """

    REGISTRY_PATTERN = re.compile(
        r"^\s*([0-9A-Fa-f-]+)\s+\((?:hex|base 16)\)\s+(.+?)\s*$",
        re.IGNORECASE,
    )

    VALID_PREFIX_LENGTHS = {6, 7, 9}

    def __init__(self, database_path: str | Path | None = None):
        self.database_path = (
            Path(database_path) if database_path is not None else None
        )
        self._database: dict[str, str] = {}

        self.load_database()

    @staticmethod
    def _normalize_prefix(value: str) -> str | None:
        normalized = re.sub(r"[-:.\s]", "", value.strip()).lower()

        if not re.fullmatch(r"[0-9a-f]+", normalized):
            return None

        if len(normalized) not in OUIResolver.VALID_PREFIX_LENGTHS:
            return None

        return normalized

    def _open_database(self):
        """
        Opens either a custom registry file or the bundled package resource.
        """
        if self.database_path is not None:
            return self.database_path.open(
                "r",
                encoding="utf-8",
                errors="replace",
            )

        resource = files("watchfuleye.data").joinpath("oui.txt")

        return resource.open(
            "r",
            encoding="utf-8",
            errors="replace",
        )

    
    def load_database(self) -> int:
        """
        Loads IEEE manufacturer assignments into memory.

        Returns the number of distinct prefixes loaded.

        Missing custom files return 0, which is useful for tests.
        Missing bundled data raises an error instead of silently
        disabling manufacturer identification.
        """
        self._database.clear()

        try:
            with self._open_database() as file:
                for line in file:
                    match = self.REGISTRY_PATTERN.match(line)

                    if not match:
                        continue

                    prefix = self._normalize_prefix(match.group(1))
                    manufacturer = match.group(2).strip()

                    if prefix is None or not manufacturer:
                        continue

                    self._database[prefix] = manufacturer

        except (FileNotFoundError, ModuleNotFoundError) as exc:
            if self.database_path is not None:
                return 0

            raise RuntimeError(
                "The bundled IEEE registry could not be found. "
                "Expected: watchfuleye/data/oui.txt. "
                "Generate it using build_oui_database_v1_2.py."
            ) from exc

        except OSError as exc:
            raise RuntimeError(
                f"Could not read OUI database: {exc}"
            ) from exc

        if not self._database and self.database_path is None:
            raise RuntimeError(
                "The bundled oui.txt exists, but no valid IEEE assignments "
                "were recognized. Check the registry file format."
            )

        return len(self._database)


    def resolve(self, mac_address: str | None) -> str | None:
        """
        Returns the manufacturer matching a MAC address.

        Longer assignments take precedence over shorter assignments.
        """
        normalized_mac = DeviceIdentityResolver.normalize_mac(mac_address)

        if normalized_mac is None:
            return None

        compact_mac = normalized_mac.replace(":", "")

        for prefix_length in (9, 7, 6):
            prefix = compact_mac[:prefix_length]
            manufacturer = self._database.get(prefix)

            if manufacturer:
                return manufacturer

        return None

    def enrich(self, observation: Observation) -> Observation | None:
        """
        Converts a MAC_ADDRESS observation into a MANUFACTURER observation.
        """
        if not isinstance(observation, Observation):
            raise TypeError("enrich() requires an Observation object.")

        if observation.type != ObservationType.MAC_ADDRESS:
            raise ValueError(
                "OUIResolver only accepts MAC_ADDRESS observations."
            )

        manufacturer = self.resolve(observation.value)

        if manufacturer is None:
            return None

        return Observation(
            scan_id=observation.scan_id,
            source="OUI",
            type=ObservationType.MANUFACTURER,
            value=manufacturer,
            device_id=observation.device_id,
            correlation_id=observation.correlation_id,
            confidence=0.95,
            interface=observation.interface,
        )
