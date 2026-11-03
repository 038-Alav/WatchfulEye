import json
import os

from pathlib import Path
from tempfile import NamedTemporaryFile
from threading import RLock
from typing import Any


class JsonStorageError(Exception):
    """Raised when JSON storage cannot be read or written safely."""


class JsonStorage:

    SCHEMA_VERSION = 1

    def __init__(self, file_path: str | Path):

        self.file_path = Path(file_path)
        self._lock = RLock()

    # --------------------------------------------------
    # Read
    # --------------------------------------------------

    def read(self, default_data: Any = None) -> Any:
        """
        Read a versioned JSON document.

        Missing files return the supplied default data.
        Existing legacy documents must be migrated explicitly
        by their respective repositories.
        """

        with self._lock:

            if not self.file_path.exists():

                return (
                    default_data
                    if default_data is not None
                    else []
                )

            try:

                with self.file_path.open(
                    "r",
                    encoding="utf-8"
                ) as file:

                    document = json.load(file)

            except json.JSONDecodeError as exc:

                raise JsonStorageError(
                    f"Invalid JSON in '{self.file_path}': "
                    f"line {exc.lineno}, column {exc.colno}."
                ) from exc

            except OSError as exc:

                raise JsonStorageError(
                    f"Could not read '{self.file_path}': {exc}"
                ) from exc

            if not isinstance(document, dict):

                raise JsonStorageError(
                    f"Unsupported JSON structure in "
                    f"'{self.file_path}'. Expected a versioned "
                    "JSON object."
                )

            if "schema_version" not in document:
                raise JsonStorageError(
                    f"Missing schema_version in '{self.file_path}'."
                )

            if "data" not in document:
                raise JsonStorageError(
                    f"Missing data field in '{self.file_path}'."
                )

            version = document["schema_version"]

            if version != self.SCHEMA_VERSION:

                raise JsonStorageError(
                    f"Unsupported schema version {version} in "
                    f"'{self.file_path}'. Expected "
                    f"{self.SCHEMA_VERSION}."
                )

            return document["data"]

    # --------------------------------------------------
    # Write
    # --------------------------------------------------

    def write(self, data: Any) -> None:
        """
        Atomically write a versioned JSON document.
        """

        document = {
            "schema_version": self.SCHEMA_VERSION,
            "data": data,
        }

        temporary_path = None

        with self._lock:

            try:

                self.file_path.parent.mkdir(
                    parents=True,
                    exist_ok=True
                )

                with NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    dir=self.file_path.parent,
                    prefix=f".{self.file_path.name}.",
                    suffix=".tmp",
                    delete=False,
                ) as temporary_file:

                    temporary_path = Path(
                        temporary_file.name
                    )

                    json.dump(
                        document,
                        temporary_file,
                        indent=4,
                        ensure_ascii=False,
                    )

                    temporary_file.flush()
                    os.fsync(temporary_file.fileno())

                os.replace(
                    temporary_path,
                    self.file_path
                )

            except (OSError, TypeError, ValueError) as exc:

                raise JsonStorageError(
                    f"Could not write '{self.file_path}': {exc}"
                ) from exc

            finally:

                if (
                    temporary_path is not None
                    and temporary_path.exists()
                ):

                    try:
                        temporary_path.unlink()
                    except OSError:
                        pass
