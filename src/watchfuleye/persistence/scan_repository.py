from pathlib import Path
from datetime import datetime

from watchfuleye.domain.scan import (
    ScanRun,
    ScanStatus,
    ProviderStatus,
    ProviderExecutionResult,
)

from watchfuleye.persistence.json_storage import JsonStorage


class ScanRepository:

    def __init__(self, file_path: str | Path):

        self.storage = JsonStorage(file_path)

    # --------------------------------------------------
    # Serialization
    # --------------------------------------------------

    @staticmethod
    def _provider_to_dict(
        result: ProviderExecutionResult
    ) -> dict:

        return {
            "provider": result.provider,
            "status": result.status.value,
            "duration_ms": result.duration_ms,
            "error": result.error,
        }

    @staticmethod
    def _scan_to_dict(scan: ScanRun) -> dict:

        return {
            "id": scan.id,
            "network_cidr": scan.network_cidr,
            "interface_name": scan.interface_name,
            "status": scan.status.value,
            "started_at": scan.started_at.isoformat(),
            "finished_at": (
                scan.finished_at.isoformat()
                if scan.finished_at
                else None
            ),
            "providers_executed": scan.providers_executed,
            "errors": scan.errors,
            "provider_results": [
                ScanRepository._provider_to_dict(result)
                for result in scan.provider_results
            ],
        }

    @staticmethod
    def _scan_from_dict(data: dict) -> ScanRun:

        provider_results = [
            ProviderExecutionResult(
                provider=item["provider"],
                status=ProviderStatus(item["status"]),
                observations=[],
                duration_ms=item.get("duration_ms", 0.0),
                error=item.get("error"),
            )
            for item in data.get("provider_results", [])
        ]

        return ScanRun(
            id=data["id"],
            network_cidr=data["network_cidr"],
            interface_name=data["interface_name"],
            status=ScanStatus(data["status"]),
            started_at=datetime.fromisoformat(
                data["started_at"]
            ),
            finished_at=(
                datetime.fromisoformat(data["finished_at"])
                if data.get("finished_at")
                else None
            ),
            providers_executed=data.get(
                "providers_executed", []
            ),
            errors=data.get("errors", []),
            provider_results=provider_results,
        )

    # --------------------------------------------------
    # Internal loading
    # --------------------------------------------------

    def _load(self) -> list[ScanRun]:

        raw = self.storage.read(default_data=[])

        if not isinstance(raw, list):
            raise RuntimeError(
                "Invalid scan storage: expected a list."
            )

        try:

            return [
                self._scan_from_dict(item)
                for item in raw
            ]

        except (KeyError, TypeError, ValueError) as exc:

            raise RuntimeError(
                f"Invalid scan record: {exc}"
            ) from exc

    # --------------------------------------------------
    # Public operations
    # --------------------------------------------------

    def get_all(self) -> list[ScanRun]:

        return self._load()

    def get_by_id(self, scan_id: str):

        return next(
            (
                scan
                for scan in self.get_all()
                if scan.id == scan_id
            ),
            None
        )

    def get_by_status(
        self,
        status: ScanStatus
    ) -> list[ScanRun]:

        return [
            scan
            for scan in self.get_all()
            if scan.status == status
        ]

    def add(self, scan: ScanRun):

        self.add_many([scan])

    def add_many(self, scans: list[ScanRun]):

        if not all(
            isinstance(scan, ScanRun)
            for scan in scans
        ):
            raise TypeError(
                "add_many() only accepts ScanRun objects."
            )

        existing = self._load()

        existing_ids = {
            scan.id
            for scan in existing
        }

        incoming_ids = set()

        for scan in scans:

            if scan.id in incoming_ids:
                raise ValueError(
                    f"Duplicate scan ID in batch: {scan.id}"
                )

            incoming_ids.add(scan.id)

        new_scans = [
            scan
            for scan in scans
            if scan.id not in existing_ids
        ]

        if not new_scans:
            return

        self.storage.write([
            self._scan_to_dict(scan)
            for scan in existing + new_scans
        ])

    def update(self, scan: ScanRun):

        scans = self._load()

        for index, current in enumerate(scans):

            if current.id == scan.id:

                scans[index] = scan

                self.storage.write([
                    self._scan_to_dict(item)
                    for item in scans
                ])

                return

        raise KeyError(
            f"Scan not found: {scan.id}"
        )

    def save_all(self, scans: list[ScanRun]):

        if not all(
            isinstance(scan, ScanRun)
            for scan in scans
        ):
            raise TypeError(
                "save_all() only accepts ScanRun objects."
            )

        ids = [
            scan.id
            for scan in scans
        ]

        if len(ids) != len(set(ids)):
            raise ValueError(
                "Duplicate scan IDs are not allowed."
            )

        self.storage.write([
            self._scan_to_dict(scan)
            for scan in scans
        ])
