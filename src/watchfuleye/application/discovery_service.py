import socket

from datetime import datetime, timezone


class DiscoveryService:

    def __init__(self, providers):
        self.providers = providers

    def discover(self, context):

        results = []
        errors = []

        for provider in self.providers:

            try:

                if not provider.is_available():
                    errors.append(
                        f"{provider.name}: provider unavailable"
                    )
                    continue

                observations = provider.discover(context)

                for item in observations:

                    ip = item.get("ip", "")
                    hostname = ""

                    if ip:
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]

                        except (
                            socket.herror,
                            socket.gaierror,
                            OSError,
                        ):
                            pass

                    item["hostname"] = hostname

                    item["observed_at"] = (
                        datetime.now(timezone.utc)
                        .isoformat(timespec="seconds")
                    )

                    results.append(item)

            except Exception as exc:

                errors.append(
                    f"{provider.name}: {exc}"
                )

        return results, errors