import logging

from watchfuleye.application.discovery_coordinator import DiscoveryCoordinator
from watchfuleye.application.discovery_registry import DiscoveryRegistry
from watchfuleye.domain.observation import Observation, ObservationType
from watchfuleye.discovery.context import DiscoveryContext


class FakeProvider:
    def __init__(self, name):
        self.name = name

    def is_available(self):
        return True

    def discover(self, context):
        return [
            Observation(
                scan_id=context.scan_id,
                source=self.name,
                type=ObservationType.IP_ADDRESS,
                value="192.0.2.10",
            )
        ]


def test_each_provider_completion_is_logged_once(caplog):
    registry = DiscoveryRegistry()
    registry.register(FakeProvider("FIRST"), enabled=True)
    registry.register(FakeProvider("SECOND"), enabled=True)
    coordinator = DiscoveryCoordinator(registry)
    context = DiscoveryContext(
        network_cidr="192.0.2.0/24",
        interface_name="test0",
        scan_id="scan-1",
    )

    with caplog.at_level(logging.INFO, logger="watchfuleye.application.discovery_coordinator"):
        results = coordinator.execute(context)

    messages = [record.message for record in caplog.records if "Discovery provider '" in record.message]
    assert len(results) == 2
    assert len(messages) == 2
    assert "FIRST" in messages[0]
    assert "SECOND" in messages[1]
