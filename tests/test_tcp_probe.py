from watchfuleye.enrichment.tcp_probe import TCPProbe


class FakeSocket:
    def __init__(self, result=0, error=None):
        self.result = result
        self.error = error
        self.timeout = None
        self.address = None
        self.closed = False

    def settimeout(self, value):
        self.timeout = value

    def connect_ex(self, address):
        self.address = address
        if self.error:
            raise self.error
        return self.result

    def close(self):
        self.closed = True


def test_tcp_probe_reports_open_connection(monkeypatch):
    fake = FakeSocket(result=0)
    monkeypatch.setattr("watchfuleye.enrichment.tcp_probe.socket.socket", lambda *args: fake)

    assert TCPProbe.is_open("192.168.100.20", 554, 0.25) is True
    assert fake.address == ("192.168.100.20", 554)
    assert fake.timeout == 0.25
    assert fake.closed is True


def test_tcp_probe_reports_closed_or_failed_connection(monkeypatch):
    fake = FakeSocket(result=111)
    monkeypatch.setattr("watchfuleye.enrichment.tcp_probe.socket.socket", lambda *args: fake)

    assert TCPProbe.is_open("192.168.100.20", 554, 0.25) is False
    assert fake.closed is True


def test_tcp_probe_validates_curated_ports():
    probe = TCPProbe(ports=[80, 443, 80])
    assert probe.ports == (80, 443)

    try:
        TCPProbe(ports=[0])
    except ValueError:
        pass
    else:
        raise AssertionError("Expected invalid port to be rejected")


def test_tcp_probe_binds_to_selected_interface_source_ip(monkeypatch):
    class BindableSocket(FakeSocket):
        def __init__(self):
            super().__init__(result=0)
            self.bound = None

        def bind(self, address):
            self.bound = address

    fake = BindableSocket()
    monkeypatch.setattr("watchfuleye.enrichment.tcp_probe.socket.socket", lambda *args: fake)

    assert TCPProbe.is_open(
        "192.168.100.20",
        554,
        0.25,
        source_ip="192.168.100.1",
    ) is True
    assert fake.bound == ("192.168.100.1", 0)
