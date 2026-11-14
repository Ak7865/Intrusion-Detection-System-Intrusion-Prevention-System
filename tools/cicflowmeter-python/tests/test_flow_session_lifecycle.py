import threading

from cicflowmeter.flow_session import FlowSession


class DummyWriter:
    def __init__(self):
        self.records = []

    def write(self, data):
        self.records.append(data)

    def close(self):
        pass


def test_to_packet_list_does_not_deadlock(monkeypatch):
    writer = DummyWriter()

    monkeypatch.setattr(
        "cicflowmeter.flow_session.output_writer_factory",
        lambda *args, **kwargs: writer,
    )

    session = FlowSession()

    result = {}
    errors = []

    def run():
        try:
            result["packets"] = session.toPacketList()
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout=2)

    assert not thread.is_alive(), "toPacketList() deadlocked"
    assert not errors, f"toPacketList() raised: {errors}"

class FailingWriter:
    def write(self, data):
        raise RuntimeError("Simulated delivery failure")

    def close(self):
        pass


def test_failed_delivery_preserves_flow(monkeypatch):
    writer = FailingWriter()

    monkeypatch.setattr(
        "cicflowmeter.flow_session.output_writer_factory",
        lambda *args, **kwargs: writer,
    )

    session = FlowSession()
    packet = (
        __import__("scapy.layers.l2", fromlist=["Ether"]).Ether()
        / __import__("scapy.layers.inet", fromlist=["IP"]).IP(
            src="192.168.1.10", dst="192.168.1.20"
        )
        / __import__("scapy.layers.inet", fromlist=["TCP"]).TCP(
            sport=12345, dport=80
        )
    )
    packet.time = 1000.0

    session.process(packet)
    assert len(session.flows) == 1

    with __import__('pytest').raises(RuntimeError, match="Simulated delivery failure"):
        session.garbage_collect(None)

    assert len(session.flows) == 1

