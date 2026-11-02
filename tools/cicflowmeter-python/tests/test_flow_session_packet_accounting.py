import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from cicflowmeter.flow_session import FlowSession
from cicflowmeter.features.context import PacketDirection

class DummyWriter:
    def init(self):
        self.records = []


def write(self, data):
    self.records.append(data)


@pytest.fixture
def session(monkeypatch):
    writer = DummyWriter()

    monkeypatch.setattr(
        "cicflowmeter.flow_session.output_writer_factory",
        lambda *args, **kwargs: writer,
    )

    flow_session = FlowSession()

    return flow_session


def create_tcp_packet(timestamp, src_port=12345):
    packet = (
        Ether()
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=src_port, dport=80)
    )
    packet.time = timestamp
    return packet

def test_new_flow_initial_packet_counted_once(session):
    packet = create_tcp_packet(1000.0)

    session.process(packet)

    assert len(session.flows) == 1

    flow = next(iter(session.flows.values()))

    assert len(flow.observations) == 1
    assert list(flow.observations.timestamps) == [0.0]
    assert list(flow.observations.directions) == [0]


def test_existing_flow_packet_added_once(session):
    first = create_tcp_packet(1000.0)
    second = create_tcp_packet(1000.1)


    session.process(first)
    session.process(second)

    flow = next(iter(session.flows.values()))

    assert len(flow.observations) == 2

    assert list(flow.observations.timestamps) == pytest.approx([0.0, 0.1])
    assert list(flow.observations.directions) == [0, 0]


def test_expired_replacement_flow_initial_packet_counted_once(session):
    first = create_tcp_packet(1000.0)
    replacement = create_tcp_packet(1300.0)

    session.process(first)
    session.process(replacement)

    assert len(session.flows) == 2

    replacement_key = (
        (
            "IPv4",
            "TCP",
            "192.168.1.10",
            "192.168.1.20",
            12345,
            80,
        ),
        1,
    )

    replacement_flow = session.flows[replacement_key]

    assert len(replacement_flow.observations) == 1
    assert list(replacement_flow.observations.timestamps) == [0.0]
    assert list(replacement_flow.observations.directions) == [0]
