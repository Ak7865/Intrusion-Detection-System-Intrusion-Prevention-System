from scapy.all import Ether, IP, TCP

from cicflowmeter.flow import Flow
from cicflowmeter.features.context import PacketDirection
from cicflowmeter.features.packet_time import PacketTime

def make_packet(timestamp):
    packet = (
        Ether()
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=80)
    )
    packet.time = timestamp
    return packet

def create_flow(timestamps):
    flow = Flow(make_packet(timestamps[0]), PacketDirection.FORWARD)

    for timestamp in timestamps[1:]:
        flow.add_packet(make_packet(timestamp), PacketDirection.FORWARD)

    return flow


def test_negative_flow_iat_is_excluded():
    flow = create_flow([1000.0, 1002.0, 1001.0, 1003.0])


    assert flow.flow_interarrival_time == [2.0, 2.0]
    assert all(iat >= 0 for iat in flow.flow_interarrival_time)


def test_timestamp_regression_is_counted():
    flow = create_flow([1000.0, 1002.0, 1001.0, 1003.0])


    assert flow.timestamp_regressions == 1


def test_latest_timestamp_remains_maximum():
    flow = create_flow([1000.0, 1002.0, 1001.0, 1003.0])


    assert flow.latest_timestamp == 1003.0


def test_packet_order_is_preserved():
    timestamps = [1000.0, 1002.0, 1001.0, 1003.0]
    flow = create_flow(timestamps)


    recorded = [
        flow.observations.first_timestamp + timestamp
        for timestamp in flow.observations.timestamps
    ]

    assert recorded == timestamps


def test_directional_iat_excludes_negative_intervals():
    flow = create_flow([1000.0, 1002.0, 1001.0, 1003.0])
    packet_time = PacketTime(flow)


    forward_iat = packet_time.get_packet_iat(PacketDirection.FORWARD)

    assert forward_iat == [2.0, 2.0]
    assert all(iat >= 0 for iat in forward_iat)


def test_zero_iat_is_preserved():
    flow = create_flow([1000.0, 1000.0, 1001.0])


    assert flow.flow_interarrival_time == [0.0, 1.0]


def test_out_of_order_packet_does_not_update_bulk_statistics(monkeypatch):
    flow = create_flow([1000.0])


    calls = {"bulk": 0, "active_idle": 0}

def bulk_spy(packet, direction):
    calls["bulk"] += 1

def active_idle_spy(packet):
    calls["active_idle"] += 1

    monkeypatch.setattr(flow, "update_flow_bulk", bulk_spy)
    monkeypatch.setattr(flow, "update_subflow", active_idle_spy)

    flow.add_packet(make_packet(999.0), PacketDirection.FORWARD)

    assert calls["bulk"] == 0
    assert calls["active_idle"] == 0
    assert flow.timestamp_regressions == 1


def test_processing_resumes_after_timestamp_regression(monkeypatch):
    flow = create_flow([1000.0, 1002.0])


    calls = {"bulk": 0, "active_idle": 0}

def bulk_spy(packet, direction):
    calls["bulk"] += 1

def active_idle_spy(packet):
    calls["active_idle"] += 1

    monkeypatch.setattr(flow, "update_flow_bulk", bulk_spy)
    monkeypatch.setattr(flow, "update_subflow", active_idle_spy)

    # Capture-order recovery, but still below the maximum timestamp.
    flow.add_packet(make_packet(1001.0), PacketDirection.FORWARD)
    flow.add_packet(make_packet(1001.5), PacketDirection.FORWARD)

    assert calls["bulk"] == 0
    assert calls["active_idle"] == 0

    # Timestamp advances beyond the previous maximum.
    flow.add_packet(make_packet(1003.0), PacketDirection.FORWARD)

    assert calls["bulk"] == 1
    assert calls["active_idle"] == 1
    assert flow.timestamp_regressions == 1
    assert flow.latest_timestamp == 1003.0

