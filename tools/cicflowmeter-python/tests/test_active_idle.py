from scapy.all import Ether, IP, TCP

from cicflowmeter.flow import Flow
from cicflowmeter.features.context import PacketDirection
import pytest

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


def test_active_idle_initialization():
    flow = create_flow([1000.0])

    assert flow.start_active == 1000.0
    assert flow.last_active == 1000.0


def test_continuous_traffic():
    flow = create_flow([1000.0, 1002.0, 1004.0])

    assert flow.active == []
    assert flow.idle == []
    assert flow.last_active == 1004.0


def test_idle_gap_exceeding_five_seconds():
    flow = create_flow([1000.0, 1002.0, 1008.0, 1010.0])

    assert flow.active == [2.0]
    assert flow.idle == [6.0]
    assert flow.start_active == 1008.0
    assert flow.last_active == 1010.0


def test_multiple_active_idle_periods():
    flow = create_flow([
        1000.0, 1002.0,
        1008.0, 1010.0,
        1017.0, 1019.0
    ])

    assert flow.active == [2.0, 2.0]
    assert flow.idle == [6.0, 7.0]
    assert flow.start_active == 1017.0
    assert flow.last_active == 1019.0

def test_final_active_period_included_in_features():
    flow = create_flow([1000.0, 1002.0, 1004.0])

    data = flow.get_data()

    assert data["active_mean"] == 4.0
    assert data["active_max"] == 4.0
    assert data["active_min"] == 4.0


def test_repeated_extraction_does_not_duplicate_active_period():
    flow = create_flow([1000.0, 1002.0, 1004.0])

    first = flow.get_data()
    second = flow.get_data()

    assert first["active_mean"] == 4.0
    assert second["active_mean"] == 4.0

    assert first["active_max"] == 4.0
    assert second["active_max"] == 4.0

    assert flow.active == []


def test_exactly_five_second_gap_is_not_idle():
    flow = create_flow([1000.0, 1002.0, 1007.0])

    assert flow.active == []
    assert flow.idle == []
    assert flow.start_active == 1000.0
    assert flow.last_active == 1007.0


def test_gap_greater_than_five_seconds_starts_idle_period():
    flow = create_flow([1000.0, 1002.0, 1007.001])

    assert flow.active == [2.0]
    assert flow.idle[0] == pytest.approx(5.001)
    assert flow.start_active == 1007.001
    assert flow.last_active == 1007.001