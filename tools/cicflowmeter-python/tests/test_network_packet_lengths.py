import pytest

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from cicflowmeter.features.context import PacketDirection
from cicflowmeter.features.flow_bytes import FlowBytes
from cicflowmeter.features.packet_length import PacketLength
from cicflowmeter.flow import Flow


@pytest.mark.parametrize(
    "network_layer,transport_layer",
    [
        (IP, TCP),
        (IPv6, UDP),
    ],
)
def test_packet_length_excludes_ethernet_header(
    network_layer, transport_layer
):
    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / network_layer()
        / transport_layer()
        / Raw(load=b"test-payload")
    )

    flow = Flow(packet, PacketDirection.FORWARD)
    packet_length = PacketLength(flow)

    expected_length = len(bytes(packet[network_layer]))

    assert packet_length.get_packet_length() == [expected_length]
    assert packet_length.get_total() == expected_length
    assert len(packet) - expected_length == 14


@pytest.mark.parametrize(
    "network_layer,transport_layer,forward_length,reverse_length",
    [
        (IP, TCP, 20, 10),
        (IPv6, UDP, 20, 10),
    ],
)
def test_forward_reverse_byte_accounting(
    network_layer,
    transport_layer,
    forward_length,
    reverse_length,
):
    if network_layer is IP:
        forward = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.168.1.2", dst="192.168.1.1")
            / TCP(sport=12345, dport=80)
            / Raw(load=b"A" * forward_length)
        )

        reverse = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.168.1.1", dst="192.168.1.2")
            / TCP(sport=80, dport=12345)
            / Raw(load=b"B" * reverse_length)
        )

    else:
        forward = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IPv6(src="2001:db8::1", dst="2001:db8::2")
            / UDP(sport=12345, dport=80)
            / Raw(load=b"A" * forward_length)
        )

        reverse = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IPv6(src="2001:db8::2", dst="2001:db8::1")
            / UDP(sport=80, dport=12345)
            / Raw(load=b"B" * reverse_length)
        )

    forward.time = 1000.0
    reverse.time = 1000.5

    flow = Flow(forward, PacketDirection.FORWARD)
    flow.add_packet(reverse, PacketDirection.REVERSE)

    flow_bytes = FlowBytes(flow)
    packet_lengths = PacketLength(flow)

    expected_forward = len(bytes(forward[network_layer]))
    expected_reverse = len(bytes(reverse[network_layer]))

    assert flow_bytes.get_bytes_sent() == expected_forward
    assert flow_bytes.get_bytes_received() == expected_reverse

    assert flow_bytes.get_bytes() == expected_forward + expected_reverse

    assert packet_lengths.get_total(PacketDirection.FORWARD) == expected_forward
    assert packet_lengths.get_total(PacketDirection.REVERSE) == expected_reverse

    assert flow_bytes.get_rate() == pytest.approx(
        (expected_forward + expected_reverse) / 0.5
    )


def test_unsupported_packet_has_zero_network_length():
    from scapy.layers.inet import ICMP

    packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP() / ICMP()

    flow = Flow.__new__(Flow)
    flow.packets = [(packet, PacketDirection.FORWARD)]

    packet_length = PacketLength(flow)

    assert packet_length.get_packet_length() == [28]
