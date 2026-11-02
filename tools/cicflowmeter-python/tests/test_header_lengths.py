import pytest

from scapy.layers.inet import IP, UDP, IPOption_NOP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt
from scapy.layers.l2 import Ether

from cicflowmeter.flow import Flow
from cicflowmeter.features.context import PacketDirection
from cicflowmeter.features.packet_length import PacketLength
from cicflowmeter.features.flow_bytes import FlowBytes


def create_flow(packet):
    packet.time = 1000.0
    return Flow(packet, PacketDirection.FORWARD)


@pytest.mark.parametrize(
    "packet,expected",
    [
        (
            Ether() / IP() / UDP(),
            20,
        ),
        (
            Ether() / IP(options=[IPOption_NOP()] * 4) / UDP(),
            24,
        ),
        (
            Ether() / IPv6() / UDP(),
            40,
        ),
        (
            Ether()
            / IPv6()
            / IPv6ExtHdrHopByHop()
            / IPv6ExtHdrDestOpt()
            / UDP(),
            56,
        ),
    ],
)
def test_network_header_length(packet, expected):
    flow = create_flow(packet)

    packet_length = PacketLength(flow)
    flow_bytes = FlowBytes(flow)

    assert list(packet_length.get_header_length()) == [expected]
    assert flow_bytes._header_size(packet) == expected


@pytest.mark.parametrize(
    "packet,expected",
    [
        (Ether() / IP(ttl=64) / UDP(), 64),
        (Ether() / IPv6(hlim=128) / UDP(), 128),
    ],
)
def test_initial_ttl_or_hop_limit(packet, expected):
    flow = create_flow(packet)

    assert FlowBytes(flow).get_initial_ttl() == expected
