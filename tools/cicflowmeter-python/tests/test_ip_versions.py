import pytest

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from cicflowmeter.features.context import (
    PacketDirection,
    get_packet_flow_key,
)
from cicflowmeter.flow import Flow


@pytest.mark.parametrize(
    "ip_layer,src,dst",
    [
        (IP, "192.168.1.10", "192.168.1.20"),
        (IPv6, "2001:db8::10", "2001:db8::20"),
    ],
)
@pytest.mark.parametrize("transport", [TCP, UDP])
def test_forward_and_reverse_flow_keys(ip_layer, src, dst, transport):
    forward_packet = (
        Ether()
        / ip_layer(src=src, dst=dst)
        / transport(sport=50000, dport=80)
    )

    reverse_packet = (
        Ether()
        / ip_layer(src=dst, dst=src)
        / transport(sport=80, dport=50000)
    )

    forward_key = get_packet_flow_key(
        forward_packet, PacketDirection.FORWARD
    )

    reverse_key = get_packet_flow_key(
        reverse_packet, PacketDirection.REVERSE
    )

    assert forward_key == reverse_key


@pytest.mark.parametrize(
    "ip_layer,src,dst,expected_family",
    [
        (IP, "192.168.1.10", "192.168.1.20", "IPv4"),
        (IPv6, "2001:db8::10", "2001:db8::20", "IPv6"),
    ],
)
@pytest.mark.parametrize(
    "transport,expected_protocol",
    [
        (TCP, 6),
        (UDP, 17),
    ],
)
def test_flow_protocol_identification(
    ip_layer, src, dst, expected_family, transport, expected_protocol
):
    packet = (
        Ether()
        / ip_layer(src=src, dst=dst)
        / transport(sport=50000, dport=80)
    )
    packet.time = 1000.0

    flow = Flow(packet, PacketDirection.FORWARD)

    assert flow.protocol == expected_protocol
    assert flow.src_ip == src
    assert flow.dest_ip == dst


def test_ipv4_and_ipv6_flow_keys_are_distinct():
    ipv4_packet = (
        Ether()
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=80)
    )

    ipv6_packet = (
        Ether()
        / IPv6(src="2001:db8::10", dst="2001:db8::20")
        / TCP(sport=50000, dport=80)
    )

    ipv4_key = get_packet_flow_key(
        ipv4_packet, PacketDirection.FORWARD
    )

    ipv6_key = get_packet_flow_key(
        ipv6_packet, PacketDirection.FORWARD
    )

    assert ipv4_key != ipv6_key
    assert ipv4_key[0] == "IPv4"
    assert ipv6_key[0] == "IPv6"

def test_tcp_udp_identical_endpoints_produce_distinct_flow_keys():
    src = "192.168.1.10"
    dst = "192.168.1.20"

    tcp_packet = (
        Ether()
        / IP(src=src, dst=dst)
        / TCP(sport=50000, dport=80)
    )

    udp_packet = (
        Ether()
        / IP(src=src, dst=dst)
        / UDP(sport=50000, dport=80)
    )

    tcp_key = get_packet_flow_key(
        tcp_packet, PacketDirection.FORWARD
    )

    udp_key = get_packet_flow_key(
        udp_packet, PacketDirection.FORWARD
    )

    assert tcp_key != udp_key
    assert tcp_key[0] == udp_key[0] == "IPv4"
    assert tcp_key[2:] == udp_key[2:]
    assert tcp_key[1] == "TCP"
    assert udp_key[1] == "UDP"