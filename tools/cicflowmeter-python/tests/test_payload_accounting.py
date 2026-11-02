from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

from cicflowmeter.features.packet_count import PacketCount


def test_tcp_payload_length_ipv4():
    packet = (
        IP(src="192.0.2.1", dst="192.0.2.2")
        / TCP(sport=12345, dport=80)
        / Raw(load=b"HELLO")
    )

    assert len(PacketCount.get_payload(packet)) == 5


def test_udp_payload_length_ipv4():
    packet = (
        IP(src="192.0.2.1", dst="192.0.2.2")
        / UDP(sport=12345, dport=53)
        / Raw(load=b"DNSDATA")
    )

    assert len(PacketCount.get_payload(packet)) == 7


def test_tcp_payload_length_ipv6():
    packet = (
        IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=12345, dport=80)
        / Raw(load=b"IPV6TCP")
    )

    assert len(PacketCount.get_payload(packet)) == 7


def test_udp_payload_length_ipv6():
    packet = (
        IPv6(src="2001:db8::1", dst="2001:db8::2")
        / UDP(sport=12345, dport=53)
        / Raw(load=b"IPV6UDP")
    )

    assert len(PacketCount.get_payload(packet)) == 7


def test_tcp_without_payload():
    packet = IP() / TCP()

    assert len(PacketCount.get_payload(packet)) == 0


def test_udp_without_payload():
    packet = IP() / UDP()

    assert len(PacketCount.get_payload(packet)) == 0