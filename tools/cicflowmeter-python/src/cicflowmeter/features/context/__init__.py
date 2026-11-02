from enum import Enum, auto

from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6


class PacketDirection(Enum):
    """Direction of a packet within a bidirectional network flow."""

    FORWARD = auto()
    REVERSE = auto()


def get_packet_flow_key(packet: Packet, direction: PacketDirection) -> tuple:
    """Generate a bidirectional flow key for IPv4 or IPv6 TCP/UDP packets."""

    if TCP in packet:
        transport = packet[TCP]
        protocol = "TCP"
    elif UDP in packet:
        transport = packet[UDP]
        protocol = "UDP"
    else:
        raise ValueError("Only TCP and UDP packets are supported.")

    if IP in packet:
        ip_layer = packet[IP]
        address_family = "IPv4"
    elif IPv6 in packet:
        ip_layer = packet[IPv6]
        address_family = "IPv6"
    else:
        raise ValueError("Only IPv4 and IPv6 packets are supported.")

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    src_port = transport.sport
    dst_port = transport.dport

    if direction == PacketDirection.REVERSE:
        src_ip, dst_ip = dst_ip, src_ip
        src_port, dst_port = dst_port, src_port

    return address_family, protocol, src_ip, dst_ip, src_port, dst_port


def get_network_header_length(packet: Packet) -> int:
    """Calculate IPv4 or IPv6 network-layer header length."""

    if IP in packet:
        ip_layer = packet[IP]
    elif IPv6 in packet:
        ip_layer = packet[IPv6]
    else:
        return 0

    if TCP in packet:
        transport_layer = packet[TCP]
    elif UDP in packet:
        transport_layer = packet[UDP]
    else:
        return 0

    return len(bytes(ip_layer)) - len(bytes(transport_layer))


def get_network_packet_length(packet: Packet) -> int:
    """Return the serialized IPv4 or IPv6 packet length."""

    if IP in packet:
        return len(bytes(packet[IP]))

    if IPv6 in packet:
        return len(bytes(packet[IPv6]))

    return 0