from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw
import pytest

from cicflowmeter.features.context import PacketDirection
from cicflowmeter.packet_observations import PacketObservations


def make_packet(timestamp, protocol="TCP", flags="PA", payload=b"DATA"):
    if protocol == "TCP":
        packet = (
            Ether()
            / IP(src="192.0.2.1", dst="192.0.2.2")
            / TCP(sport=12345, dport=80, flags=flags)
            / Raw(load=payload)
        )
    elif protocol == "UDP":
        packet = (
            Ether()
            / IPv6(src="2001:db8::1", dst="2001:db8::2")
            / UDP(sport=12345, dport=53)
            / Raw(load=payload)
        )
    else:
        raise ValueError(protocol)

    packet.time = timestamp
    return packet


def test_observation_storage_lengths():
    observations = PacketObservations(1000.0)

    observations.append(
        make_packet(1000.0),
        PacketDirection.FORWARD,
    )

    observations.append(
        make_packet(1000.1, "UDP"),
        PacketDirection.REVERSE,
    )

    assert len(observations) == 2
    assert len(observations.timestamps) == 2
    assert len(observations.directions) == 2
    assert len(observations.packet_lengths) == 2
    assert len(observations.header_lengths) == 2
    assert len(observations.tcp_flags) == 2
    assert len(observations.payload_lengths) == 2


def test_relative_timestamps_preserve_capture_order():
    observations = PacketObservations(1000.0)

    for timestamp in [1000.0, 1002.0, 1001.0, 1003.0]:
        observations.append(
            make_packet(timestamp),
            PacketDirection.FORWARD,
        )

    assert list(observations.timestamps) == [0.0, 2.0, 1.0, 3.0]


def test_directional_iat_excludes_zero_and_negative_intervals():
    observations = PacketObservations(1000.0)

    for timestamp in [1000.0, 1002.0, 1001.0, 1003.0]:
        observations.append(
            make_packet(timestamp),
            PacketDirection.FORWARD,
        )

    assert list(observations.forward_iats) == pytest.approx([2.0, 2.0])


def test_forward_and_backward_iat_are_separate():
    observations = PacketObservations(1000.0)

    packets = [
        (1000.0, PacketDirection.FORWARD),
        (1000.2, PacketDirection.REVERSE),
        (1000.5, PacketDirection.FORWARD),
        (1000.7, PacketDirection.REVERSE),
    ]

    for timestamp, direction in packets:
        observations.append(make_packet(timestamp), direction)

    assert list(observations.forward_iats) == [0.5]
    assert list(observations.backward_iats) == [0.5]


def test_response_time_preserves_capture_order():
    observations = PacketObservations(1000.0)

    packets = [
        (1000.0, PacketDirection.FORWARD),
        (1000.2, PacketDirection.REVERSE),
        (1000.5, PacketDirection.FORWARD),
        (1000.7, PacketDirection.REVERSE),
    ]

    for timestamp, direction in packets:
        observations.append(make_packet(timestamp), direction)

    assert list(observations.response_times) == pytest.approx([0.2, 0.2])


def test_response_time_preserves_negative_difference():
    observations = PacketObservations(1000.0)

    observations.append(
        make_packet(1000.0),
        PacketDirection.FORWARD,
    )

    observations.append(
        make_packet(999.5),
        PacketDirection.REVERSE,
    )

    assert list(observations.response_times) == [-0.5]


def test_tcp_flags_and_payload_length():
    observations = PacketObservations(1000.0)

    observations.append(
        make_packet(1000.0, flags="PA", payload=b"HELLO"),
        PacketDirection.FORWARD,
    )

    assert observations.tcp_flags[0] == 0x18
    assert observations.payload_lengths[0] == 5


def test_udp_payload_length_ipv6():
    observations = PacketObservations(1000.0)

    observations.append(
        make_packet(1000.0, protocol="UDP", payload=b"DNSDATA"),
        PacketDirection.FORWARD,
    )

    assert observations.tcp_flags[0] == 0
    assert observations.payload_lengths[0] == 7


def test_header_length_uses_four_byte_storage():
    observations = PacketObservations(1000.0)

    assert observations.header_lengths.itemsize == 4
