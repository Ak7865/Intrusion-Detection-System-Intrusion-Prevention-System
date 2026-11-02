from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

from .context import (
    PacketDirection,
    get_network_header_length,
    get_network_packet_length,
)
from .packet_time import PacketTime


class FlowBytes:
    """Extracts features from the traffic related to the bytes in a flow."""

    def __init__(self, flow):
        self.flow = flow

    def get_bytes(self) -> int:
        """Calculate the total network-layer bytes transferred."""

        observations = getattr(self.flow, "observations", None)

        if observations is not None:
            return sum(observations.packet_lengths)

        return sum(
            get_network_packet_length(packet)
            for packet, _ in self.flow.packets
        )

    def get_rate(self) -> float:
        """Calculate the total bytes transferred per second."""

        duration = PacketTime(self.flow).get_duration()

        if duration == 0:
            return 0

        return self.get_bytes() / duration

    def get_bytes_sent(self) -> int:
        """Calculate the network-layer bytes sent in the forward direction."""

        observations = getattr(self.flow, "observations", None)

        if observations is not None:
            return sum(
                length
                for length, direction in zip(
                    observations.packet_lengths,
                    observations.directions,
                )
                if direction == 0
            )

        return sum(
            get_network_packet_length(packet)
            for packet, direction in self.flow.packets
            if direction == PacketDirection.FORWARD
        )

    def get_sent_rate(self) -> float:
        """Calculate the forward bytes transferred per second."""

        sent = self.get_bytes_sent()
        duration = PacketTime(self.flow).get_duration()

        if duration == 0:
            return -1

        return sent / duration

    def get_bytes_received(self) -> int:
        """Calculate the network-layer bytes received in the reverse direction."""

        observations = getattr(self.flow, "observations", None)

        if observations is not None:
            return sum(
                length
                for length, direction in zip(
                    observations.packet_lengths,
                    observations.directions,
                )
                if direction == 1
            )

        return sum(
            get_network_packet_length(packet)
            for packet, direction in self.flow.packets
            if direction == PacketDirection.REVERSE
        )

    def get_received_rate(self) -> float:
        """Calculate the reverse bytes transferred per second."""

        received = self.get_bytes_received()
        duration = PacketTime(self.flow).get_duration()

        if duration == 0:
            return -1

        return received / duration

    def get_forward_header_bytes(self) -> int:
        """Calculate total forward network-layer header bytes."""

        observations = getattr(self.flow, "observations", None)

        if observations is not None:
            return sum(
                length
                for length, direction in zip(
                    observations.header_lengths,
                    observations.directions,
                )
                if direction == 0
            )

        return sum(
            self._header_size(packet)
            for packet, direction in self.flow.packets
            if direction == PacketDirection.FORWARD
        )

    def get_forward_rate(self) -> int:
        """Calculate forward header bytes transferred per second."""

        forward = self.get_forward_header_bytes()
        duration = PacketTime(self.flow).get_duration()

        if duration > 0:
            return forward / duration

        return -1

    def _header_size(self, packet):
        """Calculate the network-layer header size."""

        return get_network_header_length(packet)

    def get_reverse_header_bytes(self) -> int:
        """Calculate total reverse network-layer header bytes."""

        observations = getattr(self.flow, "observations", None)

        if observations is not None:
            return sum(
                length
                for length, direction in zip(
                    observations.header_lengths,
                    observations.directions,
                )
                if direction == 1
            )

        return sum(
            self._header_size(packet)
            for packet, direction in self.flow.packets
            if direction == PacketDirection.REVERSE
        )

    def get_min_forward_header_bytes(self) -> int:
        """Return the minimum forward network-layer header length."""

        observations = getattr(self.flow, "observations", None)

        if observations is not None:
            return min(
                (
                    length
                    for length, direction in zip(
                        observations.header_lengths,
                        observations.directions,
                    )
                    if direction == 0
                ),
                default=0,
            )

        return min(
            (
                self._header_size(packet)
                for packet, direction in self.flow.packets
                if direction == PacketDirection.FORWARD
            ),
            default=0,
        )

    def get_reverse_rate(self) -> int:
        """Calculate reverse header bytes transferred per second."""

        reverse = self.get_reverse_header_bytes()
        duration = PacketTime(self.flow).get_duration()

        if duration == 0:
            return -1

        return reverse / duration

    def get_header_in_out_ratio(self) -> float:
        """Calculate the ratio of forward to reverse header bytes."""

        reverse_header_bytes = self.get_reverse_header_bytes()
        forward_header_bytes = self.get_forward_header_bytes()

        if reverse_header_bytes == 0:
            return -1

        return forward_header_bytes / reverse_header_bytes

    def get_initial_ttl(self) -> int:
        """Return the initial IPv4 TTL or IPv6 Hop Limit."""

        # Future compact Flow integration will store this as a scalar.
        initial_ttl = getattr(self.flow, "initial_ttl", None)

        if initial_ttl is not None:
            return initial_ttl

        if not self.flow.packets:
            return 0

        packet = self.flow.packets[0][0]

        if IP in packet:
            return packet[IP].ttl

        if IPv6 in packet:
            return packet[IPv6].hlim

        return 0

    def get_bytes_per_bulk(self, direction: PacketDirection) -> float:
        """Calculate average bytes per bulk."""

        if (
            direction is PacketDirection.FORWARD
            and self.flow.forward_bulk_count != 0
        ):
            return (
                self.flow.forward_bulk_size
                / self.flow.forward_bulk_count
            )

        if (
            direction is PacketDirection.REVERSE
            and self.flow.backward_bulk_count != 0
        ):
            return (
                self.flow.backward_bulk_size
                / self.flow.backward_bulk_count
            )

        return 0

    def get_packets_per_bulk(self, direction: PacketDirection) -> float:
        """Calculate average packets per bulk."""

        if (
            direction is PacketDirection.FORWARD
            and self.flow.forward_bulk_count != 0
        ):
            return (
                self.flow.forward_bulk_packet_count
                / self.flow.forward_bulk_count
            )

        if (
            direction is PacketDirection.REVERSE
            and self.flow.backward_bulk_count != 0
        ):
            return (
                self.flow.backward_bulk_packet_count
                / self.flow.backward_bulk_count
            )

        return 0

    def get_bulk_rate(self, direction: PacketDirection) -> float:
        """Calculate the average bulk transfer rate."""

        if (
            direction is PacketDirection.FORWARD
            and self.flow.forward_bulk_duration != 0
        ):
            return (
                self.flow.forward_bulk_size
                / self.flow.forward_bulk_duration
            )

        if (
            direction is PacketDirection.REVERSE
            and self.flow.backward_bulk_duration != 0
        ):
            return (
                self.flow.backward_bulk_size
                / self.flow.backward_bulk_duration
            )

        return 0