from array import array

from scapy.layers.inet import TCP, UDP

from .features.context import (
    PacketDirection,
    get_network_header_length,
    get_network_packet_length,
)


class PacketObservations:
    """Compact per-packet metadata retained by a network flow."""

    def __init__(self, first_timestamp):
        self.first_timestamp = first_timestamp

        self.timestamps = array("d")
        self.directions = bytearray()
        self.packet_lengths = array("I")
        self.header_lengths = array("I")
        self.tcp_flags = bytearray()
        self.payload_lengths = array("I")

        self.forward_iats = array("d")
        self.backward_iats = array("d")
        self.response_times = array("d")

        self.last_forward_timestamp = None
        self.last_backward_timestamp = None
        self.last_packet_timestamp = None
        self.last_packet_direction = None

    def append(self, packet, direction):
        """Extract and retain compact metadata from a Scapy packet."""

        timestamp = packet.time

        # Calculate relative time before converting to float.
        relative_timestamp = float(timestamp - self.first_timestamp)

        if direction == PacketDirection.FORWARD:
            direction_value = 0
        elif direction == PacketDirection.REVERSE:
            direction_value = 1
        else:
            raise ValueError(f"Unsupported packet direction: {direction}")

        packet_length = get_network_packet_length(packet)
        header_length = get_network_header_length(packet)

        flags = int(packet[TCP].flags) if TCP in packet else 0

        if TCP in packet:
            payload_length = len(packet[TCP].payload)
        elif UDP in packet:
            payload_length = len(packet[UDP].payload)
        else:
            payload_length = 0

        if not 0 <= packet_length <= 0xFFFFFFFF:
            raise OverflowError("Packet length exceeds compact storage capacity.")

        if not 0 <= header_length <= 0xFFFFFFFF:
            raise OverflowError("Header length exceeds compact storage capacity.")

        if not 0 <= payload_length <= 0xFFFFFFFF:
            raise OverflowError("Payload length exceeds compact storage capacity.")

        # Directional IAT: preserve original timestamp subtraction.
        if direction_value == 0:
            if self.last_forward_timestamp is not None:
                difference = timestamp - self.last_forward_timestamp
                if timestamp > self.last_forward_timestamp:
                    self.forward_iats.append(float(difference))

            self.last_forward_timestamp = timestamp

        else:
            if self.last_backward_timestamp is not None:
                difference = timestamp - self.last_backward_timestamp
                if timestamp > self.last_backward_timestamp:
                    self.backward_iats.append(float(difference))

            self.last_backward_timestamp = timestamp

        # Response time: preserve the original capture-order semantics.
        if (
            self.last_packet_direction == PacketDirection.FORWARD
            and direction == PacketDirection.REVERSE
        ):
            self.response_times.append(
                float(timestamp - self.last_packet_timestamp)
            )

        self.timestamps.append(relative_timestamp)
        self.directions.append(direction_value)
        self.packet_lengths.append(packet_length)
        self.header_lengths.append(header_length)
        self.tcp_flags.append(flags)
        self.payload_lengths.append(payload_length)

        self.last_packet_timestamp = timestamp
        self.last_packet_direction = direction

    def __len__(self):
        return len(self.timestamps)
