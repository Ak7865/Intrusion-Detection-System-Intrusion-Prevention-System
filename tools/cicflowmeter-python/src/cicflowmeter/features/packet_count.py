from .context import PacketDirection
from .packet_time import PacketTime


class PacketCount:
    """This class extracts features related to packet counts."""

    def __init__(self, flow):
        self.flow = flow

    def get_total(self, packet_direction=None) -> int:
        """Count packets, optionally filtered by direction."""

        observations = getattr(self.flow, "observations", None)

        if observations is not None:
            if packet_direction is None:
                return len(observations)

            direction_code = (
                0 if packet_direction == PacketDirection.FORWARD else 1
            )

            return observations.directions.count(direction_code)

        if packet_direction is not None:
            return sum(
                1
                for _, direction in self.flow.packets
                if direction == packet_direction
            )

        return len(self.flow.packets)

    def get_rate(self, packet_direction=None) -> float:
        """Calculate packet transmission rate."""

        duration = PacketTime(self.flow).get_duration()

        if duration == 0:
            return 0

        return self.get_total(packet_direction) / duration

    def get_down_up_ratio(self) -> float:
        """Calculate reverse-to-forward packet ratio."""

        forward_size = self.get_total(PacketDirection.FORWARD)
        backward_size = self.get_total(PacketDirection.REVERSE)

        if forward_size > 0:
            return backward_size / forward_size

        return 0

    @staticmethod
    def get_payload(packet):
        """Return TCP or UDP payload."""

        if "TCP" in packet:
            return packet["TCP"].payload

        if "UDP" in packet:
            return packet["UDP"].payload

        return 0

    def has_payload(self, packet_direction=None) -> int:
        """Count packets containing application/transport payload."""

        observations = getattr(self.flow, "observations", None)

        if observations is not None:
            if packet_direction is None:
                return sum(
                    1 for length in observations.payload_lengths if length > 0
                )

            direction_code = (
                0 if packet_direction == PacketDirection.FORWARD else 1
            )

            return sum(
                1
                for length, direction in zip(
                    observations.payload_lengths,
                    observations.directions,
                )
                if direction == direction_code and length > 0
            )

        if packet_direction is not None:
            return sum(
                1
                for packet, direction in self.flow.packets
                if direction == packet_direction
                and len(self.get_payload(packet)) > 0
            )

        return sum(
            1
            for packet, _ in self.flow.packets
            if len(self.get_payload(packet)) > 0
        )