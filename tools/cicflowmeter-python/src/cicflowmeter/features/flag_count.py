from .context import PacketDirection


class FlagCount:
    """Extract TCP flag statistics using numeric bitmasks."""

    # TCP flag bit positions (RFC 793 and subsequent extensions).
    FLAG_MASKS = {
        "F": 0x01,  # FIN
        "S": 0x02,  # SYN
        "R": 0x04,  # RST
        "P": 0x08,  # PSH
        "A": 0x10,  # ACK
        "U": 0x20,  # URG
        "E": 0x40,  # ECE
        "C": 0x80,  # CWR
    }

    def __init__(self, flow):
        self.flow = flow

    def count(self, flag, packet_direction=None) -> int:
        """Count packets containing the requested TCP flag."""

        if not flag:
            return 0

        mask = self.FLAG_MASKS.get(flag[0].upper())

        if mask is None:
            return 0

        observations = getattr(self.flow, "observations", None)

        if observations is not None:
            if packet_direction is None:
                return sum(
                    1
                    for flags in observations.tcp_flags
                    if flags & mask
                )

            if packet_direction == PacketDirection.FORWARD:
                direction_code = 0
            elif packet_direction == PacketDirection.REVERSE:
                direction_code = 1
            else:
                raise ValueError(
                    f"Unsupported packet direction: {packet_direction}"
                )

            return sum(
                1
                for flags, direction in zip(
                    observations.tcp_flags,
                    observations.directions,
                )
                if direction == direction_code and flags & mask
            )

        # Backward-compatible packet-based implementation.
        count = 0

        if packet_direction is not None:
            packets = (
                packet
                for packet, direction in self.flow.packets
                if direction == packet_direction
            )
        else:
            packets = (
                packet for packet, _ in self.flow.packets
            )

        for packet in packets:
            if flag[0].upper() in packet.sprintf("%TCP.flags%"):
                count += 1

        return count