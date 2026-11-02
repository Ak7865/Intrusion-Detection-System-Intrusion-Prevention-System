import numpy
from scipy import stats as stat
from .context import (
    get_network_header_length,
    get_network_packet_length,
)
from .context import PacketDirection

class PacketLength:
    """This class extracts features related to the Packet Lengths.

    Attributes:
        mean_count (int): The row number.
        grand_total (float): The cummulative total of the means.

    """

    mean_count = 0
    grand_total = 0

    def __init__(self, flow):
        self.flow = flow

    def _get_direction_code(self, packet_direction):
        if packet_direction is None:
            return None

        if packet_direction == PacketDirection.FORWARD:
            return 0

        if packet_direction == PacketDirection.REVERSE:
            return 1

        return None

    def get_packet_length(self, packet_direction=None) -> list:
        """Return network-layer packet lengths for the selected direction."""

        observations = getattr(self.flow, "observations", None)

        if observations is not None:
            direction_code = self._get_direction_code(packet_direction)

            if direction_code is None:
                return list(observations.packet_lengths)

            return [
                length
                for length, direction in zip(
                    observations.packet_lengths,
                    observations.directions,
                )
                if direction == direction_code
            ]

        if packet_direction is not None:
            return [
                get_network_packet_length(packet)
                for packet, direction in self.flow.packets
                if direction == packet_direction
            ]

        return [
            get_network_packet_length(packet)
            for packet, _ in self.flow.packets
        ]



    def get_header_length(self, packet_direction=None):
        """Return network-layer header lengths for IPv4 and IPv6 packets."""

        observations = getattr(self.flow, "observations", None)

        if observations is not None:
            direction_code = self._get_direction_code(packet_direction)

            if direction_code is None:
                return list(observations.header_lengths)

            return [
                length
                for length, direction in zip(
                    observations.header_lengths,
                    observations.directions,
                )
                if direction == direction_code
            ]

        if packet_direction is not None:
            return (
                get_network_header_length(packet)
                for packet, direction in self.flow.packets
                if direction == packet_direction
            )

        return (
            get_network_header_length(packet)
            for packet, _ in self.flow.packets
        )

    def get_total_header(self, packet_direction=None) -> int:
        """Calculates the summary header lengths.

        Returns:
            packet_lengths (List[int]):

        """
        return sum(self.get_header_length(packet_direction))

    def get_min_header(self, packet_direction=None) -> int:
        """Min the summary header lengths.

        Returns:
            packet_lengths (List[int]):

        """
        return min(self.get_header_length(packet_direction))

    def get_max(self, packet_direction=None) -> int:
        """Max packet lengths in flow direction.

        Returns:
            packet_lengths (int):

        """
        try:
            return max(self.get_packet_length(packet_direction))
        except ValueError:
            return 0

    def get_min(self, packet_direction=None) -> int:
        """Min packet lengths in forward direction.

        Returns:
            packet_lengths (int):

        """
        try:
            return min(self.get_packet_length(packet_direction))
        except ValueError:
            return 0

    def get_total(self, packet_direction=None) -> int:
        """Total packet lengths by direction.

        Returns:
            packet_lengths (int):

        """
        return sum(self.get_packet_length(packet_direction))

    def get_avg(self, packet_direction=None) -> int:
        """Total packet lengths by direction.

        Returns:
            packet_lengths (int):

        """
        count = len(self.get_packet_length(packet_direction))

        if count > 0:
            return self.get_total(packet_direction) / count
        return 0

    def first_fifty(self) -> list:
        """Returns first 50 packet sizes

        Return:
            List of Packet Sizes

        """
        return self.get_packet_length()[:50]

    def get_var(self, packet_direction=None) -> float:
        """The variation of packet lengths in a network Feature.

        Returns:
            float: The variation of packet lengths.

        """
        var = 0
        if len(self.get_packet_length(packet_direction)) > 0:
            var = numpy.var(self.get_packet_length(packet_direction))
        return var

    def get_std(self, packet_direction=None) -> float:
        """The standard deviation of packet lengths in a network flow.

        Rens:
            float: The standard deviation of packet lengths.

        """
        return numpy.sqrt(self.get_var(packet_direction))

    def get_mean(self, packet_direction=None) -> float:
        """The mean of packet lengths in a network flow.

        Returns:
            float: The mean of packet lengths.

        """
        mean = 0
        if len(self.get_packet_length(packet_direction)) > 0:
            mean = numpy.mean(self.get_packet_length(packet_direction))

        return mean

    def get_median(self) -> float:
        """The median of packet lengths in a network flow.

        Returns:
            float: The median of packet lengths.

        """
        return numpy.median(self.get_packet_length())

    def get_mode(self) -> float:
        """The mode of packet lengths in a network flow.

        Returns:
            float: The mode of packet lengths.

        """
        mode = -1
        if len(self.get_packet_length()) != 0:
            mode = int(stat.mode(self.get_packet_length())[0])

        return mode

    def get_skew(self) -> float:
        """The skew of packet lengths in a network flow using the median.

        Returns:
            float: The skew of packet lengths.

        """
        mean = self.get_mean()
        median = self.get_median()
        dif = 3 * (mean - median)
        std = self.get_std()
        skew = -10

        if std != 0:
            skew = dif / std

        return skew

    def get_skew2(self) -> float:
        """The skew of the packet lengths ina network flow using the mode.

        Returns:
            float: The skew of the packet lengths.

        """
        mean = self.get_mean()
        mode = self.get_mode()
        dif = mean - mode
        std = self.get_std()
        skew2 = -10

        if std != 0:
            skew2 = dif / std

        return skew2

    def get_cov(self) -> float:
        """The coefficient of variance of packet lengths in a network flow.

        Returns:
            float: The coefficient of variance of a packet lengths list.

        """
        cov = -1
        if self.get_mean() != 0:
            cov = self.get_std() / self.get_mean()

        return cov
