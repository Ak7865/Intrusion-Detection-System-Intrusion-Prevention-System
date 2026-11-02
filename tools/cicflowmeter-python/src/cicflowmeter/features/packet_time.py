from datetime import datetime

import numpy
from scipy import stats as stat

from .context import PacketDirection


class PacketTime:
    """Extract features related to packet timestamps."""

    count = 0

    def __init__(self, flow):
        self.flow = flow
        PacketTime.count += 1
        self.packet_times = None

    def _get_packet_times(self):
        """Return packet timestamps relative to the first packet."""

        if self.packet_times is not None:
            return self.packet_times

        observations = getattr(self.flow, "observations", None)

        if observations is not None:
            return list(observations.timestamps)

        first_packet_time = self.flow.packets[0][0].time

        return [
            float(packet.time - first_packet_time)
            for packet, _ in self.flow.packets
        ]

    def get_packet_iat(self, packet_direction=None):
        """Return positive inter-arrival times in capture order."""

        observations = getattr(self.flow, "observations", None)

        if observations is not None:
            if packet_direction == PacketDirection.FORWARD:
                return list(observations.forward_iats)

            if packet_direction == PacketDirection.REVERSE:
                return list(observations.backward_iats)

            if packet_direction is None:
                packets = list(observations.timestamps)
            else:
                raise ValueError(
                    f"Unsupported packet direction: {packet_direction}"
                )

            return [
                float(packets[index] - packets[index - 1])
                for index in range(1, len(packets))
                if packets[index] > packets[index - 1]
            ]

        if packet_direction is not None:
            packets = [
                packet
                for packet, direction in self.flow.packets
                if direction == packet_direction
            ]
        else:
            packets = [
                packet for packet, _ in self.flow.packets
            ]

        return [
            float(packets[index].time - packets[index - 1].time)
            for index in range(1, len(packets))
            if packets[index].time > packets[index - 1].time
        ]

    def relative_time_list(self):
        """Return relative time differences between captured packets."""

        packet_times = self._get_packet_times()

        relative_time_list = []

        for index, timestamp in enumerate(packet_times):
            if index == 0:
                relative_time_list.append(0)
            elif index < len(packet_times):
                relative_time_list.append(
                    float(timestamp - packet_times[index - 1])
                )
            elif index < 50:
                relative_time_list.append(0)
            else:
                break

        return relative_time_list

    def get_timestamp(self):
        """Return the first packet timestamp in readable format."""

        observations = getattr(self.flow, "observations", None)

        if observations is not None:
            timestamp = float(observations.first_timestamp)
        else:
            timestamp = float(self.flow.packets[0][0].time)

        return datetime.fromtimestamp(timestamp).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    def get_duration(self):
        """Return maximum relative timestamp, preserving regression handling."""

        packet_times = self._get_packet_times()

        if not packet_times:
            return 0

        return max(packet_times)

    def get_var(self):
        """Calculate variance of relative packet timestamps."""

        return numpy.var(self._get_packet_times())

    def get_std(self):
        """Calculate standard deviation of relative packet timestamps."""

        return numpy.sqrt(self.get_var())

    def get_mean(self):
        """Calculate mean of relative packet timestamps."""

        packet_times = self._get_packet_times()

        if len(packet_times) == 0:
            return 0

        return numpy.mean(packet_times)

    def get_median(self):
        """Calculate median of relative packet timestamps."""

        return numpy.median(self._get_packet_times())

    def get_mode(self):
        """Calculate mode of relative packet timestamps."""

        packet_times = self._get_packet_times()

        if len(packet_times) == 0:
            return -1

        mode = stat.mode(packet_times)

        return float(mode[0])

    def get_skew(self):
        """Calculate skew using the median."""

        mean = self.get_mean()
        median = self.get_median()
        difference = 3 * (mean - median)
        std = self.get_std()

        if std == 0:
            return -10

        return difference / std

    def get_skew2(self):
        """Calculate skew using the mode."""

        mean = self.get_mean()
        mode = self.get_mode()
        difference = float(mean) - mode
        std = self.get_std()

        if std == 0:
            return -10

        return difference / float(std)

    def get_cov(self):
        """Calculate coefficient of variation."""

        mean = self.get_mean()

        if mean == 0:
            return -1

        return self.get_std() / mean