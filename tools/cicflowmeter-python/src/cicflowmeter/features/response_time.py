import numpy
from scipy import stats as stat


class ResponseTime:
    """Extract response-time statistics from compact flow observations."""

    def __init__(self, flow):
        self.flow = flow

    def get_dif(self) -> list:
        """Return forward-to-reverse packet response-time differences."""

        observations = getattr(self.flow, "observations", None)

        if observations is not None:
            return list(observations.response_times)

        # Backward-compatible implementation.
        from .context import PacketDirection

        time_diff = []
        temp_packet = None
        temp_direction = None

        for packet, direction in self.flow.packets:
            if (
                temp_direction == PacketDirection.FORWARD
                and direction == PacketDirection.REVERSE
            ):
                time_diff.append(
                    float(packet.time - temp_packet.time)
                )

            temp_packet = packet
            temp_direction = direction

        return time_diff

    def get_var(self) -> float:
        differences = self.get_dif()

        if not differences:
            return -1

        return numpy.var(differences)

    def get_mean(self) -> float:
        differences = self.get_dif()

        if not differences:
            return -1

        return numpy.mean(differences)

    def get_median(self) -> float:
        return numpy.median(self.get_dif())

    def get_mode(self) -> float:
        differences = self.get_dif()

        if not differences:
            return -1

        return float(stat.mode(differences)[0])

    def get_std(self) -> float:
        differences = self.get_dif()

        if not differences:
            return -1

        return numpy.sqrt(numpy.var(differences))

    def get_skew(self) -> float:
        mean = self.get_mean()
        median = self.get_median()
        std = self.get_std()

        if std <= 0:
            return -10

        return 3 * (mean - median) / std

    def get_skew2(self) -> float:
        mean = self.get_mean()
        mode = self.get_mode()
        std = self.get_std()

        if std <= 0:
            return -10

        return (float(mean) - mode) / float(std)

    def get_cov(self) -> float:
        mean = self.get_mean()

        if mean == 0:
            return -1

        return self.get_std() / mean