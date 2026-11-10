"""
Rolling-window traffic analyzer for the IPS project.

Consumes completed CICFlowMeter prediction records.
Monitor-only: generates alerts but never blocks traffic.

Thresholds are experimental and require calibration.
Timestamps represent inference-record creation times,
not necessarily original packet arrival times.
"""

from collections import deque
from dataclasses import dataclass
from datetime import datetime
import ipaddress
import math
from typing import Any


@dataclass(frozen=True)
class DDoSThresholds:
    source_flows_5s: int = 30
    source_packets_5s: int = 1000
    source_bytes_5s: int = 1_000_000
    destination_unique_sources_5s: int = 50
    destination_syn_packets_5s: int = 200


class RollingWindowDDoSAnalyzer:

    WINDOWS = (1, 5)

    def __init__(
        self,
        thresholds: DDoSThresholds | None = None,
        allowed_lateness_seconds: float = 2.0,
        lab_subnet: str = "192.168.56.0/24",
    ):
        if allowed_lateness_seconds < 0:
            raise ValueError("Allowed lateness cannot be negative")

        try:
            self.lab_network = ipaddress.ip_network(
                lab_subnet, strict=False
            )
        except ValueError as exc:
            raise ValueError("Invalid lab subnet") from exc

        if self.lab_network.version != 4:
            raise ValueError("Lab subnet must be IPv4")

        self.thresholds = thresholds or DDoSThresholds()
        self.events = deque()
        self.latest_timestamp = None
        self.active_alerts = set()
        self.allowed_lateness_seconds = allowed_lateness_seconds

    @staticmethod
    def _number(value: Any) -> float:
        try:
            result = float(value)
            if math.isfinite(result) and result >= 0:
                return result
        except (TypeError, ValueError):
            pass

        return 0.0

    @staticmethod
    def _timestamp(value: str) -> datetime:
        if not isinstance(value, str):
            raise ValueError("Prediction timestamp must be a string")

        timestamp = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            raise ValueError(
                "Prediction timestamp must include timezone"
            )

        return timestamp

    def _normalize(self, record: dict) -> dict:

        if not isinstance(record, dict):
            raise ValueError("Prediction record must be a dictionary")

        flow = record.get("flow") or {}
        raw = record.get("raw_features") or {}

        if not isinstance(flow, dict) or not isinstance(raw, dict):
            raise ValueError("Invalid flow or raw_features object")

        source = flow.get("src_ip") or raw.get("src_ip")
        destination = flow.get("dst_ip") or raw.get("dst_ip")

        if not source or not destination:
            raise ValueError(
                "Source IP or destination IP is missing"
            )

        try:
            source_ip = ipaddress.ip_address(str(source))
            destination_ip = ipaddress.ip_address(str(destination))
        except ValueError as exc:
            raise ValueError("Invalid source or destination IP address") from exc

        protocol = flow.get("protocol", raw.get("protocol"))
        src_port = flow.get("src_port", raw.get("src_port"))
        dst_port = flow.get("dst_port", raw.get("dst_port"))

        return {
            "timestamp": self._timestamp(record.get("timestamp")),
            "src_ip": str(source_ip),
            "dst_ip": str(destination_ip),
            "protocol": self._number(protocol),
            "src_port": self._number(src_port),
            "dst_port": self._number(dst_port),
            "packets": (
                self._number(raw.get("tot_fwd_pkts"))
                + self._number(raw.get("tot_bwd_pkts"))
            ),
            "bytes": (
                self._number(raw.get("totlen_fwd_pkts"))
                + self._number(raw.get("totlen_bwd_pkts"))
            ),
            "syn": self._number(raw.get("syn_flag_cnt")),
        }

    def _prune(self, current_time: datetime) -> None:

        cutoff = current_time.timestamp() - max(self.WINDOWS)

        while self.events:
            oldest = self.events[0]["timestamp"].timestamp()

            if oldest >= cutoff:
                break

            self.events.popleft()

    def _window_events(
        self,
        current_time: datetime,
        seconds: int,
    ) -> list[dict]:

        cutoff = current_time.timestamp() - seconds
        current = current_time.timestamp()

        return [
            event
            for event in self.events
            if cutoff < event["timestamp"].timestamp() <= current
        ]

    def _filter_reason(self, event: dict) -> str | None:
        source = ipaddress.ip_address(event["src_ip"])
        destination = ipaddress.ip_address(event["dst_ip"])

        # Exclude multicast and unspecified addresses.
        if source.is_multicast or destination.is_multicast:
            return "MULTICAST_TRAFFIC"

        if source.is_unspecified or destination.is_unspecified:
            return "UNSPECIFIED_IP"

        # Exclude limited broadcast and configured lab subnet broadcast.
        if (
            event["src_ip"] == "255.255.255.255"
            or event["dst_ip"] == "255.255.255.255"
            or event["src_ip"] == str(self.lab_network.broadcast_address)
            or event["dst_ip"] == str(self.lab_network.broadcast_address)
        ):
            return "BROADCAST_TRAFFIC"

        # DHCP client/server traffic uses UDP ports 67 and 68.
        if (
            event["protocol"] == 17
            and {event["src_port"], event["dst_port"]} == {67.0, 68.0}
        ):
            return "DHCP_TRAFFIC"

        return None

    def process_record(self, record: dict) -> dict:

        event = self._normalize(record)
        timestamp = event["timestamp"]

        filter_reason = self._filter_reason(event)

        if filter_reason:
            return {
                "status": "ignored",
                "reason": filter_reason,
                "timestamp": timestamp.isoformat(),
                "sensor_id": record.get("sensor_id", "unknown"),
                "windows": {},
                "alerts": [],
            }

        is_late = (
            self.latest_timestamp is not None
            and timestamp < self.latest_timestamp
        )

        if self.latest_timestamp is None:
            self.latest_timestamp = timestamp
            self.events.append(event)

        elif is_late:
            lateness = (
                self.latest_timestamp - timestamp
            ).total_seconds()

            if lateness > self.allowed_lateness_seconds:
                raise ValueError(
                    "Out-of-order prediction timestamp exceeds "
                    "allowed lateness"
                )

            # Insert the accepted late event chronologically.
            index = 0

            while (
                index < len(self.events)
                and self.events[index]["timestamp"] <= timestamp
            ):
                index += 1

            self.events.insert(index, event)

        else:
            self.latest_timestamp = timestamp
            self.events.append(event)

        # Always prune relative to the newest event timestamp.
        self._prune(self.latest_timestamp)

        results = {
            "timestamp": timestamp.isoformat(),
            "sensor_id": record.get("sensor_id", "unknown"),
            "windows": {},
            "alerts": [],
        }

        for seconds in self.WINDOWS:

            window = self._window_events(timestamp, seconds)

            # Aggregate source activity across ALL destinations.
            source_events = [
                item for item in window
                if item["src_ip"] == event["src_ip"]
            ]

            # Aggregate destination activity across ALL sources.
            destination_events = [
                item for item in window
                if item["dst_ip"] == event["dst_ip"]
            ]

            packet_count = sum(
                item["packets"] for item in source_events
            )

            byte_count = sum(
                item["bytes"] for item in source_events
            )

            syn_count = sum(
                item["syn"] for item in destination_events
            )

            metrics = {
                "source_ip": event["src_ip"],
                "destination_ip": event["dst_ip"],

                "source_flow_count": len(source_events),
                "source_packet_count": packet_count,
                "source_byte_count": byte_count,

                "source_packet_rate_pps": (
                    packet_count / seconds
                ),

                "source_byte_rate_bps": (
                    byte_count / seconds
                ),

                "source_unique_destinations": len({
                    item["dst_ip"] for item in source_events
                }),

                "destination_flow_count": len(destination_events),

                "destination_unique_sources": len({
                    item["src_ip"] for item in destination_events
                }),

                "destination_syn_count": syn_count,

                "destination_syn_rate_pps": (
                    syn_count / seconds
                ),
            }

            results["windows"][f"{seconds}s"] = metrics

        metrics_5s = results["windows"]["5s"]

        checks = [
            (
                "HIGH_SOURCE_FLOW_RATE",
                metrics_5s["source_flow_count"],
                self.thresholds.source_flows_5s,
            ),
            (
                "HIGH_SOURCE_PACKET_RATE",
                metrics_5s["source_packet_count"],
                self.thresholds.source_packets_5s,
            ),
            (
                "HIGH_SOURCE_BYTE_RATE",
                metrics_5s["source_byte_count"],
                self.thresholds.source_bytes_5s,
            ),
            (
                "HIGH_DESTINATION_SOURCE_DIVERSITY",
                metrics_5s["destination_unique_sources"],
                self.thresholds.destination_unique_sources_5s,
            ),
            (
                "HIGH_DESTINATION_SYN_ACTIVITY",
                metrics_5s["destination_syn_count"],
                self.thresholds.destination_syn_packets_5s,
            ),
        ]

        for alert_type, observed, threshold in checks:

            # Late records update history but cannot change alert state.
            if is_late:
                continue

            if alert_type.startswith("HIGH_SOURCE_"):
                scope_ip = event["src_ip"]
                scope_type = "source"
            else:
                scope_ip = event["dst_ip"]
                scope_type = "destination"

            alert_key = (alert_type, scope_ip)

            if observed >= threshold:

                # Emit only when this condition becomes active.
                if alert_key not in self.active_alerts:
                    results["alerts"].append({
                        "alert_type": alert_type,
                        "severity": "experimental",
                        "source_ip": (
                            event["src_ip"]
                            if scope_type == "source"
                            else None
                        ),
                        "destination_ip": (
                            event["dst_ip"]
                            if scope_type == "destination"
                            else None
                        ),
                        "observed_value": observed,
                        "threshold": threshold,
                        "window_seconds": 5,
                        "action": "MONITOR_ONLY",
                    })

                self.active_alerts.add(alert_key)

            else:
                # Rearm after the condition falls below threshold.
                self.active_alerts.discard(alert_key)

        return results
