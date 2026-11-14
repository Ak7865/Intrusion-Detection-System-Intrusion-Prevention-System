"use client";
import { useEffect, useState, useCallback } from "react";
import {
  fetchStats,
  formatTimestamp,
  severityFromEvent,
  type StatsResponse,
} from "@/lib/api";

const REFRESH_MS = 15_000;

export default function Dashboard() {
  const [data, setData] = useState<StatsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const stats = await fetchStats();
      setData(stats);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to reach IPS backend");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  if (loading) return <p className="muted">Loading dashboard…</p>;

  if (error)
    return (
      <div className="card" style={{ padding: 20 }}>
        <p style={{ color: "var(--sev-critical, #e53)" }}>⚠ Backend unreachable: {error}</p>
        <p className="b3 muted">
          Ensure the IPS API is running on 192.168.56.1:8765 and try again.
        </p>
      </div>
    );

  const stats = [
    ["Total Events", data!.total_events.toString()],
    ["Attack Events", data!.attack_events.toString()],
    ["Suricata Detections", data!.suricata_detections.toString()],
    ["ML Detections", data!.ml_detections.toString()],
    ["Informational", data!.informational_alerts.toString()],
    ["Requires Review", data!.events_requiring_review.toString()],
    ["Active Nodes", data!.active_nodes.toString()],
  ];

  const recent = data!.recent_events;

  return (
    <>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h3>Dashboard</h3>
        <span className="b4 muted" style={{ fontSize: 12 }}>
          Auto-refresh every {REFRESH_MS / 1000}s
        </span>
      </div>

      <div className="grid4">
        {stats.map(([l, v]) => (
          <div key={l} className="card stat">
            <span className="b4 muted">{l}</span>
            <strong>{v}</strong>
          </div>
        ))}
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <h4 style={{ padding: "16px 20px" }}>
          Recent activity
          <span className="b4 muted" style={{ marginLeft: 8, fontWeight: 400, fontSize: 12 }}>
            (live from hyperledger_events.jsonl)
          </span>
        </h4>
        {recent.length === 0 ? (
          <p className="b3 muted" style={{ padding: "0 20px 16px" }}>
            No events yet. Start the IPS backend and trigger some traffic.
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Attack Type</th>
                <th>Source IP</th>
                <th>Dest IP</th>
                <th>Detection</th>
                <th>Status</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((evt) => {
                const sev = severityFromEvent(evt);
                const src = evt.detection?.detection_source ?? "—";
                const badge = src === "SURICATA" ? "sev-low" : src === "ML_MODEL" ? "sev-high" : "";
                const status = evt.detection?.classification_status ?? "—";
                return (
                  <tr key={evt.event_id}>
                    <td>{formatTimestamp(evt.timestamp)}</td>
                    <td>{evt.detection?.attack_type ?? "—"}</td>
                    <td>{evt.network?.source_ip ?? "—"}</td>
                    <td>{evt.network?.destination_ip ?? "—"}</td>
                    <td>
                      <span className={`badge ${badge}`}>{src}</span>
                    </td>
                    <td>{status}</td>
                    <td>
                      <span className={`badge sev-${sev}`}>{sev}</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
