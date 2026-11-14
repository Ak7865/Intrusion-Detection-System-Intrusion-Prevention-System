// network/traffic — Traffic summary page
// CICFlowMeter flow data is submitted via POST /flow but there is no
// separate "traffic summary" endpoint in the current IPS API.
// This page shows real recent events filtered to ML-detected flows instead of fake traffic tables.
"use client";
import { useEffect, useState, useCallback } from "react";
import { fetchEvents, formatTimestamp, severityFromEvent, type IpsEvent } from "@/lib/api";

const REFRESH_MS = 30_000;

export default function TrafficPage() {
  const [events, setEvents] = useState<IpsEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      // Show ML-detected flow events (CICFlowMeter submissions)
      const res = await fetchEvents(1, 50, "ML_MODEL");
      setEvents(res.events);
      setTotal(res.total);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Backend unreachable");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  return (
    <>
      <div className="page-head">
        <div>
          <h3>Traffic Flows</h3>
          <p className="b3 muted">
            ML-analysed network flows from CICFlowMeter — {total} total ML events
          </p>
        </div>
      </div>

      <div className="card" style={{ padding: "12px 20px", marginBottom: 12 }}>
        <p className="b3 muted">
          Flows are submitted by sensor nodes via <code>POST /flow</code> after
          CICFlowMeter feature extraction. Only flows where the ML model predicts
          an attack are stored. Benign flows are not recorded.
        </p>
      </div>

      {error && (
        <div className="card" style={{ padding: 16, marginBottom: 12 }}>
          <p style={{ color: "var(--sev-critical, #e53)" }}>⚠ {error}</p>
        </div>
      )}

      <div className="card" style={{ overflowX: "auto" }}>
        {loading && events.length === 0 ? (
          <p className="b3 muted" style={{ padding: 16 }}>Loading…</p>
        ) : events.length === 0 ? (
          <p className="b3 muted" style={{ padding: 16 }}>
            No ML-detected flow events yet. Submit flows via CICFlowMeter →{" "}
            <code>POST /flow</code> to populate this view.
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Protocol</th>
                <th>Source IP</th>
                <th>Source Port</th>
                <th>Dest IP</th>
                <th>Dest Port</th>
                <th>Attack Type</th>
                <th>Confidence</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {events.map((evt) => {
                const sev = severityFromEvent(evt);
                const ml = evt.detection?.machine_learning as Record<string, unknown>;
                const conf =
                  ml?.ensemble_confidence != null
                    ? `${(Number(ml.ensemble_confidence) * 100).toFixed(1)}%`
                    : "—";
                return (
                  <tr key={evt.event_id}>
                    <td>{formatTimestamp(evt.timestamp)}</td>
                    <td>{evt.network?.protocol ?? "—"}</td>
                    <td>{evt.network?.source_ip ?? "—"}</td>
                    <td>{evt.network?.source_port ?? "—"}</td>
                    <td>{evt.network?.destination_ip ?? "—"}</td>
                    <td>{evt.network?.destination_port ?? "—"}</td>
                    <td>{evt.detection?.attack_type ?? "—"}</td>
                    <td>{conf}</td>
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

