"use client";
import { useEffect, useState, useCallback } from "react";
import { fetchEvents, blockIP, formatTimestamp, severityFromEvent, type IpsEvent } from "@/lib/api";

const PAGE_SIZE = 25;
const REFRESH_MS = 20_000;

export default function AlertsPage() {
  const [events, setEvents] = useState<IpsEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [filter, setFilter] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [blockMsg, setBlockMsg] = useState<string | null>(null);
  const [blocking, setBlocking] = useState<string | null>(null);

  const load = useCallback(async (p: number, dm: string) => {
    setLoading(true);
    try {
      const res = await fetchEvents(p, PAGE_SIZE, dm);
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
    load(page, filter);
    const id = setInterval(() => load(page, filter), REFRESH_MS);
    return () => clearInterval(id);
  }, [load, page, filter]);

  async function handleBlockIP(ip: string, eventId: string) {
    if (!confirm(`Block IP ${ip}? This will add it to the blocked IPs list.`)) return;
    setBlocking(ip);
    setBlockMsg(null);
    try {
      await blockIP(ip, `Blocked from alert ${eventId}`, 0);
      setBlockMsg(`✅ ${ip} blocked permanently. View in Blocked IPs page.`);
    } catch (e) {
      setBlockMsg(`❌ Failed to block ${ip}: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBlocking(null);
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <>
      <div className="page-head">
        <div>
          <h3>Alerts</h3>
          <p className="b3 muted">Live detections from Suricata and ML — {total} total events</p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <select
            value={filter}
            onChange={(e) => { setFilter(e.target.value); setPage(1); }}
            className="btn"
            style={{ padding: "6px 12px" }}
          >
            <option value="">All sources</option>
            <option value="SURICATA">Suricata only</option>
            <option value="ML_MODEL">ML only</option>
          </select>
        </div>
      </div>

      {blockMsg && (
        <div className="card" style={{ padding: 12, marginBottom: 12, background: "var(--surface-2,#1e2130)" }}>
          <p className="b3">{blockMsg}</p>
        </div>
      )}

      {error && (
        <div className="card" style={{ padding: 16, marginBottom: 12 }}>
          <p style={{ color: "var(--sev-critical, #e53)" }}>⚠ {error}</p>
        </div>
      )}

      <div className="card" style={{ overflowX: "auto" }}>
        {loading && events.length === 0 ? (
          <p className="b3 muted" style={{ padding: 16 }}>Loading…</p>
        ) : events.length === 0 ? (
          <p className="b3 muted" style={{ padding: 16 }}>No events found.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Event ID</th>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Dest IP</th>
                <th>Proto</th>
                <th>Attack Type</th>
                <th>Detection</th>
                <th>Status</th>
                <th>Confidence</th>
                <th>Severity</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {events.map((evt) => {
                const sev = severityFromEvent(evt);
                const src = evt.detection?.detection_source ?? "—";
                const srcBadge = src === "SURICATA" ? "sev-low" : src === "ML_MODEL" ? "sev-high" : "";
                const ml = evt.detection?.machine_learning as Record<string, unknown>;
                const conf = ml?.ensemble_confidence != null
                  ? `${(Number(ml.ensemble_confidence) * 100).toFixed(1)}%`
                  : "—";
                const srcIP = evt.network?.source_ip;
                return (
                  <tr key={evt.event_id}>
                    <td style={{ fontSize: 11, fontFamily: "monospace" }}>
                      {evt.event_id.slice(0, 16)}…
                    </td>
                    <td>{formatTimestamp(evt.timestamp)}</td>
                    <td style={{ fontFamily: "monospace" }}>{srcIP ?? "—"}</td>
                    <td>{evt.network?.destination_ip ?? "—"}</td>
                    <td>{evt.network?.protocol ?? "—"}</td>
                    <td>{evt.detection?.attack_type ?? "—"}</td>
                    <td><span className={`badge ${srcBadge}`}>{src}</span></td>
                    <td>{evt.detection?.classification_status ?? "—"}</td>
                    <td>{conf}</td>
                    <td><span className={`badge sev-${sev}`}>{sev}</span></td>
                    <td>
                      {srcIP && (
                        <button
                          onClick={() => handleBlockIP(srcIP, evt.event_id)}
                          disabled={blocking === srcIP}
                          title={`Block ${srcIP}`}
                          style={{
                            padding: "3px 9px", borderRadius: 5, border: "none",
                            background: "var(--sev-critical,#e53)", color: "#fff",
                            cursor: "pointer", fontSize: 11, fontWeight: 600
                          }}
                        >
                          {blocking === srcIP ? "…" : "🚫 Block"}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div style={{ display: "flex", gap: 8, marginTop: 12, alignItems: "center" }}>
          <button
            className="btn"
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >← Prev</button>
          <span className="b4 muted">Page {page} / {totalPages}</span>
          <button
            className="btn"
            disabled={page >= totalPages}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
          >Next →</button>
        </div>
      )}
    </>
  );
}

