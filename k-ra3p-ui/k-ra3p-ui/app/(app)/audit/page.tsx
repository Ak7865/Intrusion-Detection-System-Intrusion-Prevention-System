// audit — Tamper-evident event log (real data from JSONL)
"use client";
import { useEffect, useState, useCallback } from "react";
import { fetchEvents, clearEvents, formatTimestamp, type IpsEvent } from "@/lib/api";

const PAGE_SIZE = 50;
const REFRESH_MS = 30_000;

export default function AuditPage() {
  const [events, setEvents] = useState<IpsEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [clearing, setClearing] = useState(false);
  const [clearMsg, setClearMsg] = useState<string | null>(null);

  const load = useCallback(
    async (p: number) => {
      setLoading(true);
      try {
        const res = await fetchEvents(p, PAGE_SIZE, "");
        setEvents(res.events);
        setTotal(res.total);
        setError(null);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Backend unreachable");
      } finally {
        setLoading(false);
      }
    },
    []
  );

  useEffect(() => {
    load(page);
    const id = setInterval(() => load(page), REFRESH_MS);
    return () => clearInterval(id);
  }, [load, page]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  async function handleClearEvents() {
    if (!confirm("⚠️ Clear ALL events from hyperledger_events.jsonl?\n\nOnly do this during testing. This cannot be undone.")) return;
    setClearing(true);
    setClearMsg(null);
    try {
      const res = await clearEvents();
      setClearMsg(`✅ Cleared ${res.events_removed} events. Log is now empty.`);
      setPage(1);
      await load(1);
    } catch (e) {
      setClearMsg(`❌ Failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setClearing(false);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h3>Audit Log</h3>
          <p className="b3 muted">
            Append-only event record from{" "}
            <code>runtime/events/hyperledger_events.jsonl</code> — {total} entries
          </p>
        </div>
        <div>
          <button
            onClick={handleClearEvents}
            disabled={clearing || total === 0}
            style={{
              padding: "7px 14px", borderRadius: 6, border: "none",
              background: total === 0 ? "var(--surface-2,#1e2130)" : "var(--sev-critical,#e53)",
              color: total === 0 ? "var(--muted,#888)" : "#fff",
              cursor: clearing || total === 0 ? "not-allowed" : "pointer",
              fontSize: 12, fontWeight: 600
            }}
            title="Testing only — clears hyperledger_events.jsonl"
          >
            {clearing ? "Clearing…" : "🗑 Clear All Events (Testing Only)"}
          </button>
        </div>
      </div>

      {clearMsg && (
        <div className="card" style={{ padding: 12, marginBottom: 12, background: "var(--surface-2,#1e2130)" }}>
          <p className="b3">{clearMsg}</p>
        </div>
      )}

      <div
        className="card"
        style={{ padding: "12px 20px", marginBottom: 12, borderLeft: "3px solid var(--sev-low, #3c3)" }}
      >
        <p className="b3 muted">
          <strong>Storage:</strong> Events are stored append-only in{" "}
          <code>hyperledger_events.jsonl</code>. Blockchain submission is{" "}
          <strong>PENDING_NOT_SUBMITTED</strong> — no Hyperledger network is
          currently configured. Each event ID is a UUID generated at detection
          time and is unique within this file.
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
          <p className="b3 muted" style={{ padding: 16 }}>No events yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Event ID</th>
                <th>Timestamp</th>
                <th>Detection Source</th>
                <th>Attack Type</th>
                <th>Source IP</th>
                <th>Blockchain</th>
              </tr>
            </thead>
            <tbody>
              {events.map((evt, idx) => {
                const src = evt.detection?.detection_source ?? "—";
                const srcBadge =
                  src === "SURICATA"
                    ? "sev-low"
                    : src === "ML_MODEL"
                    ? "sev-high"
                    : "";
                const offset = (page - 1) * PAGE_SIZE;
                return (
                  <tr key={evt.event_id}>
                    <td style={{ color: "var(--muted)", fontSize: 11 }}>
                      {total - offset - idx}
                    </td>
                    <td style={{ fontSize: 10, fontFamily: "monospace" }}>
                      {evt.event_id.slice(0, 20)}…
                    </td>
                    <td>{formatTimestamp(evt.timestamp)}</td>
                    <td>
                      <span className={`badge ${srcBadge}`}>{src}</span>
                    </td>
                    <td>{evt.detection?.attack_type ?? "—"}</td>
                    <td>{evt.network?.source_ip ?? "—"}</td>
                    <td>
                      <span className="badge">PENDING</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {totalPages > 1 && (
        <div style={{ display: "flex", gap: 8, marginTop: 12, alignItems: "center" }}>
          <button
            className="btn"
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            ← Prev
          </button>
          <span className="b4 muted">
            Page {page} / {totalPages}
          </span>
          <button
            className="btn"
            disabled={page >= totalPages}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
          >
            Next →
          </button>
        </div>
      )}
    </>
  );
}

