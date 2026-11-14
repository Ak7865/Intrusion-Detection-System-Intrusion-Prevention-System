"use client";
import { useEffect, useState, useCallback } from "react";
import { fetchBlockedIPs, blockIP, unblockIP, formatTimestamp, type BlockedIP } from "@/lib/api";

const REFRESH_MS = 30_000;

const DURATION_OPTIONS = [
  { label: "Permanent", value: 0 },
  { label: "1 hour",    value: 60 },
  { label: "6 hours",   value: 360 },
  { label: "24 hours",  value: 1440 },
];

export default function BlockedPage() {
  const [blocked, setBlocked]   = useState<BlockedIP[]>([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState<string | null>(null);
  const [msg, setMsg]           = useState<string | null>(null);
  const [acting, setActing]     = useState<string | null>(null);

  // Block form state
  const [formIP, setFormIP]         = useState("");
  const [formReason, setFormReason] = useState("");
  const [formDuration, setFormDuration] = useState(0);
  const [formBusy, setFormBusy]     = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await fetchBlockedIPs();
      setBlocked(res.blocked_ips);
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

  async function handleUnblock(ip: string) {
    if (!confirm(`Unblock ${ip}?`)) return;
    setActing(ip);
    setMsg(null);
    try {
      await unblockIP(ip);
      setMsg(`✅ ${ip} unblocked.`);
      await load();
    } catch (e) {
      setMsg(`❌ Failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setActing(null);
    }
  }

  async function handleBlock(e: React.FormEvent) {
    e.preventDefault();
    const ip = formIP.trim();
    const reason = formReason.trim() || "Manually blocked by admin";
    if (!ip) { setMsg("❌ IP address is required."); return; }
    setFormBusy(true);
    setMsg(null);
    try {
      await blockIP(ip, reason, formDuration);
      setMsg(`✅ ${ip} blocked${formDuration ? ` for ${formDuration} min` : " permanently"}.`);
      setFormIP("");
      setFormReason("");
      setFormDuration(0);
      await load();
    } catch (err) {
      setMsg(`❌ Failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setFormBusy(false);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h3>Blocked IPs</h3>
          <p className="b3 muted">
            Temporarily or permanently blocked IP addresses. Block IPs from alert events
            or add them manually here.
          </p>
        </div>
      </div>

      {msg && (
        <div className="card" style={{ padding: 12, marginBottom: 12, background: "var(--surface-2,#1e2130)" }}>
          <p className="b3">{msg}</p>
        </div>
      )}

      {/* Block IP form */}
      <div className="card" style={{ padding: 16, marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>Block an IP Address</h4>
        <form onSubmit={handleBlock} style={{ display: "flex", flexWrap: "wrap", gap: 10, alignItems: "flex-end" }}>
          <div>
            <label className="b3 muted" style={{ display: "block", marginBottom: 4 }}>IP Address *</label>
            <input
              value={formIP} onChange={(e) => setFormIP(e.target.value)}
              placeholder="e.g. 192.168.56.129"
              style={{
                padding: "6px 10px", borderRadius: 6, border: "1px solid var(--border,#333)",
                background: "var(--surface-2,#1e2130)", color: "inherit", width: 180
              }}
            />
          </div>
          <div>
            <label className="b3 muted" style={{ display: "block", marginBottom: 4 }}>Reason</label>
            <input
              value={formReason} onChange={(e) => setFormReason(e.target.value)}
              placeholder="e.g. DoS attack detected"
              style={{
                padding: "6px 10px", borderRadius: 6, border: "1px solid var(--border,#333)",
                background: "var(--surface-2,#1e2130)", color: "inherit", width: 220
              }}
            />
          </div>
          <div>
            <label className="b3 muted" style={{ display: "block", marginBottom: 4 }}>Duration</label>
            <select
              value={formDuration} onChange={(e) => setFormDuration(Number(e.target.value))}
              style={{
                padding: "6px 10px", borderRadius: 6, border: "1px solid var(--border,#333)",
                background: "var(--surface-2,#1e2130)", color: "inherit"
              }}
            >
              {DURATION_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
          <button
            type="submit" disabled={formBusy}
            style={{
              padding: "7px 18px", borderRadius: 6, border: "none",
              background: "var(--sev-critical,#e53)", color: "#fff",
              cursor: formBusy ? "not-allowed" : "pointer", fontWeight: 600
            }}
          >
            {formBusy ? "Blocking…" : "🚫 Block IP"}
          </button>
        </form>
      </div>

      {error && (
        <div className="card" style={{ padding: 16, marginBottom: 12 }}>
          <p style={{ color: "var(--sev-critical,#e53)" }}>⚠ {error}</p>
        </div>
      )}

      <div className="card" style={{ overflowX: "auto" }}>
        {loading ? (
          <p className="b3 muted" style={{ padding: 16 }}>Loading…</p>
        ) : blocked.length === 0 ? (
          <p className="b3 muted" style={{ padding: 16 }}>
            No IPs are currently blocked. Block IPs from the Alerts page or using the form above.
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Reason</th>
                <th>Blocked By</th>
                <th>Blocked At</th>
                <th>Expires</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {blocked.map((b) => (
                <tr key={b.ip}>
                  <td style={{ fontFamily: "monospace", fontWeight: 600, color: "var(--sev-critical,#e53)" }}>
                    {b.ip}
                  </td>
                  <td>{b.reason}</td>
                  <td>{b.blocked_by}</td>
                  <td>{formatTimestamp(b.blocked_at)}</td>
                  <td>{b.expires_at ? formatTimestamp(b.expires_at) : <span className="badge sev-critical">Permanent</span>}</td>
                  <td>
                    <button
                      onClick={() => handleUnblock(b.ip)}
                      disabled={acting === b.ip}
                      style={{
                        padding: "4px 12px", borderRadius: 6, border: "none",
                        background: "var(--sev-low,#2a5)", color: "#fff",
                        cursor: "pointer", fontSize: 12, fontWeight: 600
                      }}
                    >
                      {acting === b.ip ? "…" : "✓ Unblock"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
