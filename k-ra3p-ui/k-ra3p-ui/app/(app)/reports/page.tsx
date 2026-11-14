// reports — Honest placeholder (no report generator integrated)
export default function ReportsPage() {
  return (
    <>
      <div className="page-head">
        <div>
          <h3>Reports</h3>
          <p className="b3 muted">
            Generated summaries for review and sharing.
          </p>
        </div>
      </div>
      <div className="card" style={{ padding: 24 }}>
        <h4 style={{ marginBottom: 12 }}>Report Generation</h4>
        <p className="b3 muted" style={{ marginBottom: 16 }}>
          No automated report generator is currently connected. Use the data
          available from the following live pages to build your own reports:
        </p>
        <ul
          className="b3 muted"
          style={{ paddingLeft: 20, lineHeight: "1.8em" }}
        >
          <li>
            <a href="/dashboard">Dashboard</a> — real-time statistics from{" "}
            <code>hyperledger_events.jsonl</code>.
          </li>
          <li>
            <a href="/threats/alerts">Alerts</a> — full paginated event list
            with source filter.
          </li>
          <li>
            <a href="/network/nodes">Nodes</a> — connected IPS sensor registry.
          </li>
          <li>
            <a href="/audit">Audit Log</a> — complete append-only event log.
          </li>
        </ul>
        <p className="b3 muted" style={{ marginTop: 16 }}>
          The IPS API exposes <code>GET /api/events</code> and{" "}
          <code>GET /api/stats</code> endpoints which can be consumed by
          external reporting tools.
        </p>
      </div>
    </>
  );
}
