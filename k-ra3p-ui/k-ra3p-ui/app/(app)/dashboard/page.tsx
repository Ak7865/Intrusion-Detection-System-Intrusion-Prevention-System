const stats = [["Active threats", "12"], ["Blocked today", "1,284"], ["Nodes online", "8 / 8"], ["Rules deployed", "46"]];
const rows = [
  ["10:42", "SSH brute force", "203.0.113.24", "node-2", "critical"],
  ["10:31", "Port scan", "198.51.100.7", "node-1", "high"],
  ["10:05", "Suspicious DNS query", "192.0.2.88", "node-4", "low"],
  ["09:48", "SQL injection attempt", "203.0.113.90", "node-3", "critical"],
];
export default function Dashboard() {
  return (
    <>
      <h3>Dashboard</h3>
      <div className="grid4">
        {stats.map(([l, v]) => <div key={l} className="card stat"><span className="b4 muted">{l}</span><strong>{v}</strong></div>)}
      </div>
      <div className="card">
        <h4 style={{ padding: "16px 20px" }}>Recent activity</h4>
        <table>
          <thead><tr><th>Time</th><th>Event</th><th>Source IP</th><th>Node</th><th>Severity</th></tr></thead>
          <tbody>{rows.map((r) => <tr key={r[0]}>{r.slice(0, 4).map((c, i) => <td key={i}>{c}</td>)}<td><span className={`badge sev-${r[4]}`}>{r[4]}</span></td></tr>)}</tbody>
        </table>
      </div>
    </>
  );
}
