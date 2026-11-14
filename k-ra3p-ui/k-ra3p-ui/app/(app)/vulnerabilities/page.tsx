// vulnerabilities — Honest placeholder (no scanner integrated)
export default function VulnerabilitiesPage() {
  return (
    <>
      <div className="page-head">
        <div>
          <h3>Vulnerabilities</h3>
          <p className="b3 muted">Known weaknesses on monitored hosts.</p>
        </div>
      </div>
      <div className="card" style={{ padding: 24 }}>
        <h4 style={{ marginBottom: 12 }}>Vulnerability Scanner</h4>
        <p className="b3 muted" style={{ marginBottom: 16 }}>
          No vulnerability scanner is integrated with this IPS deployment. This
          page would display CVE scan results from tools such as OpenVAS,
          Nessus, or Trivy once an integration is configured.
        </p>
        <ul className="b3 muted" style={{ paddingLeft: 20, lineHeight: "1.8em" }}>
          <li>Suricata and ML detections appear in the <a href="/threats/alerts">Alerts</a> page.</li>
          <li>Network flow analysis is in <a href="/network/traffic">Traffic</a>.</li>
          <li>All raw events are in the <a href="/audit">Audit Log</a>.</li>
        </ul>
      </div>
    </>
  );
}

