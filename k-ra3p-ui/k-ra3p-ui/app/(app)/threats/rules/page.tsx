// threats/rules — Detection rules page
// Rules are managed by Suricata on the sensor nodes and not exposed via the
// current IPS API.  This page explains that honestly instead of showing fake data.
export default function RulesPage() {
  return (
    <>
      <div className="page-head">
        <div>
          <h3>Detection Rules</h3>
          <p className="b3 muted">
            Suricata signature rules deployed on IPS sensor nodes.
          </p>
        </div>
      </div>

      <div className="card" style={{ padding: 24 }}>
        <h4 style={{ marginBottom: 12 }}>Rule Management</h4>
        <p className="b3 muted" style={{ marginBottom: 16 }}>
          Detection rules are Suricata <code>.rules</code> files managed
          directly on each sensor node. The current IPS API does not expose a
          rule-management endpoint, so live rule data cannot be displayed here.
        </p>
        <ul
          className="b3 muted"
          style={{ paddingLeft: 20, lineHeight: "1.8em" }}
        >
          <li>
            Suricata rules live at{" "}
            <code>/etc/suricata/rules/</code> on each Linux sensor.
          </li>
          <li>
            The <code>eve_forwarder.py</code> script reads Suricata EVE JSON and
            forwards matched alerts to this API automatically.
          </li>
          <li>
            New rules can be added by editing <code>local.rules</code> on the
            sensor and reloading Suricata with{" "}
            <code>suricata-update && systemctl reload suricata</code>.
          </li>
          <li>
            All Suricata alerts appear in the{" "}
            <a href="/threats/alerts">Alerts</a> page once forwarded.
          </li>
        </ul>
      </div>

      <div
        className="card"
        style={{ padding: 16, marginTop: 12, borderLeft: "3px solid var(--sev-high, #f80)" }}
      >
        <p className="b3 muted">
          <strong>Planned:</strong> A future API extension will allow reading
          deployed rule counts and status from connected nodes. This page will be
          updated when that endpoint is available.
        </p>
      </div>
    </>
  );
}

