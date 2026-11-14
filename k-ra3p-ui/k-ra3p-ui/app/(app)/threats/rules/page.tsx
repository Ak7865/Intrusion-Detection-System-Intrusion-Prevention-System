"use client";
import { useEffect, useState, useCallback } from "react";
import { fetchRules, formatTimestamp, type GeneratedRule } from "@/lib/api";

const REFRESH_MS = 20_000;

export default function RulesPage() {
  const [rules, setRules] = useState<GeneratedRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetchRules();
      setRules(res.rules);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load rules");
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
          <h3>Detection Rules</h3>
          <p className="b3 muted">
            Suricata signature rules — both sensor baselines and self-learning ML auto-generated rules.
          </p>
        </div>
      </div>

      {error && (
        <div className="card" style={{ padding: 16, marginBottom: 12 }}>
          <p style={{ color: "var(--sev-critical, #e53)" }}>⚠ {error}</p>
        </div>
      )}

      {/* Auto-Generated Rules Section */}
      <div className="card" style={{ padding: 20, marginBottom: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <div>
            <h4 style={{ margin: 0 }}>Auto-Generated Suricata Rules (Self-Learning ML)</h4>
            <p className="b3 muted" style={{ marginTop: 4 }}>
              When the ML model classifies a novel attack flow, a formal Suricata signature is synthesized, pushed to the sensor, and synced across nodes.
            </p>
          </div>
          <span className="badge sev-low">{rules.length} Generated Rules</span>
        </div>

        {loading ? (
          <p className="b3 muted" style={{ padding: 12 }}>Loading rules…</p>
        ) : rules.length === 0 ? (
          <p className="b3 muted" style={{ padding: 12, background: "var(--surface-2, #1e2130)", borderRadius: 6 }}>
            No auto-generated rules yet. Run an ML detection (e.g. <code>bash ml_dos_demo.sh</code> or <code>ml_bruteforce_demo.sh</code>) to see the rule generator synthesize new signatures.
          </p>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>SID</th>
                  <th>Attack Type</th>
                  <th>Source IP</th>
                  <th>Suricata Signature Content</th>
                  <th>Created</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.event_id + (r.rule_sid || "")}>
                    <td style={{ fontFamily: "monospace", fontWeight: 600 }}>
                      {r.rule_sid ?? "—"}
                    </td>
                    <td>
                      <span className="badge sev-high">{r.attack_type}</span>
                    </td>
                    <td style={{ fontFamily: "monospace" }}>{r.source_ip}</td>
                    <td>
                      <code style={{ fontSize: 11, background: "var(--surface-2, #1e2130)", padding: "4px 8px", borderRadius: 4, display: "block", maxWidth: 450, overflowX: "auto" }}>
                        {r.rule_content}
                      </code>
                    </td>
                    <td style={{ fontSize: 12 }}>{formatTimestamp(r.timestamp)}</td>
                    <td>
                      <span className="badge sev-low">
                        {r.rule_status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Rule Management & Architecture Guide */}
      <div className="card" style={{ padding: 20 }}>
        <h4 style={{ marginBottom: 12 }}>Self-Learning Suricata & Blockchain Pipeline</h4>
        <p className="b3 muted" style={{ marginBottom: 14 }}>
          This decentralized IPS implements a closed-loop feedback cycle between ML detection and Suricata rule enforcement:
        </p>
        <ul className="b3 muted" style={{ paddingLeft: 20, lineHeight: "1.8em" }}>
          <li>
            <strong>1. Signature Detection (Fast Path):</strong> Known attacks hit Suricata directly. Alerts are logged into <code>hyperledger_events.jsonl</code>. No new rule required.
          </li>
          <li>
            <strong>2. ML Detection (Slow Path):</strong> Traffic that bypasses Suricata signatures is scored by the ML Random Forest / XGBoost ensemble.
          </li>
          <li>
            <strong>3. Rule Synthesis:</strong> <code>suricata_rule_generator.py</code> extracts the source IP, destination port, protocol, and traffic thresholds, generating a new rule with a unique SID.
          </li>
          <li>
            <strong>4. Local Enforcement:</strong> The rule is appended to <code>/etc/suricata/rules/ips-ml-generated.rules</code> and Suricata is reloaded via <code>suricatasc</code>.
          </li>
          <li>
            <strong>5. Distributed Ledger Sync:</strong> The new rule and event are committed to Hyperledger Fabric so peer nodes synchronize and apply the rule automatically.
          </li>
        </ul>
      </div>
    </>
  );
}
