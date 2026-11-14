"use client";
import { useEffect, useState, useCallback } from "react";
import {
  fetchNodes,
  approveNode,
  rejectNode,
  formatTimestamp,
  type NodeInfo,
} from "@/lib/api";

const REFRESH_MS = 15_000;

function ApprovalBadge({ node }: { node: NodeInfo }) {
  const status = node.approval_status ?? "APPROVED";
  if (status === "APPROVED")
    return <span className="badge sev-low">APPROVED</span>;
  if (status === "REJECTED")
    return <span className="badge sev-critical">REJECTED</span>;
  const recv = node.received_approvals?.length ?? 0;
  const req = node.required_approvals ?? 1;
  return (
    <span className="badge sev-high">
      PENDING ({recv}/{req} approvals)
    </span>
  );
}

export default function NodesPage() {
  const [nodes, setNodes] = useState<NodeInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [acting, setActing] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetchNodes();
      setNodes(res.nodes);
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

  async function handleApprove(nodeId: string) {
    setActing(nodeId);
    setMsg(null);
    try {
      const res = (await approveNode(nodeId)) as {
        status: string;
        received?: number;
        required?: number;
      };
      if (res.status === "approved") {
        setMsg(`✅ ${nodeId} approved and joined the network.`);
      } else if (res.status === "pending_more_approvals") {
        setMsg(
          `⏳ Approval recorded (${res.received}/${res.required}). Waiting for more approvals.`,
        );
      } else {
        setMsg(`ℹ️ ${nodeId}: ${res.status}`);
      }
      await load();
    } catch (e) {
      setMsg(`❌ Failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setActing(null);
    }
  }

  async function handleReject(nodeId: string) {
    if (!confirm(`Reject node ${nodeId}? This will deny its join request.`))
      return;
    setActing(nodeId);
    setMsg(null);
    try {
      await rejectNode(nodeId);
      setMsg(`🚫 ${nodeId} rejected.`);
      await load();
    } catch (e) {
      setMsg(`❌ Failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setActing(null);
    }
  }

  const pending = nodes.filter((n) => n.approval_status === "PENDING_APPROVAL");

  return (
    <>
      <div className="page-head">
        <div>
          <h3>IPS Nodes</h3>
          <p className="b3 muted">
            Connected sensor nodes. First node is auto-approved; subsequent
            nodes require unanimous approval from all existing nodes.
          </p>
        </div>
      </div>

      {msg && (
        <div
          className="card"
          style={{
            padding: 12,
            marginBottom: 12,
            background: "var(--surface-2,#1e2130)",
          }}
        >
          <p className="b3">{msg}</p>
        </div>
      )}

      {error && (
        <div className="card" style={{ padding: 16, marginBottom: 12 }}>
          <p style={{ color: "var(--sev-critical, #e53)" }}>⚠ {error}</p>
        </div>
      )}

      {/* Pending approval banner */}
      {pending.length > 0 && (
        <div
          className="card"
          style={{
            padding: 14,
            marginBottom: 12,
            border: "1px solid var(--sev-high, #f90)",
            background: "rgba(255,153,0,0.07)",
          }}
        >
          <p
            className="b3"
            style={{ color: "var(--sev-high,#f90)", fontWeight: 600 }}
          >
            🔔 {pending.length} node{pending.length > 1 ? "s" : ""} waiting for
            join approval
          </p>
          <p className="b3 muted" style={{ marginTop: 4 }}>
            Use the Approve / Reject buttons below. All existing approved nodes
            must approve.
          </p>
        </div>
      )}

      <div className="card" style={{ overflowX: "auto" }}>
        {loading ? (
          <p className="b3 muted" style={{ padding: 16 }}>
            Loading…
          </p>
        ) : nodes.length === 0 ? (
          <p className="b3 muted" style={{ padding: 16 }}>
            No nodes connected yet. Run{" "}
            <code>bash /mnt/hgfs/IPS-Project/start.sh</code> on a sensor node.
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Node ID</th>
                <th>Role</th>
                <th>Approval</th>
                <th>Online</th>
                <th>First Seen</th>
                <th>Last Heartbeat</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {nodes.map((n) => (
                <tr key={n.node_id}>
                  <td style={{ fontFamily: "monospace", fontWeight: 600 }}>
                    {n.node_id}
                  </td>
                  <td>{n.role}</td>
                  <td>
                    <ApprovalBadge node={n} />
                  </td>
                  <td>
                    <span
                      className={`badge ${n.status === "online" ? "sev-low" : "sev-critical"}`}
                    >
                      {n.status}
                    </span>
                  </td>
                  <td>{formatTimestamp(n.first_seen)}</td>
                  <td>{formatTimestamp(n.last_heartbeat)}</td>
                  <td>
                    {n.approval_status === "PENDING_APPROVAL" && (
                      <span style={{ display: "flex", gap: 6 }}>
                        <button
                          onClick={() => handleApprove(n.node_id)}
                          disabled={acting === n.node_id}
                          style={{
                            padding: "4px 10px",
                            borderRadius: 6,
                            border: "none",
                            background: "var(--sev-low,#2a5)",
                            color: "#fff",
                            cursor: "pointer",
                            fontSize: 12,
                            fontWeight: 600,
                          }}
                        >
                          {acting === n.node_id ? "…" : "✓ Approve"}
                        </button>
                        <button
                          onClick={() => handleReject(n.node_id)}
                          disabled={acting === n.node_id}
                          style={{
                            padding: "4px 10px",
                            borderRadius: 6,
                            border: "none",
                            background: "var(--sev-critical,#e53)",
                            color: "#fff",
                            cursor: "pointer",
                            fontSize: 12,
                            fontWeight: 600,
                          }}
                        >
                          ✗ Reject
                        </button>
                      </span>
                    )}
                    {n.approval_status === "APPROVED" && (
                      <span className="b3 muted">—</span>
                    )}
                    {n.approval_status === "REJECTED" && (
                      <button
                        onClick={() => handleApprove(n.node_id)}
                        disabled={acting === n.node_id}
                        style={{
                          padding: "4px 10px",
                          borderRadius: 6,
                          border: "none",
                          background: "var(--sev-low,#2a5)",
                          color: "#fff",
                          cursor: "pointer",
                          fontSize: 12,
                        }}
                      >
                        Re-approve
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card" style={{ padding: 14, marginTop: 12 }}>
        <p className="b3 muted">
          <strong>Approval rules:</strong> The first node to connect is
          auto-approved. A second node needs approval from the 1 existing node.
          A third node needs approval from both existing 2 nodes.
        </p>
      </div>
    </>
  );
}
