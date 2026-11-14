// IPS Backend API client
// All reads go through the Next.js /api/* proxy to avoid CORS issues when
// the Next.js dev server and the Python API run on different ports.

export const IPS_API_BASE =
  process.env.NEXT_PUBLIC_IPS_API_URL || "http://192.168.56.1:8765";

// ── Types ──────────────────────────────────────────────────────────────────────

export type Detection = {
  detection_source: "SURICATA" | "ML_MODEL" | string;
  attack_detected: boolean;
  classification_status: string;
  classification_basis: string;
  attack_type: string | null;
  suricata: Record<string, unknown>;
  machine_learning: Record<string, unknown>;
};

export type Network = {
  source_ip: string | null;
  source_port: number | null;
  destination_ip: string | null;
  destination_port: number | null;
  protocol: string | null;
};

export type IpsEvent = {
  schema_version: string;
  event_id: string;
  event_type: string;
  timestamp: string;
  organisation: { organisation_id: string; organisation_name: string; node_id: string };
  detection: Detection;
  network: Network;
  response: { recommended_action: string; actual_block_status: string };
  evidence: Record<string, unknown>;
};

export type StatsResponse = {
  total_events: number;
  suricata_detections: number;
  ml_detections: number;
  informational_alerts: number;
  events_requiring_review: number;
  attack_events: number;
  active_nodes: number;
  recent_events: IpsEvent[];
};

export type EventsResponse = {
  total: number;
  page: number;
  page_size: number;
  events: IpsEvent[];
};

export type NodeInfo = {
  node_id: string;
  status: string;
  last_heartbeat: string;
  first_seen: string;
  role: string;
  approval_status: "APPROVED" | "PENDING_APPROVAL" | "REJECTED";
  required_approvals: number;
  received_approvals: string[];
  join_requested_at?: string;
};

export interface BlockedIP {
  ip: string;
  reason: string;
  blocked_at: string;
  blocked_by: string;
  expires_at: string | null;
}

export type NodesResponse = {
  nodes: NodeInfo[];
  total: number;
};

// ── Fetch helpers ──────────────────────────────────────────────────────────────

async function apiFetch<T>(path: string): Promise<T> {
  const url = `/api/ips${path}`;
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`IPS API ${path} → ${res.status}`);
  return res.json() as Promise<T>;
}

export async function fetchStats(): Promise<StatsResponse> {
  return apiFetch<StatsResponse>("/stats");
}

export async function fetchEvents(
  page = 1,
  pageSize = 50,
  detectionMethod = ""
): Promise<EventsResponse> {
  const qs = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize),
    ...(detectionMethod ? { detection_method: detectionMethod } : {}),
  });
  return apiFetch<EventsResponse>(`/events?${qs}`);
}

export async function fetchNodes(): Promise<NodesResponse> {
  return apiFetch<NodesResponse>("/nodes");
}

export async function fetchHealth(): Promise<Record<string, unknown>> {
  return apiFetch<Record<string, unknown>>("/health");
}

async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const url = `/api/ips${path}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`IPS API POST ${path} → ${res.status}`);
  return res.json() as Promise<T>;
}

export async function blockIP(ip: string, reason: string, duration_minutes = 0): Promise<void> {
  await apiPost<unknown>("/block", { ip, reason, duration_minutes });
}

export async function unblockIP(ip: string): Promise<void> {
  await apiPost<unknown>("/unblock", { ip });
}

export async function fetchBlockedIPs(): Promise<{ blocked_ips: BlockedIP[]; total: number }> {
  return apiFetch<{ blocked_ips: BlockedIP[]; total: number }>("/blocked");
}

export async function approveNode(node_id: string): Promise<unknown> {
  return apiPost<unknown>("/nodes/approve", { node_id, approved_by: "ADMIN" });
}

export async function rejectNode(node_id: string): Promise<unknown> {
  return apiPost<unknown>("/nodes/reject", { node_id });
}

export async function clearEvents(): Promise<{ status: string; events_removed: number }> {
  return apiPost<{ status: string; events_removed: number }>("/events/clear", {});
}

// ── Formatting helpers ─────────────────────────────────────────────────────────

export function formatTimestamp(ts: string): string {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

export function severityFromEvent(evt: IpsEvent): string {
  const sev = (evt.detection?.suricata as Record<string, unknown>)?.severity;
  if (sev === 1) return "critical";
  if (sev === 2) return "high";
  if (sev === 3) return "medium";
  const status = evt.detection?.classification_status ?? "";
  if (status === "MODEL_PREDICTED") return "high";
  if (status === "INFORMATIONAL") return "low";
  // Legacy events (pre-classification_status) default to medium
  return "medium";
}

