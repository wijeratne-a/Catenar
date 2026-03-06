import { createHash } from "crypto";

export type StoredAlert = {
  id: string;
  incident_id: string;
  event: string;
  policy_commitment: string;
  domain: string;
  reason: string;
  timestamp_ns: number;
  received_at: string;
  severity?: string;
};

const alerts: StoredAlert[] = [];
const MAX_ALERTS = 2000;

function generateId(payload: { event: string; policy_commitment: string; domain: string; timestamp_ns: number }): string {
  const raw = `${payload.event}:${payload.policy_commitment}:${payload.domain}:${payload.timestamp_ns}:${Date.now()}`;
  return createHash("sha256").update(raw).digest("hex").slice(0, 24);
}

export function pushAlert(alert: Omit<StoredAlert, "id" | "received_at"> & { incident_id?: string }): StoredAlert {
  const received_at = new Date().toISOString();
  const id = generateId(alert);
  const incident_id =
    alert.incident_id ??
    `inc-${new Date().toISOString().slice(0, 10)}-${createHash("sha256").update(`${id}:${Date.now()}`).digest("hex").slice(0, 8)}`;
  const stored: StoredAlert = {
    ...alert,
    id,
    incident_id,
    received_at,
  };
  alerts.unshift(stored);
  if (alerts.length > MAX_ALERTS) {
    alerts.length = MAX_ALERTS;
  }
  return stored;
}

export function listAlerts(options?: {
  limit?: number;
  offset?: number;
  domain?: string;
}): { items: StoredAlert[]; total: number } {
  let filtered = alerts;
  if (options?.domain) {
    filtered = filtered.filter((a) => a.domain.toLowerCase().includes(options.domain!.toLowerCase()));
  }
  const total = filtered.length;
  const limit = Math.min(Math.max(1, options?.limit ?? 50), 200);
  const offset = Math.max(0, options?.offset ?? 0);
  const items = filtered.slice(offset, offset + limit);
  return { items, total };
}

export function getAlertCount(): number {
  return alerts.length;
}

export function getAlertByIncidentId(incident_id: string): StoredAlert | undefined {
  return alerts.find((a) => a.incident_id === incident_id);
}
