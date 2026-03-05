export type PolicyHistoryEntry = {
  policy_commitment: string;
  policy_storage_key: string;
  org_id: string;
  created_at: string;
};

const history: PolicyHistoryEntry[] = [];
const MAX_HISTORY = 500;

export function pushPolicyHistory(entry: Omit<PolicyHistoryEntry, "created_at">): void {
  const created_at = new Date().toISOString();
  history.unshift({
    ...entry,
    created_at,
  });
  if (history.length > MAX_HISTORY) {
    history.length = MAX_HISTORY;
  }
}

export function listPolicyHistory(options?: {
  limit?: number;
  offset?: number;
  org_id?: string;
}): PolicyHistoryEntry[] {
  let filtered = history;
  if (options?.org_id) {
    filtered = filtered.filter((h) => h.org_id === options.org_id);
  }
  const limit = Math.min(Math.max(1, options?.limit ?? 50), 200);
  const offset = Math.max(0, options?.offset ?? 0);
  return filtered.slice(offset, offset + limit);
}
