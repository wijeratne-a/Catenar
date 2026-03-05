/** TypeScript interfaces mirroring verifier/src/schema.rs */

export interface AgentMetadata {
  domain: string;
  version: string;
}

export interface TraceEntry {
  action: string;
  target: string;
  amount?: number;
  table?: string;
  details?: Record<string, unknown>;
}

export interface PublicValues {
  max_spend?: number;
  restricted_endpoints?: string[];
}

export interface VerifyRequest {
  agent_metadata: AgentMetadata;
  policy_commitment: string;
  execution_trace: TraceEntry[];
  public_values: PublicValues;
  identity_context?: {
    session_id?: string;
    user_id?: string;
    iam_role?: string;
  };
}

export interface PotReceipt {
  receipt_id: string;
  policy_commitment: string;
  trace_hash: string;
  identity_hash?: string;
  combined_hash?: string;
  timestamp_ns: number;
  signature: string;
  public_key: string;
}

export interface VerifyResponse {
  valid: boolean;
  reason?: string;
  proof?: PotReceipt;
}

export interface RegisterResponse {
  policy_commitment: string;
  policy_storage_key?: string;
  anchor_url?: string;
  anchored_at?: string;
}

/** Policy payload sent to /v1/register - wraps public_values */
export interface RegisterPolicyPayload {
  public_values: PublicValues;
  rego_policy?: string;
}

/** Agent registration from verifier GET /v1/agents */
export interface Agent {
  agent_id: string;
  team: string;
  model: string;
  env: string;
  version: string;
}

/** Policy violation alert from verifier webhook */
export interface Alert {
  id: string;
  event: string;
  policy_commitment: string;
  domain: string;
  reason: string;
  timestamp_ns: number;
  received_at: string;
  severity?: string;
}
