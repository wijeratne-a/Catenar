/**
 * Catenar Proof-of-Task SDK for Node.js
 *
 * Route agent traffic through the Catenar proxy and verify traces with the verifier.
 * Set HTTP_PROXY and HTTPS_PROXY to the proxy URL (e.g. http://127.0.0.1:8080).
 */

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
  reasoning_summary?: string;
  model_id?: string;
  instruction_hash?: string;
  parent_task_id?: string;
}

export interface PublicValues {
  max_spend?: number;
  restricted_endpoints?: string[];
}

export interface IdentityContext {
  session_id?: string;
  user_id?: string;
  iam_role?: string;
}

export interface VerifyRequest {
  agent_metadata: AgentMetadata;
  policy_commitment: string;
  execution_trace: TraceEntry[];
  public_values: PublicValues;
  identity_context?: IdentityContext;
  task_token?: string;
}

export interface VerifyResponse {
  valid: boolean;
  reason?: string;
  proof?: {
    receipt_id: string;
    policy_commitment: string;
    trace_hash: string;
    identity_hash?: string;
    combined_hash?: string;
    timestamp_ns: number;
    signature: string;
    public_key: string;
  };
}

export interface RegisterResponse {
  policy_commitment: string;
  task_token?: string;
  task_token_required?: boolean;
}

export class CatenarClient {
  private baseUrl: string;
  private timeout: number;

  constructor(baseUrl = "http://127.0.0.1:3000", timeout = 5000) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.timeout = timeout;
  }

  async registerPolicy(
    policy: { public_values: PublicValues; rego_policy?: string },
    headers?: Record<string, string>
  ): Promise<RegisterResponse> {
    const res = await fetch(`${this.baseUrl}/v1/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify(policy),
      signal: AbortSignal.timeout(this.timeout),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Register failed: ${res.status} ${err}`);
    }
    return res.json() as Promise<RegisterResponse>;
  }

  async verify(payload: VerifyRequest, headers?: Record<string, string>): Promise<VerifyResponse> {
    const res = await fetch(`${this.baseUrl}/v1/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(this.timeout),
    });
    const body = (await res.json()) as VerifyResponse & { error?: string };
    if (!res.ok) {
      throw new Error(body.error ?? `Verify failed: ${res.status}`);
    }
    return body;
  }
}

export interface CatenarOptions {
  baseUrl?: string;
  sessionId?: string;
  userId?: string;
  iamRole?: string;
  agentId?: string;
}

export class Catenar {
  private client: CatenarClient;
  private policyCommitment: string | null = null;
  private taskToken: string | null = null;
  private domain = "defi";
  private version = "1.0";
  private publicValues: PublicValues = {};
  private identityContext: IdentityContext = {};
  private executionTrace: TraceEntry[] = [];

  constructor(options: CatenarOptions = {}) {
    this.client = new CatenarClient(options.baseUrl ?? "http://127.0.0.1:3000");
    this.identityContext = {
      session_id: options.sessionId,
      user_id: options.userId,
      iam_role: options.iamRole,
    };
  }

  async init(
    policy: { public_values: PublicValues; rego_policy?: string },
    domain: string,
    publicValues: PublicValues,
    version = "1.0"
  ): Promise<string> {
    const res = await this.client.registerPolicy(policy);
    this.policyCommitment = res.policy_commitment;
    this.taskToken = res.task_token ?? null;
    this.domain = domain;
    this.version = version;
    this.publicValues = publicValues;
    this.executionTrace = [];
    return res.policy_commitment;
  }

  trace(action: string, target: string, extras?: Partial<TraceEntry>): void {
    this.executionTrace.push({
      action,
      target,
      ...extras,
    });
  }

  async verify(): Promise<VerifyResponse> {
    if (!this.policyCommitment) {
      throw new Error("Call init() before verify()");
    }
    const payload: VerifyRequest = {
      agent_metadata: { domain: this.domain, version: this.version },
      policy_commitment: this.policyCommitment,
      execution_trace: [...this.executionTrace],
      public_values: this.publicValues,
      identity_context: this.identityContext,
      task_token: this.taskToken ?? undefined,
    };
    return this.client.verify(payload);
  }
}
