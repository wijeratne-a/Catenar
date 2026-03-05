/**
 * Aegis Proof-of-Task SDK for Node.js
 *
 * Route agent traffic through the Aegis proxy and verify traces with the verifier.
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
export declare class AegisClient {
    private baseUrl;
    private timeout;
    constructor(baseUrl?: string, timeout?: number);
    registerPolicy(policy: {
        public_values: PublicValues;
        rego_policy?: string;
    }, headers?: Record<string, string>): Promise<RegisterResponse>;
    verify(payload: VerifyRequest, headers?: Record<string, string>): Promise<VerifyResponse>;
}
export interface AegisOptions {
    baseUrl?: string;
    sessionId?: string;
    userId?: string;
    iamRole?: string;
    agentId?: string;
}
export declare class Aegis {
    private client;
    private policyCommitment;
    private taskToken;
    private domain;
    private version;
    private publicValues;
    private identityContext;
    private executionTrace;
    constructor(options?: AegisOptions);
    init(policy: {
        public_values: PublicValues;
        rego_policy?: string;
    }, domain: string, publicValues: PublicValues, version?: string): Promise<string>;
    trace(action: string, target: string, extras?: Partial<TraceEntry>): void;
    verify(): Promise<VerifyResponse>;
}
