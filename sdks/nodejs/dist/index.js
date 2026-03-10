"use strict";
/**
 * Catenar Proof-of-Task SDK for Node.js
 *
 * Route agent traffic through the Catenar proxy and verify traces with the verifier.
 * Set HTTP_PROXY and HTTPS_PROXY to the proxy URL (e.g. http://127.0.0.1:8080).
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.Catenar = exports.CatenarClient = void 0;
class CatenarClient {
    constructor(baseUrl = "http://127.0.0.1:3000", timeout = 5000) {
        this.baseUrl = baseUrl.replace(/\/$/, "");
        this.timeout = timeout;
    }
    async registerPolicy(policy, headers) {
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
        return res.json();
    }
    async verify(payload, headers) {
        const res = await fetch(`${this.baseUrl}/v1/verify`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...headers },
            body: JSON.stringify(payload),
            signal: AbortSignal.timeout(this.timeout),
        });
        const body = (await res.json());
        if (!res.ok) {
            throw new Error(body.error ?? `Verify failed: ${res.status}`);
        }
        return body;
    }
}
exports.CatenarClient = CatenarClient;
class Catenar {
    constructor(options = {}) {
        this.policyCommitment = null;
        this.taskToken = null;
        this.domain = "defi";
        this.version = "1.0";
        this.publicValues = {};
        this.identityContext = {};
        this.executionTrace = [];
        this.client = new CatenarClient(options.baseUrl ?? "http://127.0.0.1:3000");
        this.identityContext = {
            session_id: options.sessionId,
            user_id: options.userId,
            iam_role: options.iamRole,
        };
    }
    async init(policy, domain, publicValues, version = "1.0") {
        const res = await this.client.registerPolicy(policy);
        this.policyCommitment = res.policy_commitment;
        this.taskToken = res.task_token ?? null;
        this.domain = domain;
        this.version = version;
        this.publicValues = publicValues;
        this.executionTrace = [];
        return res.policy_commitment;
    }
    trace(action, target, extras) {
        this.executionTrace.push({
            action,
            target,
            ...extras,
        });
    }
    async verify() {
        if (!this.policyCommitment) {
            throw new Error("Call init() before verify()");
        }
        const payload = {
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
exports.Catenar = Catenar;
