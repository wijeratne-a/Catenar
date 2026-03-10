# Catenar SDK Examples

## blocked_tool_demo.py

Demonstrates a real agent integration: policy registration, traced tool calls, a blocked request, and reasoning injection for EU AI Act compliance.

### What it shows

- Policy registration with restricted endpoints (`/salary` blocked)
- Traced function `get_data(resource)` decorated with `@catenar.trace`
- Allowed call: `get_data("accounts")` with reasoning → receipt generated with `reasoning_summary`
- Blocked call: `get_data("salary")` → verifier rejects trace, returns policy violation

### How to run

```bash
# From repo root, with verifier running
cd agent
python examples/blocked_tool_demo.py
```

### Requirements

- Verifier running at `http://127.0.0.1:3000` (or set `CATENAR_BASE_URL`)
- Optional: Proxy at `http://127.0.0.1:8080` for full MITM flow (block is enforced at verifier for this trace-based demo)

### Output

```
Policy registered: <commitment_hash>
[1] Allowed: get_data('accounts') with reasoning
  -> Allowed. Receipt generated.
  -> Reasoning in receipt: User asked for account overview...
[2] Blocked: get_data('salary')
  -> BLOCKED: policy violation
  -> Catenar detected restricted endpoint. Trace rejected by verifier.
```

Check the dashboard receipts page to see the cryptographic proof and the reasoning summary bound to the receipt.
