#!/usr/bin/env python3
"""
Real agent demo: Aegis blocks a restricted tool call and captures reasoning.

This example demonstrates:
- A traced function that would be blocked by policy (restricted endpoint)
- Reasoning injection via with_reasoning() for EU AI Act compliance
- Semantic error handling when the verifier rejects the trace

Run with proxy + verifier up:
  docker compose up -d verifier proxy  # or your equivalent
  cd agent && python examples/blocked_tool_demo.py

Or run without proxy (trace still flows to verifier, block is verifier-side):
  python examples/blocked_tool_demo.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure parent directory is on path for aegis_sdk import
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis_sdk import Aegis

# Configure proxy env (same as agent.py)
_DEFAULT_PROXY = "http://127.0.0.1:8080"
_DEFAULT_VERIFIER = "http://127.0.0.1:3000"


def main() -> None:
    os.environ.setdefault("HTTP_PROXY", _DEFAULT_PROXY)
    os.environ.setdefault("HTTPS_PROXY", _DEFAULT_PROXY)
    os.environ.setdefault("REQUESTS_CA_BUNDLE", "/etc/aegis/ca.crt")

    base_url = os.environ.get("AEGIS_BASE_URL", _DEFAULT_VERIFIER)
    aegis = Aegis(
        base_url=base_url,
        batch_size=1,
        flush_interval_s=0.1,
        agent_id="agent-demo-vp-ai",
        session_id="session-demo-2026",
        user_id="demo@company.com",
        iam_role="data-analyst",
    )

    # Register policy: block /salary, allow /accounts
    policy = {"public_values": {"restricted_endpoints": ["/salary"]}}
    commitment = aegis.init(
        policy=policy,
        domain="enterprise",
        public_values={"restricted_endpoints": ["/salary"]},
        version="1.0",
    )
    print(f"Policy registered: {commitment}")

    @aegis.trace
    def get_data(resource: str) -> dict:
        """Simulated tool: fetch data by resource name. Blocked when resource is 'salary'."""
        return {"resource": resource, "rows": 10}

    # Allowed call with reasoning (receipt will show reasoning_summary)
    print("\n[1] Allowed: get_data('accounts') with reasoning")
    with aegis.with_reasoning("User asked for account overview; fetching allowed resource"):
        get_data("accounts")
    results = aegis.wait_for_results(expected=1, timeout_s=4.0)
    if results:
        r = results[0].response_body
        if r.get("valid"):
            proof = r.get("proof", {})
            print("  -> Allowed. Receipt generated.")
            if proof.get("reasoning_summary"):
                print(f"  -> Reasoning in receipt: {proof['reasoning_summary'][:60]}...")
        else:
            print(f"  -> Rejected: {r.get('reason', 'unknown')}")

    # Blocked call (policy denies restricted endpoint)
    print("\n[2] Blocked: get_data('salary')")
    get_data("salary")
    results = aegis.wait_for_results(expected=1, timeout_s=4.0)
    if results:
        r = results[0].response_body
        if r.get("valid"):
            print("  -> Unexpectedly allowed.")
        else:
            print(f"  -> BLOCKED: {r.get('reason', 'policy violation')}")
            print("  -> Aegis detected restricted endpoint. Trace rejected by verifier.")

    aegis.close()
    print("\nDemo complete. Check dashboard receipts for identity context and reasoning.")


if __name__ == "__main__":
    main()
