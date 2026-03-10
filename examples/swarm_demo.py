#!/usr/bin/env python3
"""
Swarm / multi-agent demo: Agent A calls Agent B over HTTP; both use Catenar with parent_task_id.

Run with proxy and verifier:
  HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=... REQUESTS_CA_BUNDLE=... python swarm_demo.py

Agent A: registers policy, does traced work, gets receipt, calls Agent B with receipt_id as parent.
Agent B: HTTP server that receives X-Catenar-Parent-Task-Id, sets it on Catenar, does traced work.
Assert: Agent B's receipt has parent_task_ids containing Agent A's receipt_id.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
_sdk_path = str(_root / "sdks" / "python")
if _sdk_path not in sys.path:
    sys.path.insert(0, _sdk_path)

import requests
from catenar_sdk import Catenar

AGENT_B_PORT = 9998
HEADER_PARENT_TASK_ID = "X-Catenar-Parent-Task-Id"


def _configure_env() -> None:
    if "HTTP_PROXY" not in os.environ and "http_proxy" not in os.environ:
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:8080"
    if "HTTPS_PROXY" not in os.environ and "https_proxy" not in os.environ:
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:8080"
    no_proxy = os.environ.get("NO_PROXY", "") or os.environ.get("no_proxy", "")
    if "127.0.0.1" not in no_proxy and "localhost" not in no_proxy:
        os.environ["NO_PROXY"] = "127.0.0.1,localhost" + (f",{no_proxy}" if no_proxy else "")
    if "REQUESTS_CA_BUNDLE" not in os.environ and "SSL_CERT_FILE" not in os.environ:
        ca_path = _root / "deploy" / "certs" / "ca.crt"
        if ca_path.exists():
            os.environ["REQUESTS_CA_BUNDLE"] = str(ca_path)
            os.environ["SSL_CERT_FILE"] = str(ca_path)


def run_agent_b(verifier_url: str) -> HTTPServer:
    """Agent B: HTTP server that does traced work with parent_task_id from request."""

    class AgentBHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parent_task_id = self.headers.get(HEADER_PARENT_TASK_ID, "").strip()
            catenar = Catenar(base_url=verifier_url, batch_size=1, flush_interval_s=0.1, agent_id="agent-b")
            policy = {"public_values": {"restricted_endpoints": ["/admin"]}}
            catenar.init(policy=policy, domain="defi", public_values=policy["public_values"])
            if parent_task_id:
                catenar._parent_task_id = parent_task_id

            @catenar.trace
            def sub_task(x: int) -> dict:
                return {"result": x * 2}

            sub_task(42)
            receipts = catenar.wait_for_results(1, timeout_s=3.0)
            proof = receipts[0].response_body.get("proof", {}) if receipts else {}
            catenar.close()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "receipt_id": proof.get("receipt_id", ""),
                "parent_task_ids": proof.get("parent_task_ids", []),
            }).encode())

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", AGENT_B_PORT), AgentBHandler)
    return server


def main() -> None:
    _configure_env()
    verifier_url = os.environ.get("CATENAR_BASE_URL", "http://127.0.0.1:3000")

    # Start Agent B
    server = run_agent_b(verifier_url)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)

    # Agent A
    catenar_a = Catenar(base_url=verifier_url, batch_size=1, flush_interval_s=0.1, agent_id="agent-a")
    policy = {"public_values": {"restricted_endpoints": ["/admin"]}}
    catenar_a.init(policy=policy, domain="defi", public_values=policy["public_values"])

    @catenar_a.trace
    def agent_a_task() -> dict:
        return {"status": "ok"}

    agent_a_task()
    receipts_a = catenar_a.wait_for_results(1, timeout_s=3.0)
    if not receipts_a:
        print("FAIL: Agent A got no receipt")
        server.shutdown()
        sys.exit(1)

    proof_a = receipts_a[0].response_body.get("proof", {})
    receipt_id_a = proof_a.get("receipt_id")
    if not receipt_id_a:
        print("FAIL: Agent A receipt missing receipt_id")
        server.shutdown()
        sys.exit(1)

    # Agent A calls Agent B with parent_task_id
    proxy = os.environ.get("HTTP_PROXY", "http://127.0.0.1:8080")
    resp = requests.get(
        f"http://127.0.0.1:{AGENT_B_PORT}/",
        headers={HEADER_PARENT_TASK_ID: receipt_id_a},
        proxies={"http": proxy, "https": proxy},
        timeout=5,
    )
    resp.raise_for_status()
    server.shutdown()

    # Agent B returns receipt_id and parent_task_ids in body (from its verify response)
    # We need Agent B's receipt - it was returned in the verify response, not in the HTTP body.
    # The HTTP body we wrote is minimal. The receipt is in the verifier's response to Agent B.
    # For assertion we need to get Agent B's receipt. Agent B could return it in the body.
    # Let me update Agent B to return the full proof in the body so we can assert.
    body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    parent_task_ids = body.get("parent_task_ids", [])
    receipt_id_b = body.get("receipt_id", "")

    if receipt_id_a in parent_task_ids:
        print("PASS: Agent B receipt has parent_task_ids containing Agent A receipt_id")
        print(f"  Agent A receipt_id: {receipt_id_a}")
        print(f"  Agent B receipt_id: {receipt_id_b}")
        print(f"  Agent B parent_task_ids: {parent_task_ids}")
    else:
        print("FAIL: Agent B receipt missing parent_task_id from Agent A")
        print(f"  Agent A receipt_id: {receipt_id_a}")
        print(f"  Agent B parent_task_ids: {parent_task_ids}")
        sys.exit(1)

    catenar_a.close()


if __name__ == "__main__":
    main()
