#!/usr/bin/env python3
"""
Stress test agent for Catenar Proof-of-Task tracing.

Uses catenar_intercept to auto-trace HTTP calls. Run with proxy and verifier:
  HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=... REQUESTS_CA_BUNDLE=... python stress_test_agent.py

With STRESS_TEST_USE_MOCK=1: runs a local mock server (port 9999) to avoid DNS errors.
  Set CATENAR_STRESS_MOCK_PORT=9999 in proxy env for Docker. For full policy testing use real URLs.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# Add sdks/python to path before any HTTP client imports
_root = Path(__file__).resolve().parent.parent
_sdk_path = str(_root / "sdks" / "python")
if _sdk_path not in sys.path:
    sys.path.insert(0, _sdk_path)

# CRITICAL: import catenar_intercept FIRST (before httpx) to patch globally
import catenar_intercept
from catenar_intercept import get_catenar

import httpx

# Task mix: 20 LLM, 10 transfer, 5 db_attack (blocked), 65 mixed
TASK_COUNTS = {"llm": 20, "transfer": 10, "db_attack": 5, "mixed": 65}
TOTAL_TASKS = sum(TASK_COUNTS.values())

MOCK_PORT = int(os.environ.get("STRESS_MOCK_PORT", "9999"))

# Endpoints - db_attack and admin hit restricted hosts (blocked by policy)
ENDPOINTS = {
    "llm": "https://api.openai.com/v1/chat/completions",
    "transfer": "https://transfer.company.com/api/transfer",
    "db_attack": "https://db.internal.company.com/api/query",
    "admin": "https://admin.company.com/api/admin",
    "allowed": "https://httpbin.org/get",
}

# Mock mode: all requests go to local HTTP mock server (avoids DNS errors)
MOCK_ENDPOINTS = {
    "llm": f"http://127.0.0.1:{MOCK_PORT}/llm",
    "transfer": f"http://127.0.0.1:{MOCK_PORT}/transfer",
    "db_attack": f"http://127.0.0.1:{MOCK_PORT}/db_attack",
    "admin": f"http://127.0.0.1:{MOCK_PORT}/admin",
    "allowed": f"http://127.0.0.1:{MOCK_PORT}/allowed",
}


def _start_mock_server(port: int) -> HTTPServer:
    """Start a minimal HTTP mock server that returns 200 JSON for all paths."""

    class MockHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True, "path": self.path}).encode())

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", port), MockHandler)
    return server


async def run_task(client: httpx.AsyncClient, task_type: str, use_mock: bool) -> dict:
    """Run a single HTTP task. Returns {allowed, blocked, error, body}."""
    if task_type == "mixed":
        task_type = random.choice(["llm", "transfer", "allowed", "db_attack", "admin"])
    endpoints = MOCK_ENDPOINTS if use_mock else ENDPOINTS
    url = endpoints.get(task_type, endpoints["allowed"])
    try:
        resp = await client.get(url, timeout=10.0)
        resp.raise_for_status()
        body = resp.json() if "application/json" in resp.headers.get("content-type", "") else {"raw": resp.text[:200]}
        # Check for 200 with semantic error body (e.g. policy violation, catenar_block)
        if resp.status_code == 200:
            if isinstance(body, dict) and (
                body.get("valid") is False or body.get("catenar_block") is True
            ):
                return {"allowed": False, "blocked": True, "error": None, "body": body}
            return {"allowed": True, "blocked": False, "error": None, "body": body}
        return {"allowed": False, "blocked": resp.status_code in (403, 451, 502), "error": resp.text[:200], "body": body}
    except httpx.HTTPStatusError as e:
        body = {}
        try:
            body = e.response.json() if e.response else {}
        except Exception:
            body = {"raw": str(e.response.text)[:200] if e.response else str(e)}
        blocked = e.response.status_code in (403, 451, 502) if e.response else False
        return {"allowed": False, "blocked": blocked, "error": str(e), "body": body}
    except Exception as e:
        return {"allowed": False, "blocked": False, "error": str(e), "body": {}}


async def run_stress_test() -> dict:
    """Run 100 concurrent tasks and return aggregated results."""
    catenar = get_catenar()
    policy = {
        "public_values": {
            "max_spend": 10000,
            "restricted_endpoints": ["db.internal.company.com", "admin.company.com"],
        }
    }
    catenar.init(
        policy=policy,
        domain="defi",
        public_values=policy["public_values"],
    )

    tasks: list[tuple[str, asyncio.Task]] = []
    async with httpx.AsyncClient() as client:
        for task_type, count in TASK_COUNTS.items():
            for _ in range(count):
                tasks.append((task_type, asyncio.create_task(run_task(client, task_type))))

        results = []
        for task_type, task in tasks:
            r = await task
            r["task_type"] = task_type
            results.append(r)

    allowed = sum(1 for r in results if r["allowed"])
    blocked = sum(1 for r in results if r["blocked"])
    errors = sum(1 for r in results if r["error"] and not r["blocked"])

    # Wait for trace flush and collect receipts
    receipts = catenar.wait_for_results(len(results), timeout_s=8.0)
    receipts_verified = sum(1 for rec in receipts if rec.response_status == 200 and (rec.response_body.get("valid") is True))

    catenar.close()

    return {
        "allowed": allowed,
        "blocked": blocked,
        "errors": errors,
        "receipts_verified": receipts_verified,
        "total": len(results),
        "receipts_count": len(receipts),
    }


def main() -> None:
    use_mock = os.environ.get("STRESS_TEST_USE_MOCK", "").strip() in ("1", "true", "yes")
    if use_mock:
        print("Catenar Stress Test (mock mode) - 100 concurrent tasks")
        print("  Mock server on 127.0.0.1:9999 (set CATENAR_STRESS_MOCK_PORT=9999 in proxy)")
    else:
        print("Catenar Stress Test - 100 concurrent tasks")
    print("  Mix: 20 LLM, 10 transfer, 5 db_attack (blocked), 65 mixed")
    print()
    if use_mock:
        server = _start_mock_server(MOCK_PORT)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
    results = asyncio.run(run_stress_test(use_mock=use_mock))
    print("Results:")
    print(f"  Allowed:        {results['allowed']}")
    print(f"  Blocked:        {results['blocked']}")
    print(f"  Errors:         {results['errors']}")
    print(f"  Receipts:       {results['receipts_count']} received")
    print(f"  Verified:       {results['receipts_verified']}")


if __name__ == "__main__":
    # Set proxy and CA bundle for MITM if not already set
    if "HTTP_PROXY" not in os.environ and "http_proxy" not in os.environ:
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:8080"
    if "HTTPS_PROXY" not in os.environ and "https_proxy" not in os.environ:
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:8080"
    # Bypass proxy for verifier (register/verify) - use NO_PROXY
    no_proxy = os.environ.get("NO_PROXY", "") or os.environ.get("no_proxy", "")
    if "127.0.0.1" not in no_proxy and "localhost" not in no_proxy:
        os.environ["NO_PROXY"] = "127.0.0.1,localhost" + (f",{no_proxy}" if no_proxy else "")
    if "REQUESTS_CA_BUNDLE" not in os.environ and "SSL_CERT_FILE" not in os.environ:
        # Optional: set if proxy CA is at known path
        ca_path = Path(__file__).resolve().parent.parent / "deploy" / "certs" / "ca.crt"
        if ca_path.exists():
            os.environ["REQUESTS_CA_BUNDLE"] = str(ca_path)
            os.environ["SSL_CERT_FILE"] = str(ca_path)

    main()
