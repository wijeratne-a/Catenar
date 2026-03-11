#!/usr/bin/env python3
"""
Bring Your Own Agent: minimal Catenar integration.

Prerequisites: docker compose up -d verifier proxy. Run from repo root so the CA path works, or set REQUESTS_CA_BUNDLE to deploy/certs/ca.crt.
Set CATENAR_DEMO=1 for auto proxy/CA config (recommended), or manually:
  export HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080
  export NO_PROXY=127.0.0.1,localhost
  export REQUESTS_CA_BUNDLE=./deploy/certs/ca.crt

Usage: import catenar_intercept FIRST, then your HTTP client.
"""
import os

os.environ.setdefault("CATENAR_DEMO", "1")  # proxy + CA for quick local test

import catenar_intercept  # noqa: F401 - MUST BE FIRST (patches requests/httpx/aiohttp)
from catenar_intercept import get_catenar

import requests

# For A2A: set get_catenar().set_parent_task_id(parent_receipt_id) before requests to the child agent.
catenar = get_catenar()
catenar.init(
    policy={"public_values": {"restricted_endpoints": ["db.internal"]}},
    domain="defi",
    public_values={"restricted_endpoints": ["db.internal"]},
)

# Your agent's HTTP calls are auto-traced. Example:
resp = requests.get("https://httpbin.org/get")
print("Status:", resp.status_code)
print("Receipts:", catenar.wait_for_results(1, timeout_s=5.0))
catenar.close()
