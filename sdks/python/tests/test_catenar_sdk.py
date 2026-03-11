from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from catenar_sdk import Catenar, CatenarClient, CatenarResult


class FakeClient:
    def __init__(self) -> None:
        self.register_calls: list[tuple[Dict[str, Any], Optional[Dict[str, str]]]] = []
        self.verify_calls: list[tuple[Dict[str, Any], Optional[Dict[str, str]]]] = []

    def register_policy(self, policy: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> str:
        self.register_calls.append((policy, headers))
        return "0xpolicy"

    def verify(self, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> CatenarResult:
        self.verify_calls.append((payload, headers))
        return CatenarResult(payload, 200, {"valid": True})


def _new_catenar(tmp_path: Path) -> Catenar:
    return Catenar(
        base_url="http://127.0.0.1:3000",
        batch_size=1,
        flush_interval_s=0.01,
        wal_path=str(tmp_path / "wal.jsonl"),
        session_id="sess-1",
        user_id="user-1",
        iam_role="auditor",
    )


def test_client_uses_env_base_url(monkeypatch) -> None:
    monkeypatch.setenv("CATENAR_BASE_URL", "http://localhost:9000")
    client = CatenarClient(base_url=None)
    assert client.base_url == "http://localhost:9000"


def test_identity_headers_present(tmp_path: Path) -> None:
    sdk = _new_catenar(tmp_path)
    try:
        headers = sdk._identity_headers()
        assert headers["X-Catenar-Session-Id"] == "sess-1"
        assert headers["X-Catenar-User-Id"] == "user-1"
        assert headers["X-Catenar-IAM-Role"] == "auditor"
    finally:
        sdk.close()


def test_trace_entry_mapping(tmp_path: Path) -> None:
    sdk = _new_catenar(tmp_path)
    try:
        swap = sdk._build_trace_entry("execute_swap", (500.0,), {"token": "USDC"}, {"ok": True}, 10.5)
        assert swap["action"] == "api_call"
        assert swap["target"] == "https://dex.api/swap"
        assert swap["amount"] == 500.0

        query = sdk._build_trace_entry("query_database", ("salary",), {}, {"rows": 3}, 4.1)
        assert query["action"] == "db_query"
        assert query["table"] == "salary"
    finally:
        sdk.close()


def test_send_batch_uses_identity_headers(tmp_path: Path) -> None:
    sdk = _new_catenar(tmp_path)
    fake = FakeClient()
    sdk.client = fake  # type: ignore[assignment]
    try:
        sdk.policy_commitment = "0xpolicy"
        sent = sdk._send_batch([{"action": "function_call", "target": "x", "details": {}}])
        assert sent is True
        assert len(fake.verify_calls) == 1
        _, headers = fake.verify_calls[0]
        assert headers is not None
        assert headers["X-Catenar-Session-Id"] == "sess-1"
    finally:
        sdk.close()


def test_send_batch_includes_parent_task_id_in_trace(tmp_path: Path) -> None:
    """Verify that when _parent_task_id is set, the verify payload includes it in execution_trace."""
    sdk = _new_catenar(tmp_path)
    sdk._parent_task_id = "agent-a-receipt-uuid"
    fake = FakeClient()
    sdk.client = fake  # type: ignore[assignment]
    try:
        sdk.policy_commitment = "0xpolicy"
        sdk.domain = "defi"
        sdk.public_values = {"restricted_endpoints": ["/admin"]}
        trace_entry = sdk._build_trace_entry("sub_task", (42,), {}, {"result": 84}, 1.0)
        assert trace_entry.get("parent_task_id") == "agent-a-receipt-uuid"
        sent = sdk._send_batch([trace_entry])
        assert sent is True
        assert len(fake.verify_calls) == 1
        payload, _ = fake.verify_calls[0]
        trace = payload.get("execution_trace", [])
        assert len(trace) == 1
        assert trace[0].get("parent_task_id") == "agent-a-receipt-uuid"
    finally:
        sdk.close()
