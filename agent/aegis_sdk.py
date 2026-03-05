"""Lightweight user-space Aegis SDK for Proof-of-Task tracing."""

from __future__ import annotations

import json
import queue
import threading
import time
import atexit
import signal
from pathlib import Path
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Dict, List, Optional

import requests
from pydantic import BaseModel, ConfigDict, ValidationError


class AgentMetadataModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: str
    version: str


class TraceEntryModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str
    target: str
    amount: Optional[float] = None
    table: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class PublicValuesModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_spend: Optional[float] = None
    restricted_endpoints: Optional[List[str]] = None


class VerifyRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_metadata: AgentMetadataModel
    policy_commitment: str
    execution_trace: List[TraceEntryModel]
    public_values: PublicValuesModel
    identity_context: Optional[Dict[str, Optional[str]]] = None


@dataclass
class AegisResult:
    request_payload: Dict[str, Any]
    response_status: int
    response_body: Dict[str, Any]


class AegisClient:
    def __init__(self, base_url: str = "http://44.204.128.105", timeout: float = 3.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def register_policy(self, policy: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> str:
        response = self.session.post(
            f"{self.base_url}/v1/register", json=policy, timeout=self.timeout, headers=headers
        )
        response.raise_for_status()
        data = response.json()
        return data["policy_commitment"]

    def verify(self, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> AegisResult:
        response = self.session.post(
            f"{self.base_url}/v1/verify", json=payload, timeout=self.timeout, headers=headers
        )
        body: Dict[str, Any]
        try:
            body = response.json()
        except requests.JSONDecodeError:
            body = {"raw": response.text}
        return AegisResult(payload, response.status_code, body)


class Aegis:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:3000",
        batch_size: int = 8,
        flush_interval_s: float = 0.4,
        wal_path: str = "./aegis-trace-wal.jsonl",
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        iam_role: Optional[str] = None,
    ):
        self.client = AegisClient(base_url=base_url)
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s
        self.wal_path = Path(wal_path)

        self.policy_commitment: Optional[str] = None
        self.domain: str = "defi"
        self.version: str = "1.0"
        self.public_values: Dict[str, Any] = {}
        self.identity_context: Dict[str, Optional[str]] = {
            "session_id": session_id,
            "user_id": user_id,
            "iam_role": iam_role,
        }

        self._trace_queue: "queue.Queue[None]" = queue.Queue()
        self._result_queue: "queue.Queue[AegisResult]" = queue.Queue()
        self._pending_lock = threading.Lock()
        self._pending_entries: List[Dict[str, Any]] = []
        self._stop_event = threading.Event()
        self._load_wal()
        self._worker = threading.Thread(target=self._flush_worker, daemon=True)
        self._worker.start()
        atexit.register(self.close)
        self._register_signal_handlers()

    def init(
        self,
        policy: Dict[str, Any],
        domain: str,
        public_values: Dict[str, Any],
        version: str = "1.0",
    ) -> str:
        self.policy_commitment = self.client.register_policy(policy, headers=self._identity_headers())
        self.domain = domain
        self.version = version
        self.public_values = public_values
        return self.policy_commitment

    def trace(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            result = fn(*args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000.0

            entry = self._build_trace_entry(fn.__name__, args, kwargs, result, elapsed_ms)
            self._append_trace(entry)
            return result

        return wrapper

    def wait_for_results(self, expected: int, timeout_s: float = 5.0) -> List[AegisResult]:
        collected: List[AegisResult] = []
        deadline = time.monotonic() + timeout_s
        while len(collected) < expected and time.monotonic() < deadline:
            try:
                item = self._result_queue.get(timeout=0.1)
                collected.append(item)
            except queue.Empty:
                continue
        return collected

    def close(self) -> None:
        if self._stop_event.is_set():
            return
        self._stop_event.set()
        self._worker.join(timeout=2.0)
        self._flush_pending(force=True)

    def _flush_worker(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._trace_queue.get(timeout=self.flush_interval_s)
            except queue.Empty:
                pass
            self._flush_pending(force=False)

    def _send_batch(self, traces: List[Dict[str, Any]]) -> bool:
        if not traces or not self.policy_commitment:
            return False

        payload = {
            "agent_metadata": {"domain": self.domain, "version": self.version},
            "policy_commitment": self.policy_commitment,
            "execution_trace": traces,
            "public_values": self.public_values,
            "identity_context": self.identity_context,
        }
        try:
            validated = VerifyRequestModel.model_validate(payload).model_dump(mode="json")
        except ValidationError as exc:
            self._result_queue.put(
                AegisResult(payload, 400, {"valid": False, "reason": str(exc)})
            )
            return False

        try:
            result = self.client.verify(validated, headers=self._identity_headers())
        except requests.RequestException as exc:
            result = AegisResult(validated, 503, {"valid": False, "reason": str(exc)})
            self._result_queue.put(result)
            return False

        self._result_queue.put(result)
        return result.response_status < 500

    def _append_trace(self, entry: Dict[str, Any]) -> None:
        with self._pending_lock:
            self._pending_entries.append(entry)
            self._persist_wal_locked()
        self._trace_queue.put_nowait(None)

    def _load_wal(self) -> None:
        if not self.wal_path.exists():
            return
        try:
            loaded: List[Dict[str, Any]] = []
            for line in self.wal_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                loaded.append(json.loads(line))
            self._pending_entries = loaded
        except Exception:
            # If WAL is corrupted, preserve current file and start fresh.
            backup = self.wal_path.with_suffix(".corrupt")
            self.wal_path.replace(backup)
            self._pending_entries = []

    def _persist_wal_locked(self) -> None:
        self.wal_path.parent.mkdir(parents=True, exist_ok=True)
        serialized = "\n".join(json.dumps(item) for item in self._pending_entries)
        if serialized:
            serialized += "\n"
        self.wal_path.write_text(serialized, encoding="utf-8")

    def _flush_pending(self, force: bool) -> None:
        if not self.policy_commitment:
            return
        while True:
            with self._pending_lock:
                if not self._pending_entries:
                    return
                if not force and len(self._pending_entries) < self.batch_size:
                    return
                batch = self._pending_entries[: self.batch_size]
            before_len = len(batch)
            sent = self._send_batch(batch)
            if not sent:
                return
            with self._pending_lock:
                if len(self._pending_entries) >= before_len:
                    del self._pending_entries[:before_len]
                    self._persist_wal_locked()
            if not force:
                return

    def _register_signal_handlers(self) -> None:
        def _handle_signal(_: int, __: Any) -> None:
            self.close()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _handle_signal)
            except Exception:
                # Some runtimes disallow setting signal handlers in non-main threads.
                pass

    def _identity_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self.identity_context.get("session_id"):
            headers["X-Aegis-Session-Id"] = str(self.identity_context["session_id"])
        if self.identity_context.get("user_id"):
            headers["X-Aegis-User-Id"] = str(self.identity_context["user_id"])
        if self.identity_context.get("iam_role"):
            headers["X-Aegis-IAM-Role"] = str(self.identity_context["iam_role"])
        return headers

    def _build_trace_entry(
        self,
        function_name: str,
        args: Any,
        kwargs: Dict[str, Any],
        result: Any,
        elapsed_ms: float,
    ) -> Dict[str, Any]:
        action = "function_call"
        target = function_name
        amount: Optional[float] = None
        table: Optional[str] = None

        if function_name == "execute_swap":
            action = "api_call"
            target = "https://dex.api/swap"
            amount = _get_arg("amount", 0, args, kwargs, default=None)
        elif function_name == "query_database":
            action = "db_query"
            target = "/database/query"
            table = _get_arg("table", 0, args, kwargs, default=None)

        details = {
            "function": function_name,
            "args": _safe_json(args),
            "kwargs": _safe_json(kwargs),
            "result": _safe_json(result),
            "execution_ms": round(elapsed_ms, 3),
        }

        return {
            "action": action,
            "target": target,
            "amount": amount,
            "table": table,
            "details": details,
        }


def _safe_json(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except TypeError:
        return repr(value)


def _get_arg(name: str, position: int, args: Any, kwargs: Dict[str, Any], default: Any) -> Any:
    if name in kwargs:
        return kwargs[name]
    if len(args) > position:
        return args[position]
    return default
