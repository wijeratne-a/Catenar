"""Lightweight user-space Aegis SDK for Proof-of-Task tracing."""

from __future__ import annotations

import json
import queue
import threading
import time
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

    def register_policy(self, policy: Dict[str, Any]) -> str:
        response = self.session.post(
            f"{self.base_url}/v1/register", json=policy, timeout=self.timeout
        )
        response.raise_for_status()
        data = response.json()
        return data["policy_commitment"]

    def verify(self, payload: Dict[str, Any]) -> AegisResult:
        response = self.session.post(
            f"{self.base_url}/v1/verify", json=payload, timeout=self.timeout
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
        base_url: str = "http://44.204.128.105",
        batch_size: int = 8,
        flush_interval_s: float = 0.4,
    ):
        self.client = AegisClient(base_url=base_url)
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s

        self.policy_commitment: Optional[str] = None
        self.domain: str = "defi"
        self.version: str = "1.0"
        self.public_values: Dict[str, Any] = {}

        self._trace_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._result_queue: "queue.Queue[AegisResult]" = queue.Queue()
        self._stop_event = threading.Event()
        self._worker = threading.Thread(target=self._flush_worker, daemon=True)
        self._worker.start()

    def init(
        self,
        policy: Dict[str, Any],
        domain: str,
        public_values: Dict[str, Any],
        version: str = "1.0",
    ) -> str:
        self.policy_commitment = self.client.register_policy(policy)
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
            try:
                self._trace_queue.put_nowait(entry)
            except queue.Full:
                # Drop trace entry instead of blocking agent execution.
                pass
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
        self._stop_event.set()
        self._worker.join(timeout=2.0)

    def _flush_worker(self) -> None:
        buffer: List[Dict[str, Any]] = []
        last_flush = time.monotonic()
        while not self._stop_event.is_set():
            now = time.monotonic()
            remaining = max(0.05, self.flush_interval_s - (now - last_flush))
            try:
                trace = self._trace_queue.get(timeout=remaining)
                buffer.append(trace)
            except queue.Empty:
                pass

            should_flush = len(buffer) >= self.batch_size or (
                buffer and (time.monotonic() - last_flush) >= self.flush_interval_s
            )
            if should_flush:
                self._send_batch(buffer)
                buffer = []
                last_flush = time.monotonic()

        if buffer:
            self._send_batch(buffer)

    def _send_batch(self, traces: List[Dict[str, Any]]) -> None:
        if not traces or not self.policy_commitment:
            return

        payload = {
            "agent_metadata": {"domain": self.domain, "version": self.version},
            "policy_commitment": self.policy_commitment,
            "execution_trace": traces,
            "public_values": self.public_values,
        }
        try:
            validated = VerifyRequestModel.model_validate(payload).model_dump(mode="json")
        except ValidationError as exc:
            self._result_queue.put(
                AegisResult(payload, 400, {"valid": False, "reason": str(exc)})
            )
            return

        try:
            result = self.client.verify(validated)
        except requests.RequestException as exc:
            result = AegisResult(validated, 503, {"valid": False, "reason": str(exc)})

        self._result_queue.put(result)

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
