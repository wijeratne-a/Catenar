"""
Zero-config monkey-patch module for Aegis Proof-of-Task tracing.

Patches requests.Session.request, httpx.Client.send, httpx.AsyncClient.send
to emit trace entries via the Aegis tracer. Import this module before any
HTTP client to enable automatic tracing.

Set HTTP_PROXY/HTTPS_PROXY (default http://127.0.0.1:8080) for proxy routing.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict, Optional

# Set proxy from env if not already set (default http://127.0.0.1:8080)
_default_proxy = os.environ.get("AEGIS_PROXY", "http://127.0.0.1:8080")
if "HTTP_PROXY" not in os.environ and "http_proxy" not in os.environ:
    os.environ["HTTP_PROXY"] = _default_proxy
if "HTTPS_PROXY" not in os.environ and "https_proxy" not in os.environ:
    os.environ["HTTPS_PROXY"] = _default_proxy

# Ensure sdks/python is on path for aegis_sdk import
_sdk_dir = os.path.dirname(os.path.abspath(__file__))
if _sdk_dir not in sys.path:
    sys.path.insert(0, _sdk_dir)

from aegis_sdk import Aegis

# Global Aegis instance from AEGIS_BASE_URL env (default http://127.0.0.1:3000)
_aegis_base_url = os.environ.get("AEGIS_BASE_URL", "http://127.0.0.1:3000")
_aegis: Optional[Aegis] = None


def _get_aegis() -> Aegis:
    global _aegis
    if _aegis is None:
        _aegis = Aegis(base_url=_aegis_base_url)
    return _aegis


def get_aegis() -> Aegis:
    """Return the global Aegis instance used by the intercept. Call init() on it."""
    return _get_aegis()


def _build_http_trace_entry(
    method: str,
    url: str,
    status_code: Optional[int],
    elapsed_ms: float,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a trace entry for an HTTP call, matching Aegis schema."""
    return {
        "action": "api_call",
        "target": url,
        "amount": None,
        "table": None,
        "details": {
            "method": method,
            "url": url,
            "status_code": status_code,
            "execution_ms": round(elapsed_ms, 3),
            "error": error,
        },
        "reasoning_summary": None,
        "model_id": None,
        "instruction_hash": None,
        "parent_task_id": None,
    }


def _patch_requests() -> None:
    """Patch requests.Session.request."""
    try:
        import requests
    except ImportError:
        return

    _original_request = requests.Session.request

    def _patched_request(
        self: Any,
        method: str,
        url: str,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        start = time.perf_counter()
        status_code: Optional[int] = None
        error_msg: Optional[str] = None
        try:
            resp = _original_request(self, method, url, *args, **kwargs)
            status_code = resp.status_code
            return resp
        except Exception as e:
            error_msg = str(e)
            raise
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            try:
                aegis = _get_aegis()
                entry = _build_http_trace_entry(
                    method.upper() if isinstance(method, str) else str(method),
                    url,
                    status_code,
                    elapsed_ms,
                    error_msg,
                )
                aegis._append_trace(entry)
            except Exception:
                pass

    requests.Session.request = _patched_request


def _patch_httpx() -> None:
    """Patch httpx.Client.send and httpx.AsyncClient.send (lazy import)."""
    try:
        import httpx
    except ImportError:
        return

    # Sync Client.send
    _original_client_send = httpx.Client.send

    def _patched_client_send(self: Any, request: Any, *args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()
        status_code: Optional[int] = None
        error_msg: Optional[str] = None
        try:
            resp = _original_client_send(self, request, *args, **kwargs)
            status_code = resp.status_code
            return resp
        except Exception as e:
            error_msg = str(e)
            raise
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            try:
                aegis = _get_aegis()
                entry = _build_http_trace_entry(
                    str(request.method),
                    str(request.url),
                    status_code,
                    elapsed_ms,
                    error_msg,
                )
                aegis._append_trace(entry)
            except Exception:
                pass

    httpx.Client.send = _patched_client_send

    # Async AsyncClient.send
    _original_async_send = httpx.AsyncClient.send

    async def _patched_async_send(
        self: Any, request: Any, *args: Any, **kwargs: Any
    ) -> Any:
        start = time.perf_counter()
        status_code: Optional[int] = None
        error_msg: Optional[str] = None
        try:
            resp = await _original_async_send(self, request, *args, **kwargs)
            status_code = resp.status_code
            return resp
        except Exception as e:
            error_msg = str(e)
            raise
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            try:
                aegis = _get_aegis()
                entry = _build_http_trace_entry(
                    str(request.method),
                    str(request.url),
                    status_code,
                    elapsed_ms,
                    error_msg,
                )
                aegis._append_trace(entry)
            except Exception:
                pass

    httpx.AsyncClient.send = _patched_async_send


def install() -> None:
    """Install all patches. Called automatically on import."""
    _patch_requests()
    _patch_httpx()


# Auto-install on import
install()
