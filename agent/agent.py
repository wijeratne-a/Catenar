#!/usr/bin/env python3
"""Aegis user-space PoT wedge tests for DeFi and Enterprise flows."""

from __future__ import annotations

from typing import Any, Dict

from aegis_sdk import Aegis


def print_verify_result(label: str, result_body: Dict[str, Any]) -> None:
    valid = result_body.get("valid")
    if valid:
        proof = result_body.get("proof", {})
        print(
            f"[{label}] PASS valid={valid} "
            f"commitment={proof.get('policy_commitment')} "
            f"trace_hash={proof.get('trace_hash')}"
        )
    else:
        print(f"[{label}] REJECTED valid={valid} reason={result_body.get('reason')}")


def run_defi_demo() -> None:
    print("=== Test A: DeFi Safe-Pay ===")
    aegis = Aegis(base_url="http://44.204.128.105", batch_size=1, flush_interval_s=0.1)

    policy = {"public_values": {"max_spend": 1000, "restricted_endpoints": ["/admin"]}}
    commitment = aegis.init(
        policy=policy,
        domain="defi",
        public_values={"max_spend": 1000, "restricted_endpoints": ["/admin"]},
        version="1.0",
    )
    print(f"[defi] registered policy_commitment={commitment}")

    @aegis.trace
    def execute_swap(amount: float, token: str, address: str) -> Dict[str, Any]:
        return {"status": "ok", "amount": amount, "token": token, "address": address}

    execute_swap(500, "USDC", "0xabc123")
    first = aegis.wait_for_results(expected=1, timeout_s=3.0)
    if first:
        print_verify_result("defi:$500", first[0].response_body)

    execute_swap(5000, "USDC", "0xabc123")
    second = aegis.wait_for_results(expected=1, timeout_s=3.0)
    if second:
        print_verify_result("defi:$5000", second[0].response_body)

    aegis.close()


def run_enterprise_demo() -> None:
    print("=== Test B: Enterprise PII-Guard ===")
    aegis = Aegis(base_url="http://44.204.128.105", batch_size=1, flush_interval_s=0.1)

    policy = {"public_values": {"restricted_endpoints": ["salary"]}}
    commitment = aegis.init(
        policy=policy,
        domain="enterprise",
        public_values={"restricted_endpoints": ["salary"]},
        version="1.0",
    )
    print(f"[enterprise] registered policy_commitment={commitment}")

    @aegis.trace
    def query_database(table: str) -> Dict[str, Any]:
        return {"table": table, "rows": 12}

    query_database("inventory")
    first = aegis.wait_for_results(expected=1, timeout_s=3.0)
    if first:
        print_verify_result("enterprise:inventory", first[0].response_body)

    query_database("salary")
    second = aegis.wait_for_results(expected=1, timeout_s=3.0)
    if second:
        print_verify_result("enterprise:salary", second[0].response_body)

    aegis.close()


if __name__ == "__main__":
    run_defi_demo()
    print()
    run_enterprise_demo()
