"""Baseline Performance Benchmark Script for FIN//GUARD.

Measures p50, p95, p99 latency and throughput for core operations:
1. Decision pipeline (without LLM)
2. Signing gate
3. Keystore operations
4. Ledger verification
"""

import time
import os
import sys
import statistics
import tempfile
from finguard.core.transaction import Transaction
from finguard.core.enums import Currency, ActorType
from finguard.decision.engine import DecisionEngine
from finguard.identity.registry import IdentityRegistry, ActorConfig
from finguard.crypto.keystore import Keystore
from finguard.signing.gate import SigningGate
from finguard.audit.ledger import AuditLedger
from finguard.storage.database import init_db


def benchmark_decision_pipeline(n_iterations=500):
    init_db()
    registry = IdentityRegistry()
    engine = DecisionEngine(registry=registry)

    latencies = []
    start_total = time.perf_counter()
    for i in range(n_iterations):
        tx = Transaction(
            actor_id="operator-1",
            from_account="acc_1",
            to_account="vendor-a",
            amount=100.0 + (i % 50),
            currency=Currency.INR,
            nonce=f"bench_nonce_{i}_{time.time_ns()}",
        )
        t0 = time.perf_counter()
        engine.decide(tx)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)  # ms

    total_time = time.perf_counter() - start_total
    ops_per_sec = n_iterations / total_time
    p50 = statistics.median(latencies)
    p95 = statistics.quantiles(latencies, n=20)[18]
    p99 = statistics.quantiles(latencies, n=100)[98]

    return {
        "n": n_iterations,
        "total_s": round(total_time, 3),
        "ops_per_sec": round(ops_per_sec, 2),
        "p50_ms": round(p50, 3),
        "p95_ms": round(p95, 3),
        "p99_ms": round(p99, 3),
    }


def benchmark_keystore_unlock():
    ks = Keystore()
    latencies = []
    ts = time.time_ns()
    for i in range(5):
        key_id = f"bench_key_{ts}_{i}"
        ks.create_keypair(key_id, "secure_pass_123")
        t0 = time.perf_counter()
        ks.load_private_key(key_id, "secure_pass_123")
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)

    return {
        "n": 5,
        "p50_ms": round(statistics.median(latencies), 3),
        "p95_ms": round(statistics.quantiles(latencies, n=20)[18], 3),
    }


def benchmark_ledger_verify(n_entries=1000):
    ledger = AuditLedger()
    for i in range(n_entries):
        ledger.append("BENCH", "actor_1", f"tx_{i}", "ALLOW", {"idx": i})
    
    t0 = time.perf_counter()
    valid, entry_id, reason = ledger.verify_integrity()
    t1 = time.perf_counter()
    duration_ms = (t1 - t0) * 1000.0
    return {
        "entries": n_entries,
        "valid": valid,
        "verify_ms": round(duration_ms, 3),
    }


def main():
    print("==================================================", flush=True)
    print("FIN//GUARD BASELINE BENCHMARK", flush=True)
    print("==================================================", flush=True)
    
    print("\n--- 1. Decision Pipeline ---", flush=True)
    dec_res = benchmark_decision_pipeline(100)
    print(f"Iterations: {dec_res['n']}", flush=True)
    print(f"Throughput: {dec_res['ops_per_sec']} ops/sec", flush=True)
    print(f"p50 Latency: {dec_res['p50_ms']} ms", flush=True)
    print(f"p95 Latency: {dec_res['p95_ms']} ms", flush=True)
    print(f"p99 Latency: {dec_res['p99_ms']} ms", flush=True)

    print("\n--- 2. Keystore Unlock (Argon2id KDF) ---", flush=True)
    ks_res = benchmark_keystore_unlock()
    print(f"p50 Latency: {ks_res['p50_ms']} ms", flush=True)
    print(f"p95 Latency: {ks_res['p95_ms']} ms", flush=True)

    print("\n--- 3. Audit Ledger Verification ---", flush=True)
    ledg_res = benchmark_ledger_verify(200)
    print(f"200 Entries Verify Time: {ledg_res['verify_ms']} ms (Valid: {ledg_res['valid']})", flush=True)
    print("==================================================", flush=True)


if __name__ == "__main__":
    main()
