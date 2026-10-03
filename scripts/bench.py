"""Baseline Performance Benchmark Script for FIN//GUARD.

Measures p50, p95, p99 latency and throughput for core operations:
1. Decision pipeline (without LLM)
2. Signing gate
3. Keystore operations
4. Ledger verification
"""

import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from finguard.audit.ledger import AuditLedger
from finguard.core.canonical import canonical_serialize
from finguard.core.config import reset_config
from finguard.core.enums import Currency
from finguard.core.transaction import Transaction
from finguard.crypto.keystore import Keystore
from finguard.crypto.signing import generate_keypair, sign_canonical_bytes
from finguard.decision.engine import DecisionEngine
from finguard.identity.registry import IdentityRegistry
from finguard.money import Money
from finguard.storage.database import init_db, reset_db


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
            amount=str(100 + (i % 50)),
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
    valid, _, _ = ledger.verify_integrity()
    t1 = time.perf_counter()
    duration_ms = (t1 - t0) * 1000.0
    return {
        "entries": n_entries,
        "valid": valid,
        "verify_ms": round(duration_ms, 3),
    }


def _latency_summary(latencies, n):
    ordered = sorted(latencies)
    return {
        "n": n,
        "p50_ms": round(statistics.median(ordered), 6),
        "p95_ms": round(ordered[int(n * 0.95) - 1], 6),
        "p99_ms": round(ordered[int(n * 0.99) - 1], 6),
    }


def benchmark_money(n_iterations=1000):
    latencies = []
    for _ in range(n_iterations):
        started = time.perf_counter_ns()
        Money.from_decimal("1234.56", Currency.USD).to_decimal_string()
        latencies.append((time.perf_counter_ns() - started) / 1_000_000)
    return _latency_summary(latencies, n_iterations)


def benchmark_canonical_hash(n_iterations=1000):
    tx = Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="1234.56", currency=Currency.INR, nonce="benchmark-nonce",
    )
    latencies = []
    for _ in range(n_iterations):
        started = time.perf_counter_ns()
        tx.transaction_hash()
        latencies.append((time.perf_counter_ns() - started) / 1_000_000)
    return _latency_summary(latencies, n_iterations)


def benchmark_signature_generation(n_iterations=1000):
    private_key, _ = generate_keypair()
    message = canonical_serialize({"benchmark": "signature", "version": 2})
    latencies = []
    for _ in range(n_iterations):
        started = time.perf_counter_ns()
        sign_canonical_bytes(message, private_key)
        latencies.append((time.perf_counter_ns() - started) / 1_000_000)
    return _latency_summary(latencies, n_iterations)


def main():
    previous_data_dir = os.environ.get("FINGUARD_DATA_DIR")
    with tempfile.TemporaryDirectory(prefix="finguard-bench-") as temporary_dir:
        os.environ["FINGUARD_DATA_DIR"] = temporary_dir
        reset_config()
        reset_db()
        try:
            print("==================================================", flush=True)
            print("FIN//GUARD BASELINE BENCHMARK (ISOLATED TEMP DATA)", flush=True)
            print("==================================================", flush=True)

            print("\n--- 1. Decision Pipeline ---", flush=True)
            dec_res = benchmark_decision_pipeline(1000)
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
            print("\n--- 4. Money Parse and Format ---", flush=True)
            print(_latency_summary_to_line(benchmark_money()), flush=True)
            print("\n--- 5. Canonical v2 Hash ---", flush=True)
            print(_latency_summary_to_line(benchmark_canonical_hash()), flush=True)
            print("\n--- 6. Ed25519 Signature Generation ---", flush=True)
            print(_latency_summary_to_line(benchmark_signature_generation()), flush=True)
            print("==================================================", flush=True)
        finally:
            reset_db()
            reset_config()
            if previous_data_dir is None:
                os.environ.pop("FINGUARD_DATA_DIR", None)
            else:
                os.environ["FINGUARD_DATA_DIR"] = previous_data_dir


def _latency_summary_to_line(result):
    return f"N={result['n']} p50={result['p50_ms']} ms p95={result['p95_ms']} ms p99={result['p99_ms']} ms"


if __name__ == "__main__":
    main()
