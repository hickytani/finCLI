"""Repeat the fixed security and regression suites until failure or interruption."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ATTACK_COMMAND = (
    "-m",
    "pytest",
    "-q",
    "tests/security",
    "tests/regression",
)


def run_attack_loop(
    *,
    iterations: int | None = None,
    interval_seconds: float = 2.0,
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Run fixed security/regression tests repeatedly; stop on the first failure."""
    if iterations is not None and iterations <= 0:
        raise ValueError("iterations must be positive when provided")
    if interval_seconds < 0:
        raise ValueError("interval_seconds cannot be negative")

    completed_iterations = 0
    command = [sys.executable, *ATTACK_COMMAND]
    while iterations is None or completed_iterations < iterations:
        result = run(command, cwd=REPO_ROOT, check=False)
        if result.returncode:
            return result.returncode
        completed_iterations += 1
        if iterations is None or completed_iterations < iterations:
            sleep(interval_seconds)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--iterations",
        type=int,
        help="Stop after this many successful iterations (default: repeat until failure).",
    )
    parser.add_argument(
        "--interval-seconds",
        type=float,
        default=2.0,
        help="Delay between successful iterations (default: 2 seconds).",
    )
    args = parser.parse_args(argv)
    return run_attack_loop(
        iterations=args.iterations,
        interval_seconds=args.interval_seconds,
    )


if __name__ == "__main__":
    raise SystemExit(main())
