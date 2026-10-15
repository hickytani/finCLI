from __future__ import annotations

import subprocess

from scripts.attack_loop import ATTACK_COMMAND, run_attack_loop


def test_attack_loop_runs_security_and_regression_suite_and_waits_between_runs() -> None:
    commands: list[tuple[list[str], str]] = []
    delays: list[float] = []

    def run(command, *, cwd, check):
        commands.append((command, str(cwd)))
        assert check is False
        return subprocess.CompletedProcess(command, 0)

    result = run_attack_loop(
        iterations=3,
        interval_seconds=2.0,
        run=run,
        sleep=delays.append,
    )

    assert result == 0
    assert len(commands) == 3
    assert all(
        command[-len(ATTACK_COMMAND) :] == list(ATTACK_COMMAND)
        for command, _ in commands
    )
    assert "tests/security" in ATTACK_COMMAND
    assert "tests/regression" in ATTACK_COMMAND
    assert delays == [2.0, 2.0]


def test_attack_loop_stops_on_first_failure_without_sleeping() -> None:
    attempts = 0
    delays: list[float] = []

    def run(command, *, cwd, check):
        nonlocal attempts
        attempts += 1
        return subprocess.CompletedProcess(command, 7 if attempts == 2 else 0)

    result = run_attack_loop(
        iterations=5,
        interval_seconds=2.0,
        run=run,
        sleep=delays.append,
    )

    assert result == 7
    assert attempts == 2
    assert delays == [2.0]


def test_attack_loop_rejects_nonpositive_iterations_and_negative_delay() -> None:
    import pytest

    with pytest.raises(ValueError):
        run_attack_loop(iterations=0, run=lambda *_args, **_kwargs: None, sleep=lambda _: None)
    with pytest.raises(ValueError):
        run_attack_loop(interval_seconds=-1, run=lambda *_args, **_kwargs: None, sleep=lambda _: None)
