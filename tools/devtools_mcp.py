"""Engineering Dev-Tools MCP Server for FIN//GUARD (tools/devtools_mcp.py).

Provides typed MCP tool interfaces for orchestrators, builders, and attackers:
- run_tests(tier): execute test tiers T0, T1, T2, T3
- run_attacks(category): execute attack scenario suites
- run_bench(): execute scripts/bench.py baseline performance suite
- invariant_status(): view status of security invariants I1-I14
- list_open_tickets(): view active/pending tickets in .agent/TASKS.md
"""

import subprocess
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("FIN//GUARD Engineering DevTools")

REPO_ROOT = Path(__file__).resolve().parent.parent


def _validate_path(path: Path) -> None:
    """Path jail check: refuse access outside repo root."""
    try:
        path.resolve().relative_to(REPO_ROOT)
    except ValueError:
        raise ValueError(f"Path jail violation: {path} is outside repository root {REPO_ROOT}")


@mcp.tool()
def run_tests(tier: str = "T1") -> str:
    """Execute test suites by tier: T0 (fast), T1 (commit gate), T2 (PR gate), T3 (nightly)."""
    tier_upper = tier.upper()
    venv_python = REPO_ROOT / ".venv" / "Scripts" / "python.exe"
    python_cmd = str(venv_python) if venv_python.exists() else sys.executable

    if tier_upper == "T0":
        cmd = [python_cmd, "-m", "pytest", "-q", "-m", "not slow", "tests/unit"]
    elif tier_upper == "T1":
        cmd = [python_cmd, "-m", "pytest", "-v", "tests/unit", "tests/regression"]
    elif tier_upper == "T2":
        cmd = [python_cmd, "-m", "pytest", "-v", "--cov=finguard", "tests/"]
    elif tier_upper == "T3":
        cmd = [python_cmd, "-m", "pytest", "-v", "--cov=finguard", "--hypothesis-profile=ci", "tests/"]
    else:
        return f"Unknown tier '{tier}'. Supported tiers: T0, T1, T2, T3."

    res = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    return f"Exit Code: {res.returncode}\n\nSTDOUT:\n{res.stdout[:4000]}\n\nSTDERR:\n{res.stderr[:2000]}"


@mcp.tool()
def run_attacks(category: str = "all") -> str:
    """Execute FIN//GUARD attack scenarios or attack regression tests."""
    venv_python = REPO_ROOT / ".venv" / "Scripts" / "python.exe"
    python_cmd = str(venv_python) if venv_python.exists() else sys.executable

    cmd = [python_cmd, "-m", "pytest", "-v", "tests/unit/test_product_redteam.py", "tests/regression/"]
    res = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    return f"Exit Code: {res.returncode}\n\nOutput:\n{res.stdout[:4000]}"


@mcp.tool()
def run_bench() -> str:
    """Execute scripts/bench.py baseline benchmark."""
    venv_python = REPO_ROOT / ".venv" / "Scripts" / "python.exe"
    python_cmd = str(venv_python) if venv_python.exists() else sys.executable

    cmd = [python_cmd, "scripts/bench.py"]
    res = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    return res.stdout if res.returncode == 0 else f"Benchmark failed:\n{res.stderr}"


@mcp.tool()
def invariant_status() -> str:
    """Read the security invariants status matrix from docs/INVARIANTS.md."""
    inv_file = REPO_ROOT / "docs" / "INVARIANTS.md"
    _validate_path(inv_file)
    if not inv_file.exists():
        return "docs/INVARIANTS.md does not exist."
    return inv_file.read_text(encoding="utf-8")


@mcp.tool()
def list_open_tickets() -> str:
    """Read active/pending backlog items from .agent/TASKS.md."""
    tasks_file = REPO_ROOT / ".agent" / "TASKS.md"
    _validate_path(tasks_file)
    if not tasks_file.exists():
        return ".agent/TASKS.md does not exist."
    return tasks_file.read_text(encoding="utf-8")


if __name__ == "__main__":
    mcp.run()
