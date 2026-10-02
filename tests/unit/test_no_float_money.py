"""AST Static Regression Test to Enforce Zero Monetary Floats (test_no_float_money.py).

SECURITY INVARIANT (I8):
Monetary paths must use Money(minor_units: int, currency: Currency) or integer minor units.
No floating-point representation (float) is permitted in money calculations or canonical representations.

Non-money floats (such as risk score weights, AI confidence, or benchmark timers) are documented in ALLOWLIST.
"""

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FINGUARD_DIR = REPO_ROOT / "finguard"

# Allowlist for files/nodes where float is explicitly allowed for NON-MONEY purposes
# Each entry requires an explicit justification comment.
ALLOWLIST = {
    "finguard/ai/schemas.py": ["confidence"],  # AI model confidence score [0.0, 1.0]
    "finguard/risk/engine.py": ["weights", "score", "risk_score"],  # Risk evaluation weights and normalized risk scores
    "finguard/detection/": [],  # Security signal detection thresholds
}


def test_no_float_in_authoritative_money_paths():
    """Reject float conversions and money declarations while allowing explicit input rejection."""
    target_modules = [
        FINGUARD_DIR / "money.py",
        FINGUARD_DIR / "core" / "canonical.py",
        FINGUARD_DIR / "core" / "transaction.py",
        FINGUARD_DIR / "decision" / "engine.py",
        FINGUARD_DIR / "signing" / "gate.py",
        FINGUARD_DIR / "simulator" / "service.py",
        FINGUARD_DIR / "attacks" / "scenario_loader.py",
        FINGUARD_DIR / "policy" / "schema.py",
        FINGUARD_DIR / "policy" / "rules.py",
        FINGUARD_DIR / "identity" / "registry.py",
    ]

    violations = []
    for filepath in target_modules:
        if not filepath.exists():
            continue
        rel_path = filepath.relative_to(REPO_ROOT).as_posix()
        content = filepath.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=rel_path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "float":
                violations.append(f"{rel_path}:{node.lineno}: float() conversion")
            if isinstance(node, ast.arg) and isinstance(node.annotation, ast.Name) and node.annotation.id == "float":
                violations.append(f"{rel_path}:{node.lineno}: float parameter annotation")
            if isinstance(node, (ast.AnnAssign, ast.Assign)):
                annotation = getattr(node, "annotation", None)
                target = node.target if isinstance(node, ast.AnnAssign) else node.targets[0]
                if isinstance(annotation, ast.Name) and annotation.id == "float":
                    violations.append(f"{rel_path}:{node.lineno}: float variable annotation")
                if (
                    isinstance(target, ast.Name)
                    and target.id in {"amount", "authority_limit", "balance", "max_amount"}
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, float)
                ):
                    violations.append(f"{rel_path}:{node.lineno}: float monetary default")

    assert not violations, "Forbidden float usage detected in monetary core modules:\n" + "\n".join(violations)
