from __future__ import annotations

import json
import math
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CHECK_SCRIPT = _REPO_ROOT / "scripts" / "check_coverage_threshold.py"


@pytest.mark.parametrize(
    ("percent_covered", "expected_returncode"),
    [(70.95, 1), (71.0, 0), (71.05, 0), (float("nan"), 1), (float("inf"), 1)],
)
def test_coverage_threshold_uses_exact_percentage(
    tmp_path: Path,
    percent_covered: float,
    expected_returncode: int,
) -> None:
    report_path = tmp_path / "coverage.json"
    report_path.write_text(
        json.dumps({"totals": {"percent_covered": percent_covered}}),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(_CHECK_SCRIPT), str(report_path)],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == expected_returncode
    if math.isfinite(percent_covered):
        assert f"{percent_covered:.5f}%" in result.stdout
    else:
        assert "coverage percentage must be finite" in result.stderr
