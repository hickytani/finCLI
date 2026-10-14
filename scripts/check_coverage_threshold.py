from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

MINIMUM_COVERAGE_PERCENT = 71.0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    report_path = parser.parse_args().report

    with report_path.open(encoding="utf-8") as report_file:
        report = json.load(report_file)

    totals = report.get("totals")
    if not isinstance(totals, dict):
        raise TypeError("coverage JSON is missing the totals object")
    percent = totals.get("percent_covered")
    if isinstance(percent, bool) or not isinstance(percent, (int, float)):
        raise TypeError("coverage JSON has no numeric totals.percent_covered value")
    if not math.isfinite(percent) or not 0 <= percent <= 100:
        raise ValueError("coverage percentage must be finite and between 0 and 100")

    print(f"Exact branch coverage: {percent:.5f}% (required: {MINIMUM_COVERAGE_PERCENT:.0f}%)")
    if percent < MINIMUM_COVERAGE_PERCENT:
        print("Exact branch coverage threshold not reached", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
