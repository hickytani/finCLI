"""FG-804: Validate that every backtick-quoted test name cited in
docs/INVARIANTS.md actually exists as a test function in the tests/ tree.

Exit 0 if all cited tests are found.
Exit 1 if any cited test is missing, printing a clear list.

This script is run by `make invariants` and `make docs`, and is also
expected to be a CI gate (added to the ci.yml workflow).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INVARIANTS_FILE = REPO_ROOT / "docs" / "INVARIANTS.md"
TESTS_DIR = REPO_ROOT / "tests"


def collect_cited_tests(invariants_path: Path) -> set[str]:
    """Extract backtick-quoted identifiers starting with 'test_' from INVARIANTS.md."""
    text = invariants_path.read_text(encoding="utf-8")
    # Match `test_something` or `test_something_else`
    return set(re.findall(r"`(test_[a-zA-Z0-9_]+)`", text))


def collect_defined_tests(tests_dir: Path) -> set[str]:
    """Collect all `def test_*` function names across the test tree."""
    defined: set[str] = set()
    for py_file in tests_dir.rglob("*.py"):
        for match in re.finditer(r"^def (test_[a-zA-Z0-9_]+)\b", py_file.read_text(encoding="utf-8"), re.MULTILINE):
            defined.add(match.group(1))
    return defined


def main() -> int:
    cited = collect_cited_tests(INVARIANTS_FILE)
    defined = collect_defined_tests(TESTS_DIR)
    missing = sorted(cited - defined)

    if missing:
        print(f"[check_invariants] FAIL: {len(missing)} test(s) cited in INVARIANTS.md but not found in tests/:")
        for name in missing:
            print(f"  MISSING: {name}")
        print()
        print("  Fix: write the test, or downgrade the invariant status from 'Proven' to 'Partial'.")
        return 1

    print(f"[check_invariants] OK: all {len(cited)} cited tests found in tests/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
