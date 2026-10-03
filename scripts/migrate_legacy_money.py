"""Dry-run-first CLI for auditing or applying the legacy money migration."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from finguard.storage.money_migration import migrate_legacy_money


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database",
        type=Path,
        default=Path(".finguard/finguard.db"),
        help="SQLite database path (default: .finguard/finguard.db)",
    )
    parser.add_argument("--apply", action="store_true", help="Apply changes after making a backup")
    parser.add_argument("--backup", type=Path, help="New SQLite backup destination required with --apply")
    args = parser.parse_args()
    report = migrate_legacy_money(
        args.database,
        dry_run=not args.apply,
        backup_path=args.backup,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
