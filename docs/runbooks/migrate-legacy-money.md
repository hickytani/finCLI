# Runbook: Legacy Transaction Money Migration

## Purpose and Limits

This migration classifies pre-v2 SQLite `transactions.amount` values and
backfills `amount_minor` only when the value represented by the stored binary
float is exactly an integer number of currency minor units. Inexact values are
recorded in `legacy_money_quarantine`; they are never rounded. Existing
CREATED, PENDING_APPROVAL, and APPROVED rows are marked FAILED with
`MIGRATED_REQUIRES_RESUBMIT`, because old approvals were bound to v1 bytes.
Existing records retain canonical version 1. This migration does not make
legacy rows signable or executable.

## Dry Run

First stop all FIN//GUARD processes using the database and run:

```powershell
python scripts/migrate_legacy_money.py --database .finguard/finguard.db
```

The command prints a JSON report and does not modify the database. Review every
`rows_quarantined` and `rows_failed_resubmit` entry. A missing database/schema
is an error, not a successful empty migration.

## Apply

Choose a new backup path that does not already exist, then run:

```powershell
python scripts/migrate_legacy_money.py `
  --database .finguard/finguard.db `
  --apply `
  --backup .finguard/backups/finguard-before-money-migration.db
```

Apply mode requires the backup path and uses SQLite's online backup API before
any schema/data writes. It then adds `amount_minor`, `canonical_version`, and
`failure_reason` when absent, backfills exact rows, records inexact rows in the
quarantine table, and fails unsigned legacy requests closed. The report lists
migrated, quarantined, and resubmit-required transaction IDs. Keep the backup
and report together for review.

## Recovery and Constraints

- Do not delete or edit quarantined source rows automatically. Reconstruct the
  request from trusted business evidence and resubmit it as a new v2 transaction.
- If apply fails, it rolls back its SQLite transaction. The pre-migration
  backup remains available; do not restore it over an active database.
- Run the command again with a new backup path only after reviewing the prior
  report. Exact backfills and quarantines are idempotent.
- This script is not a concurrent online migration. Stop all application
  writers first.
- The legacy Float column remains for old readers/schema compatibility and is
  non-authoritative. Every new security decision uses `amount_minor`.
- Migration only adds columns and quarantine records. It does not rebuild a
  legacy table, create an externally signed ledger checkpoint, or prove
  integrity against a privileged database-file attacker.
