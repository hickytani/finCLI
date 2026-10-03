# FIN//GUARD Investigation API — Contract Reference

> **Architecture Note**  
> FIN//GUARD is a Python CLI + library system. There is no HTTP server. "API" means the
> Python service class interface (`InvestigationService`, `IncidentService`) plus the
> `finguard investigate` CLI subcommand group.

---

## Investigation Service (`finguard.investigation.service.InvestigationService`)

### Constructor

```python
InvestigationService(session: Optional[sqlalchemy.orm.Session] = None)
```

Pass a session to participate in an outer transaction. If omitted, the service manages
its own sessions internally (open → close per call).

---

### 1. `get_incident_trace`

```python
def get_incident_trace(
    incident_id: str,
    owner_actor_id: Optional[str] = None,
) -> IncidentTrace
```

**Purpose**: Full forensic trace for a security incident.

**Traces**: incident → related transaction → security signals → decision receipt → audit entries

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `incident_id` | `str` | ✓ | The incident ID (e.g. `INC-ABC12345`) |
| `owner_actor_id` | `str` | ✗ | When supplied, raises `SecurityError` if incident's `actor_id` differs — IDOR protection |

**Returns**: `IncidentTrace` dataclass:
```python
@dataclass
class IncidentTrace:
    incident: IncidentRecord          # raw DB row
    transaction: Optional[TransactionSummary]
    signals: list[SignalSummary]      # bounded at 100
    receipt: Optional[ReceiptSummary]
    audit_entries: list[AuditSummary] # sorted by timestamp ASC
```

**Raises**:
- `SecurityError("Incident '...' not found.")` — on missing ID
- `SecurityError("Access denied: ...")` — on IDOR violation

**Guarantees**:
- `audit_entries` sorted chronologically ascending
- No duplicate audit entries (deduplicated by `entry_id`)
- All fields sourced from real DB rows — no fabricated data

---

### 2. `search_events`

```python
def search_events(
    actor_id: Optional[str] = None,
    state: Optional[str] = None,
    to_account: Optional[str] = None,
    from_account: Optional[str] = None,
    since: Optional[datetime.datetime] = None,
    until: Optional[datetime.datetime] = None,
    min_amount: Optional[float] = None,
    max_amount: Optional[float] = None,
    page: int = 1,
    page_size: int = 20,
    requesting_actor_id: Optional[str] = None,
) -> EventSearchResult
```

**Purpose**: Paginated, multi-filter search over security events (transactions).

**Filters**: All optional, combined with AND. See parameters table.

**Parameters**:
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `actor_id` | `str` | `None` | Filter by initiating actor |
| `state` | `str` | `None` | Filter by transaction state (`blocked`/`pending_approval`/etc.) |
| `to_account` | `str` | `None` | Filter by destination account |
| `from_account` | `str` | `None` | Filter by source account |
| `since` | `datetime` | `None` | UTC lower bound (inclusive) |
| `until` | `datetime` | `None` | UTC upper bound (inclusive) |
| `min_amount` | `float` | `None` | Minimum amount (inclusive) |
| `max_amount` | `float` | `None` | Maximum amount (inclusive) |
| `page` | `int` | `1` | 1-based page number (clamped to ≥ 1) |
| `page_size` | `int` | `20` | Rows per page — **capped at 100** |
| `requesting_actor_id` | `str` | `None` | When set: auto-scopes results to this actor; raises `SecurityError` if `actor_id` ≠ `requesting_actor_id` |

**Returns**: `EventSearchResult`:
```python
@dataclass
class EventSearchResult:
    items: list[TransactionSummary]
    total: int        # total matching rows (for computing page count)
    page: int         # effective page used
    page_size: int    # effective page size used (≤ 100)
    has_next: bool    # True if more pages exist
```

**Raises**:
- `SecurityError("Access denied: actor '...' may not query events belonging to actor '...'.")` — on cross-actor IDOR

**Guarantees**:
- `page_size` never exceeds 100
- Returns `items == []` with `has_next = False` when page is beyond total
- All results ordered by `timestamp DESC`

---

### 3. `get_actor_profile`

```python
def get_actor_profile(
    actor_id: str,
    requesting_actor_id: Optional[str] = None,
    tx_limit: int = 20,
    incident_limit: int = 20,
    audit_limit: int = 20,
) -> ActorProfile
```

**Purpose**: Security posture snapshot for a specific actor.

**Parameters**:
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `actor_id` | `str` | — | Actor to profile |
| `requesting_actor_id` | `str` | `None` | IDOR check: raises if differs from `actor_id` |
| `tx_limit` | `int` | `20` | Max recent transactions |
| `incident_limit` | `int` | `20` | Max incidents |
| `audit_limit` | `int` | `20` | Max audit entries |

**Returns**: `ActorProfile`:
```python
@dataclass
class ActorProfile:
    actor_id: str
    recent_transactions: list[TransactionSummary]  # bounded by tx_limit
    incidents: list[IncidentRecord]                # bounded by incident_limit
    signals: list[SignalSummary]                   # all signals on actor's transactions
    recent_audit: list[AuditSummary]               # bounded by audit_limit
    total_transactions_in_db: int                  # total count from DB
    open_incidents: int                            # count of non-terminal incidents
    risk_contributors: dict[str, int]              # {signal_type: occurrence_count}
```

**Raises**:
- `SecurityError("Access denied: actor '...' may not profile actor '...'.")` — on cross-actor IDOR

**Guarantees**:
- `risk_contributors` derived exclusively from stored `SecuritySignalRecord` rows
- No N+1 queries: signals fetched with a single batch IN query

---

### 4. `get_incident_timeline`

```python
def get_incident_timeline(
    incident_id: str,
    owner_actor_id: Optional[str] = None,
) -> list[TimelineItem]
```

**Purpose**: Deterministic chronological timeline for an incident, merging real records.

**Sources combined**:
1. Incident creation record
2. Related transaction (if linked)
3. Security signals on the transaction
4. Decision receipt
5. Relevant audit entries (transaction-scoped + incident lifecycle transitions)

**Returns**: `list[TimelineItem]` sorted by `(timestamp, source_type, source_id)`:
```python
@dataclass
class TimelineItem:
    timestamp: datetime.datetime   # real timestamp from source record
    source_type: str               # "incident" | "transaction" | "signal" | "receipt" | "audit"
    source_id: str                 # ID of originating record
    summary: str                   # human-readable description
    metadata: dict                 # additional fields from the source record
```

**Raises**:
- Same as `get_incident_trace` (delegates internally)

**Guarantees**:
- Every item has a non-None `timestamp` from a real DB record
- No fabricated entries
- Deterministic sort: same input always produces identical order

---

### 5. `get_transaction_trace`

```python
def get_transaction_trace(
    transaction_id: str,
    owner_actor_id: Optional[str] = None,
) -> dict[str, Any]
```

**Purpose**: Full forensic trace for a single transaction.

**Returns** dict with keys:
```python
{
    "transaction": TransactionSummary,
    "signals": list[SignalSummary],
    "receipt": Optional[ReceiptSummary],
    "incidents": list[IncidentRecord],
    "audit_entries": list[AuditSummary],
}
```

**Raises**:
- `SecurityError("Transaction '...' not found.")` — on missing ID
- `SecurityError("Access denied: ...")` — on IDOR violation

---

## Incident Service (`finguard.incidents.service.IncidentService`)

### `transition_incident`

```python
def transition_incident(
    incident_id: str,
    new_state: str,
    requesting_actor_id: str,
    note: Optional[str] = None,
) -> IncidentRecord
```

**Purpose**: Advance an incident through its lifecycle state machine.

**Valid transitions**:
```
open → investigating
open → resolved       (fast-path)
open → closed         (abandonment)
investigating → contained
investigating → resolved
investigating → closed
contained → resolved
contained → closed
resolved → closed     (archival)
```

**Terminal states**: `resolved`, `closed` — no further transitions.

**Idempotency**: Requesting the current state returns the record unchanged, creates no audit record.

**Raises**:
- `InvalidTransitionError` — on an invalid `from → to` transition
- `SecurityError("Incident '...' not found.")` — on missing incident

**Side effects on success**:
- `incident.state` updated in DB
- `incident.resolved_by` set to `requesting_actor_id`
- `incident.state_note` set to `note` (if provided)
- `incident.resolved_at` set when `new_state` ∈ `{resolved, closed}`
- `AuditLedger.append(action="INCIDENT_TRANSITION", ...)` called with metadata including `from_state`, `to_state`, `note`

---

## CLI Commands (`finguard investigate`)

| Command | Description |
|---------|-------------|
| `finguard investigate incident-trace <ID> [--json]` | Full incident forensic trace |
| `finguard investigate tx-trace <ID> [--json]` | Full transaction forensic trace |
| `finguard investigate events [--actor --state --to --from --since --until --min-amount --max-amount --page --page-size] [--json]` | Paginated event search |
| `finguard investigate actor-profile <ID> [--json]` | Actor security posture |
| `finguard investigate timeline <ID> [--json]` | Incident chronological timeline |
| `finguard investigate transition <ID> <new_state> --actor <ACTOR_ID> [--note TEXT] [--json]` | Lifecycle transition |

All commands support `--json` for machine-readable output.

---

## Database Indexes Added

| Index Name | Table | Column | Justification |
|------------|-------|--------|---------------|
| `ix_incidents_actor` | `incidents` | `actor_id` | Actor profile queries filter by actor |
| `ix_incidents_state` | `incidents` | `state` | `list_open()` filters by state set |
| `ix_incidents_transaction` | `incidents` | `transaction_id` | Incident→transaction lookup |
| `ix_signals_transaction` | `security_signals` | `transaction_id` | Batch signal lookup by TX ID |

---

## Security Guarantees

| Guarantee | Mechanism |
|-----------|-----------|
| Actor-scoped IDOR protection | `owner_actor_id` / `requesting_actor_id` parameter enforced via explicit `actor_id` field comparison before returning data |
| Unbounded query prevention | All collection queries enforce `limit` capped at `_INVESTIGATION_MAX_LIMIT = 500` |
| No N+1 queries | Batch relationships use SQLAlchemy IN queries (`get_by_transactions`, `get_by_transaction_ids`) |
| No fabricated data | Every field in every result dataclass sourced from a real DB row |
| Lifecycle audit trail | Every effective state transition appends a tamper-evident audit ledger entry |
| Idempotent transitions | Same-state requests return without writing; no duplicate audit entries |

---

## Genuine Remaining Limitations

- **No HTTP/REST API**: The investigation layer is a Python library + CLI. There is no web server, JWT authentication, or TLS termination.
- **No multi-tenant org model**: Isolation is per-actor (`actor_id`). There is no organization hierarchy or role-based access control (RBAC).
- **No IOC/Asset/Vulnerability schema**: These concepts are not in the existing SQLite schema. Mapping is: signals ↔ IOCs, transactions ↔ events, incidents ↔ incidents, actors ↔ identities.
- **No real-time streaming**: Event search is poll-based against SQLite. No WebSocket or Kafka feed.
- **SQLite only**: No multi-process write concurrency. WAL mode enabled. Production deployments should use PostgreSQL.
- **No threat intelligence integration**: There is no external feed. Signals are purely deterministic rule-based.
