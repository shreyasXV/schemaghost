# FaultWall SQLite State Layer — PR 2 Design Notes

**Status:** In-PR (this PR)
**Precedes:** PR 3 (JWT auth)
**Driver:** `modernc.org/sqlite` (pure Go, no CGO — preserves single-binary story)

## Goals

1. **Agent registry** — persist agent metadata (id, created timestamp, public key fingerprint, policy reference, revoked flag). Survives restarts.
2. **JTI denylist** — persist revoked JWT IDs with their expiration, so expired entries can be pruned.
3. **Schema migrations** — versioned DDL with a `schema_version` table so future PRs can evolve shape safely.
4. **No API surface change yet** — this PR only adds the package. Wiring into `identity.go` / `auth.go` happens in PR 3.

## Schema (v1)

```sql
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL          -- unix seconds, UTC
);

CREATE TABLE IF NOT EXISTS agents (
    id             TEXT PRIMARY KEY,      -- agent_id claim value
    created_at     INTEGER NOT NULL,      -- unix seconds, UTC
    pubkey_fp      TEXT NOT NULL,         -- SHA-256 fingerprint of signing key (hex)
    policy_id      TEXT NOT NULL,         -- maps to agents: key in policies.yaml
    description    TEXT DEFAULT '',
    revoked        INTEGER NOT NULL DEFAULT 0,  -- 0 = active, 1 = revoked
    revoked_at     INTEGER                       -- nullable
);

CREATE INDEX IF NOT EXISTS idx_agents_revoked ON agents(revoked);

CREATE TABLE IF NOT EXISTS jti_denylist (
    jti        TEXT PRIMARY KEY,           -- JWT ID (UUIDv4 or similar)
    agent_id   TEXT NOT NULL,              -- denormalized for fast per-agent revoke-all
    expires_at INTEGER NOT NULL,           -- unix seconds, UTC; pruned when < now()
    reason     TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_jti_expires ON jti_denylist(expires_at);
CREATE INDEX IF NOT EXISTS idx_jti_agent   ON jti_denylist(agent_id);
```

Rationale:
- **Unix seconds** for timestamps — portable, sortable, no TZ bugs. Dashboard can render locally.
- **pubkey_fp** (not full key) in agents table — **forward-looking for v2.2 RS256**. v2.1 uses HS256 with a single server-side shared secret (spec §3.3), so for v2.1 this column will be the same static fingerprint for every agent. Carrying the column now means no schema migration when we flip to per-agent asymmetric signing in v2.2. For v2.1 deployments it is effectively unused but harmless.
- **policy_id** references YAML — the YAML stays source of truth for the *rules*; SQLite tracks the *identity* of agents that have ever existed.
- **Denormalized agent_id** on jti_denylist — lets "revoke all tokens for agent X" be a single indexed scan.
- **Partial index on `agents.revoked`** — we only index `WHERE revoked = 1`. Most rows are `revoked = 0`; a full index on this column would be low-cardinality and the planner would skip it. Partial index gives O(k) lookups where k = count of revoked agents.

## Denylist growth model

`jti_denylist` is bounded because:

1. Every insert sets `expires_at` to a future time bounded by the JWT's original expiration (default 90 days per spec §4).
2. `PruneExpiredJTIs` is caller-scheduled (run every 15 min in the proxy) and deletes rows where `expires_at <= now`.
3. Maximum steady-state row count ≈ (max JTI TTL) × (revocation rate). At 90-day TTL and 10 revocations/day that's ≤ 900 rows — trivial.

Out-of-scope threat: a malicious admin inserting 1M bogus JTIs. This requires admin creds (not an unauthenticated attack surface) and the prune job will drain them within one TTL window. Document rate-limiting at the admin endpoint in PR 4 if we care.

## Migration Strategy

- Single `Migrate(db)` function runs at open time.
- Inserts `(version, now)` into `schema_version` after each DDL block.
- v1 is the only migration in this PR. Future PRs append v2, v3 blocks guarded by `SELECT MAX(version) FROM schema_version`.
- No down-migrations. If we need to roll back schema, we'll hand-write it.

## API Surface (PR 2 only)

```go
type Store struct { db *sql.DB }

func Open(path string) (*Store, error)                  // opens + migrates
func (s *Store) Close() error

// Agents
func (s *Store) PutAgent(ctx, Agent) error              // upsert
func (s *Store) GetAgent(ctx, id string) (Agent, error) // not found → ErrNotFound
func (s *Store) ListAgents(ctx) ([]Agent, error)        // active + revoked
func (s *Store) RevokeAgent(ctx, id string) error

// JTI denylist
func (s *Store) DenyJTI(ctx, jti, agentID string, exp time.Time, reason string) error
func (s *Store) IsJTIDenied(ctx, jti string) (bool, error)
func (s *Store) PruneExpiredJTIs(ctx) (int64, error)    // returns rows deleted
```

Errors use sentinel `ErrNotFound` wrapped with `%w` so callers can `errors.Is`.

## Concurrency

- `modernc.org/sqlite` supports `SQLITE_OPEN_FULLMUTEX`. We open with `?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)` for multi-reader one-writer.
- All methods take a `context.Context` for cancellation from HTTP/RPC handlers.
- `Store` struct is safe for concurrent use (backed by `sql.DB` pool).

## What's NOT in this PR

- No wiring into `main.go` or existing code — this is a dormant library until PR 3 imports it.
- No JWT handling — PR 3.
- No admin CLI commands — PR 4.
- No web endpoints — future.
