// Package store implements a SQLite-backed persistence layer for FaultWall
// agent records and JWT ID (JTI) denylist entries.
//
// Driver: modernc.org/sqlite (pure Go, no CGO). Preserves FaultWall's
// single-binary story while giving us SQL query power for future analytics.
//
// This package is dormant in PR 2 — no callers yet. PR 3 (JWT auth) will
// import it from identity.go and the new internal/auth package.
//
// See DESIGN.md in this directory for schema rationale.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a lookup finds no matching row.
var ErrNotFound = errors.New("store: not found")

// Store is a handle to the SQLite state database.
// Zero value is not usable; call Open.
type Store struct {
	db *sql.DB
}

// Agent is a persisted agent record.
type Agent struct {
	ID          string    // agent_id, primary key
	CreatedAt   time.Time // UTC
	PubkeyFP    string    // hex-encoded SHA-256 fingerprint of signing key
	PolicyID    string    // maps to agents: key in policies.yaml
	Description string    // free-text, optional
	Revoked     bool
	RevokedAt   time.Time // zero value if not revoked
}

// Open opens (or creates) a SQLite database at path and applies migrations.
// The caller must Close the returned Store.
//
// Path may be ":memory:" for ephemeral/test use.
func Open(path string) (*Store, error) {
	// WAL + busy_timeout give us multi-reader/single-writer with graceful
	// contention handling. _pragma params are modernc-specific.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	if path == ":memory:" {
		// WAL isn't meaningful for :memory:; skip it.
		dsn = path
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	// sql.Open is lazy; force a round-trip so bad paths fail loudly here.
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// ── Migrations ─────────────────────────────────────────────────────────

// currentSchemaVersion is bumped by future PRs as new DDL blocks are added.
const currentSchemaVersion = 1

func (s *Store) migrate(ctx context.Context) error {
	// schema_version bootstrap — always safe to run.
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_version (
			version    INTEGER PRIMARY KEY,
			applied_at INTEGER NOT NULL
		);
	`); err != nil {
		return fmt.Errorf("store: migrate schema_version: %w", err)
	}
	applied, err := s.appliedVersion(ctx)
	if err != nil {
		return err
	}
	if applied >= currentSchemaVersion {
		return nil
	}
	// Run every migration in (applied, currentSchemaVersion].
	for v := applied + 1; v <= currentSchemaVersion; v++ {
		ddl, ok := migrations[v]
		if !ok {
			return fmt.Errorf("store: no migration registered for v%d", v)
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("store: begin v%d: %w", v, err)
		}
		if _, err := tx.ExecContext(ctx, ddl); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: apply v%d: %w", v, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_version (version, applied_at) VALUES (?, ?)`,
			v, time.Now().UTC().Unix()); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: record v%d: %w", v, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: commit v%d: %w", v, err)
		}
	}
	return nil
}

func (s *Store) appliedVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_version`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("store: read schema_version: %w", err)
	}
	if !v.Valid {
		return 0, nil
	}
	return int(v.Int64), nil
}

// migrations is keyed by version; each entry is the DDL for that version.
// Future PRs append v2, v3, ...
var migrations = map[int]string{
	1: `
		CREATE TABLE IF NOT EXISTS agents (
			id          TEXT PRIMARY KEY,
			created_at  INTEGER NOT NULL,
			pubkey_fp   TEXT NOT NULL,
			policy_id   TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			revoked     INTEGER NOT NULL DEFAULT 0,
			revoked_at  INTEGER
		);
		-- Partial index: only index revoked rows. revoked=0 is the common case
		-- and would make a full index low-cardinality and useless; the planner
		-- would skip it. Partial index gives O(k) lookups over revoked agents
		-- where k is the count of revoked rows, not n.
		CREATE INDEX IF NOT EXISTS idx_agents_revoked ON agents(revoked) WHERE revoked = 1;

		CREATE TABLE IF NOT EXISTS jti_denylist (
			jti        TEXT PRIMARY KEY,
			agent_id   TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			reason     TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_jti_expires ON jti_denylist(expires_at);
		CREATE INDEX IF NOT EXISTS idx_jti_agent   ON jti_denylist(agent_id);
	`,
}

// ── Agents ────────────────────────────────────────────────────────────

// PutAgent upserts an agent record. On conflict (same id) every field except
// created_at is overwritten; created_at is preserved from the existing row.
func (s *Store) PutAgent(ctx context.Context, a Agent) error {
	if a.ID == "" {
		return errors.New("store: PutAgent: empty id")
	}
	createdAt := a.CreatedAt.UTC().Unix()
	if a.CreatedAt.IsZero() {
		createdAt = time.Now().UTC().Unix()
	}
	var revokedAt sql.NullInt64
	if !a.RevokedAt.IsZero() {
		revokedAt = sql.NullInt64{Int64: a.RevokedAt.UTC().Unix(), Valid: true}
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO agents (id, created_at, pubkey_fp, policy_id, description, revoked, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			-- NOTE: created_at is intentionally NOT in this SET list.
			-- On update we preserve the original creation timestamp so audit
			-- history survives re-registration. See TestPutAgent_UpsertPreservesCreatedAt.
			pubkey_fp   = excluded.pubkey_fp,
			policy_id   = excluded.policy_id,
			description = excluded.description,
			revoked     = excluded.revoked,
			revoked_at  = excluded.revoked_at
	`, a.ID, createdAt, a.PubkeyFP, a.PolicyID, a.Description, boolToInt(a.Revoked), revokedAt)
	if err != nil {
		return fmt.Errorf("store: PutAgent: %w", err)
	}
	return nil
}

// GetAgent fetches an agent by id. Returns ErrNotFound if no row matches.
func (s *Store) GetAgent(ctx context.Context, id string) (Agent, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, created_at, pubkey_fp, policy_id, description, revoked, revoked_at
		FROM agents WHERE id = ?
	`, id)
	return scanAgent(row)
}

// ListAgents returns every agent (active and revoked), ordered by created_at ascending.
func (s *Store) ListAgents(ctx context.Context) ([]Agent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, created_at, pubkey_fp, policy_id, description, revoked, revoked_at
		FROM agents ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("store: ListAgents: %w", err)
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RevokeAgent marks an agent as revoked. No-op if already revoked.
// Returns ErrNotFound if the agent does not exist.
func (s *Store) RevokeAgent(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE agents
		SET revoked = 1, revoked_at = ?
		WHERE id = ? AND revoked = 0
	`, time.Now().UTC().Unix(), id)
	if err != nil {
		return fmt.Errorf("store: RevokeAgent: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Could be "already revoked" or "not found". Disambiguate with a lookup.
		if _, gerr := s.GetAgent(ctx, id); errors.Is(gerr, ErrNotFound) {
			return ErrNotFound
		}
	}
	return nil
}

// ── JTI denylist ──────────────────────────────────────────────────────

// DenyJTI inserts a JTI into the denylist. Upsert semantics: re-denying an
// existing jti updates expires_at and reason.
func (s *Store) DenyJTI(ctx context.Context, jti, agentID string, expiresAt time.Time, reason string) error {
	if jti == "" {
		return errors.New("store: DenyJTI: empty jti")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO jti_denylist (jti, agent_id, expires_at, reason)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(jti) DO UPDATE SET
			expires_at = excluded.expires_at,
			reason     = excluded.reason
	`, jti, agentID, expiresAt.UTC().Unix(), reason)
	if err != nil {
		return fmt.Errorf("store: DenyJTI: %w", err)
	}
	return nil
}

// IsJTIDenied reports whether the given jti is currently denied.
// A row is considered denied only if expires_at > now; expired rows return false
// even if present (PruneExpiredJTIs will eventually remove them).
//
// Intentional race: the expiry comparison is eventually consistent with
// concurrent DenyJTI / PruneExpiredJTIs writers. For a denylist this is
// acceptable — worst case a just-revoked token works for a few more ms on one
// in-flight connection. Fixing it would require SERIALIZABLE isolation on the
// hot path, which is not worth it. Do not "fix" this without a security
// requirement that justifies the cost.
func (s *Store) IsJTIDenied(ctx context.Context, jti string) (bool, error) {
	var exp int64
	err := s.db.QueryRowContext(ctx,
		`SELECT expires_at FROM jti_denylist WHERE jti = ?`, jti).Scan(&exp)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: IsJTIDenied: %w", err)
	}
	return exp > time.Now().UTC().Unix(), nil
}

// PruneExpiredJTIs deletes denylist entries whose expires_at has passed.
// Intended to be called periodically (e.g. every 15 min) from a background goroutine.
func (s *Store) PruneExpiredJTIs(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM jti_denylist WHERE expires_at <= ?`,
		time.Now().UTC().Unix())
	if err != nil {
		return 0, fmt.Errorf("store: PruneExpiredJTIs: %w", err)
	}
	return res.RowsAffected()
}

// ── helpers ───────────────────────────────────────────────────────────

// rowScanner lets scanAgent work with both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanAgent(s rowScanner) (Agent, error) {
	var a Agent
	var createdAt int64
	var revokedInt int
	var revokedAt sql.NullInt64
	err := s.Scan(&a.ID, &createdAt, &a.PubkeyFP, &a.PolicyID, &a.Description, &revokedInt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Agent{}, ErrNotFound
	}
	if err != nil {
		return Agent{}, fmt.Errorf("store: scan agent: %w", err)
	}
	a.CreatedAt = time.Unix(createdAt, 0).UTC()
	a.Revoked = revokedInt != 0
	if revokedAt.Valid {
		a.RevokedAt = time.Unix(revokedAt.Int64, 0).UTC()
	}
	return a, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
