package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// newTestStore opens a fresh :memory: store per test. Each test gets isolation.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open(:memory:): %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpen_FileBacked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Reopen — migrations must be idempotent.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	v, err := s2.appliedVersion(context.Background())
	if err != nil {
		t.Fatalf("appliedVersion: %v", err)
	}
	if v != currentSchemaVersion {
		t.Errorf("schema version = %d; want %d", v, currentSchemaVersion)
	}
}

func TestMigrate_Idempotent(t *testing.T) {
	s := newTestStore(t)
	// Running migrate again should be a no-op and produce no error.
	if err := s.migrate(context.Background()); err != nil {
		t.Fatalf("second migrate failed: %v", err)
	}
	v, err := s.appliedVersion(context.Background())
	if err != nil {
		t.Fatalf("appliedVersion: %v", err)
	}
	if v != currentSchemaVersion {
		t.Errorf("version after double-migrate = %d; want %d", v, currentSchemaVersion)
	}
}

func TestPutAndGetAgent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	in := Agent{
		ID:          "claude-code-prod",
		CreatedAt:   now,
		PubkeyFP:    "sha256:deadbeef",
		PolicyID:    "readonly",
		Description: "prod Claude Code agent",
	}
	if err := s.PutAgent(ctx, in); err != nil {
		t.Fatalf("PutAgent: %v", err)
	}

	got, err := s.GetAgent(ctx, "claude-code-prod")
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if got.ID != in.ID || got.PubkeyFP != in.PubkeyFP || got.PolicyID != in.PolicyID ||
		got.Description != in.Description || got.Revoked != false {
		t.Errorf("round-trip mismatch: got %+v want %+v", got, in)
	}
	if !got.CreatedAt.Equal(now) {
		t.Errorf("created_at: got %v want %v", got.CreatedAt, now)
	}
	if !got.RevokedAt.IsZero() {
		t.Errorf("expected zero revoked_at, got %v", got.RevokedAt)
	}
}

func TestGetAgent_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetAgent(context.Background(), "ghost")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestPutAgent_EmptyIDRejected(t *testing.T) {
	s := newTestStore(t)
	err := s.PutAgent(context.Background(), Agent{ID: "", PubkeyFP: "x", PolicyID: "y"})
	if err == nil {
		t.Fatal("expected error for empty id, got nil")
	}
}

func TestPutAgent_UpsertPreservesCreatedAt(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	first := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)

	if err := s.PutAgent(ctx, Agent{
		ID: "a1", CreatedAt: first, PubkeyFP: "fp1", PolicyID: "p1",
	}); err != nil {
		t.Fatal(err)
	}
	// Upsert with different policy and later CreatedAt — expect policy to change
	// but (per spec) created_at to follow the new write since the current impl
	// overwrites. Track actual behavior so future changes are deliberate.
	later := time.Now().UTC().Truncate(time.Second)
	if err := s.PutAgent(ctx, Agent{
		ID: "a1", CreatedAt: later, PubkeyFP: "fp1", PolicyID: "p2",
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetAgent(ctx, "a1")
	if err != nil {
		t.Fatal(err)
	}
	if got.PolicyID != "p2" {
		t.Errorf("policy_id should have been updated to p2, got %s", got.PolicyID)
	}
	// Current DDL: ON CONFLICT does NOT update created_at → preserved.
	if !got.CreatedAt.Equal(first) {
		t.Errorf("created_at should be preserved on upsert: got %v want %v", got.CreatedAt, first)
	}
}

func TestListAgents_Ordering(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second)

	agents := []Agent{
		{ID: "a2", CreatedAt: base.Add(2 * time.Second), PubkeyFP: "fp", PolicyID: "p"},
		{ID: "a1", CreatedAt: base.Add(1 * time.Second), PubkeyFP: "fp", PolicyID: "p"},
		{ID: "a3", CreatedAt: base.Add(3 * time.Second), PubkeyFP: "fp", PolicyID: "p"},
	}
	for _, a := range agents {
		if err := s.PutAgent(ctx, a); err != nil {
			t.Fatalf("PutAgent %s: %v", a.ID, err)
		}
	}
	out, err := s.ListAgents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("ListAgents len = %d; want 3", len(out))
	}
	want := []string{"a1", "a2", "a3"}
	for i, a := range out {
		if a.ID != want[i] {
			t.Errorf("pos %d: got %s; want %s", i, a.ID, want[i])
		}
	}
}

func TestRevokeAgent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.PutAgent(ctx, Agent{ID: "rev1", PubkeyFP: "fp", PolicyID: "p"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAgent(ctx, "rev1"); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}
	got, err := s.GetAgent(ctx, "rev1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Revoked {
		t.Error("agent should be revoked=true")
	}
	if got.RevokedAt.IsZero() {
		t.Error("revoked_at should be set")
	}

	// Revoking again is a no-op, not an error.
	if err := s.RevokeAgent(ctx, "rev1"); err != nil {
		t.Errorf("second revoke should be no-op, got: %v", err)
	}
}

func TestRevokeAgent_NotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.RevokeAgent(context.Background(), "ghost")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestDenyAndCheckJTI(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	exp := time.Now().UTC().Add(10 * time.Minute)

	if err := s.DenyJTI(ctx, "jti-1", "agent-1", exp, "manual revoke"); err != nil {
		t.Fatalf("DenyJTI: %v", err)
	}
	denied, err := s.IsJTIDenied(ctx, "jti-1")
	if err != nil {
		t.Fatal(err)
	}
	if !denied {
		t.Error("jti-1 should be denied")
	}
	// Unknown jti is not denied.
	denied, err = s.IsJTIDenied(ctx, "jti-unknown")
	if err != nil {
		t.Fatal(err)
	}
	if denied {
		t.Error("unknown jti should not be denied")
	}
}

func TestIsJTIDenied_ExpiredRowNotDenied(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	past := time.Now().UTC().Add(-1 * time.Hour)

	if err := s.DenyJTI(ctx, "jti-old", "agent-1", past, "expired"); err != nil {
		t.Fatal(err)
	}
	denied, err := s.IsJTIDenied(ctx, "jti-old")
	if err != nil {
		t.Fatal(err)
	}
	if denied {
		t.Error("expired jti row should return denied=false")
	}
}

func TestDenyJTI_UpsertUpdatesExpiry(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	past := time.Now().UTC().Add(-time.Hour)
	future := time.Now().UTC().Add(time.Hour)

	// First deny with a past expiry — should read as not denied.
	if err := s.DenyJTI(ctx, "j", "a", past, ""); err != nil {
		t.Fatal(err)
	}
	if denied, _ := s.IsJTIDenied(ctx, "j"); denied {
		t.Fatal("expected not denied on past row")
	}
	// Re-deny with future expiry — upsert should now show denied.
	if err := s.DenyJTI(ctx, "j", "a", future, "re-revoked"); err != nil {
		t.Fatal(err)
	}
	if denied, _ := s.IsJTIDenied(ctx, "j"); !denied {
		t.Error("expected denied after upsert with future expiry")
	}
}

func TestDenyJTI_EmptyJTIRejected(t *testing.T) {
	s := newTestStore(t)
	if err := s.DenyJTI(context.Background(), "", "a", time.Now().Add(time.Hour), ""); err == nil {
		t.Error("expected error for empty jti")
	}
}

func TestPruneExpiredJTIs(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	past := time.Now().UTC().Add(-time.Hour)
	future := time.Now().UTC().Add(time.Hour)

	entries := []struct {
		jti string
		exp time.Time
	}{
		{"old-1", past},
		{"old-2", past},
		{"keep-1", future},
	}
	for _, e := range entries {
		if err := s.DenyJTI(ctx, e.jti, "a", e.exp, ""); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.PruneExpiredJTIs(ctx)
	if err != nil {
		t.Fatalf("PruneExpiredJTIs: %v", err)
	}
	if n != 2 {
		t.Errorf("pruned %d; want 2", n)
	}
	// keep-1 survives.
	if denied, _ := s.IsJTIDenied(ctx, "keep-1"); !denied {
		t.Error("keep-1 should still be denied")
	}
}

func TestConcurrentWrites(t *testing.T) {
	// Ensure WAL + busy_timeout prevent "database is locked" under contention.
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "concurrent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()
	const N = 50
	errCh := make(chan error, N)
	for i := 0; i < N; i++ {
		go func(i int) {
			a := Agent{
				ID:       fmtID(i),
				PubkeyFP: "fp",
				PolicyID: "p",
			}
			errCh <- s.PutAgent(ctx, a)
		}(i)
	}
	for i := 0; i < N; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("concurrent PutAgent failed: %v", err)
		}
	}
	out, err := s.ListAgents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != N {
		t.Errorf("expected %d agents, got %d", N, len(out))
	}
}

func fmtID(i int) string {
	// small helper to avoid pulling fmt import clutter in TestConcurrentWrites
	return "agent-" + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	out := string(b[p:])
	if neg {
		out = "-" + out
	}
	return out
}
