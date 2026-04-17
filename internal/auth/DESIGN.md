# FaultWall Agent Auth — PR 3a (JWT Primitives)

**Status:** In-PR (this PR, independent of PR 2)
**Scope:** Sign + Verify primitives only. No store wiring, no startup-packet integration, no keyring. Those land in PR 3b once PR 2 (SQLite store) is merged.

## Why split PR 3 into 3a + 3b

- PR 3a (this one) has **zero dependency** on `internal/store`. It's a pure crypto/JWT module.
- Unblocks forward progress while PR 2 is in review.
- When PR 2 merges, PR 3b wires these primitives into the startup-packet handler and the denylist.

## Algorithm decision

**HS256 (HMAC-SHA256) with a shared secret.** Per spec §3.3:
- Appropriate for single-server v2.1
- Min 32-byte secret (enforced in `NewSigner`)
- Server secret from `FAULTWALL_JWT_SECRET` env var (read in PR 3b by main.go)
- Rotation via admin CLI — PR 4 work

RS256 / asymmetric is explicitly out of scope for v2.1 (spec §12).

## Library

`github.com/golang-jwt/jwt/v5`. v5 is critical — v4 had alg-confusion issues. v5 requires explicit signing method checks in the verify callback, which we do.

## Claims shape

```go
type Claims struct {
    jwt.RegisteredClaims          // iss, sub, aud, exp, iat, jti
    FW FaultWallClaims `json:"fw"` // namespaced custom claims
}

type FaultWallClaims struct {
    AgentID   string   `json:"agent_id"`
    PolicyID  string   `json:"policy_id"`
    DBTargets []string `json:"db_targets,omitempty"`
    Version   int      `json:"version"` // claim schema version, starts at 1
}
```

`policy_id` is a **reference**, not embedded policy data — policies live in `policies.yaml` server-side so updates take effect without re-issuing tokens.

## Security invariants enforced

1. **Alg confusion defense**: `ParseWithClaims` callback rejects any signing method other than HMAC. Rejected alg surfaces `ErrUnexpectedSigningMethod`.
2. **Expected issuer, audience, subject-prefix** pinned by the `Verifier`. Cross-service token misuse is blocked.
3. **Secret length** enforced at `NewSigner` time (min 32 bytes). Short secrets fail fast at startup, not at runtime.
4. **Claim version** field gives us a forward-compat hatch — future PRs can reject `version > supportedMax`.
5. **Clock skew tolerance** bounded — 60s default, configurable via `VerifierOption`. Larger-than-necessary skew is a known forgery window.
6. **Never log tokens** — this package imports `internal/logging` for any future log statements. PR 3a has no log statements yet (pure lib), but the dependency is pre-wired.

## Out of scope for PR 3a

- JTI denylist lookup (needs PR 2 store → PR 3b)
- Startup-packet integration in `proxy.go` (→ PR 3b)
- Keyring wrapper (`99designs/keyring` → PR 3b)
- `FAULTWALL_JWT_SECRET` env var plumbing in `main.go` (→ PR 3b)
- Admin CLI token issuance (→ PR 4)

## Tests

Covered in `jwt_test.go`:

- Round-trip sign + verify with all claims populated
- Expired token rejected
- Token with `exp` in the future but beyond allowed skew
- Wrong issuer rejected
- Wrong audience rejected
- Wrong subject prefix rejected
- Alg-confusion attack: `alg=none` rejected
- Alg-confusion attack: `alg=RS256` with attacker-supplied key rejected
- Tampered signature rejected
- Tampered payload rejected
- Short secret (<32 bytes) rejected at signer construction
- `fw.version` presence and schema validation
- JTI round-trips and is accessible via `Claims.ID`
