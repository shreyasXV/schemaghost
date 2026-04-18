// Package auth implements FaultWall agent JWT authentication primitives.
//
// This file (jwt.go) provides only the Sign + Verify layer. Integration into
// the Postgres startup-packet handler, JTI denylist lookup against the SQLite
// store, and keyring-backed client credential handling live in PR 3b.
//
// See DESIGN.md for security invariants and scope boundaries.
package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ── Constants and fixed identifiers ──────────────────────────────────

const (
	// Issuer is the fixed value for the `iss` claim.
	Issuer = "faultwall"

	// Audience is the fixed value for the `aud` claim. Guards against
	// cross-service token misuse — a token minted for faultwall-proxy cannot
	// be replayed against a future faultwall-admin endpoint, and vice versa.
	Audience = "faultwall-proxy"

	// SubjectPrefix is the required prefix for the `sub` claim.
	// Full subject is SubjectPrefix + agentID.
	SubjectPrefix = "agent:"

	// MinSecretBytes is the minimum HMAC secret length we will accept.
	// 256 bits / 32 bytes is the HS256 recommended minimum.
	MinSecretBytes = 32

	// CurrentClaimVersion is the schema version we emit in fw.version.
	CurrentClaimVersion = 1

	// DefaultSkew is the default allowed clock skew during verification.
	DefaultSkew = 60 * time.Second
)

// ── Errors ────────────────────────────────────────────────────────────

var (
	ErrSecretTooShort          = errors.New("auth: secret must be at least 32 bytes")
	ErrUnexpectedSigningMethod = errors.New("auth: unexpected signing method")
	ErrInvalidToken            = errors.New("auth: invalid token")
	ErrWrongIssuer             = errors.New("auth: wrong issuer")
	ErrWrongAudience           = errors.New("auth: wrong audience")
	ErrBadSubject              = errors.New("auth: subject missing agent: prefix")
	ErrMissingAgentID          = errors.New("auth: fw.agent_id missing")
	ErrUnsupportedClaimVersion = errors.New("auth: unsupported fw.version")
)

// ── Claim types ───────────────────────────────────────────────────────

// FaultWallClaims are the custom claims namespaced under `fw` in the JWT.
type FaultWallClaims struct {
	AgentID   string   `json:"agent_id"`
	PolicyID  string   `json:"policy_id"`
	DBTargets []string `json:"db_targets,omitempty"`
	Version   int      `json:"version"`
}

// Claims is the full claim set signed and verified by FaultWall.
type Claims struct {
	jwt.RegisteredClaims
	FW FaultWallClaims `json:"fw"`
}

// ── Signer ────────────────────────────────────────────────────────────

// Signer produces signed JWTs for FaultWall agents.
// All tokens it issues are HS256, bound to Issuer/Audience, and stamped with
// the current claim version.
type Signer struct {
	secret []byte
}

// NewSigner constructs a Signer from a shared secret.
// Returns ErrSecretTooShort if secret is under MinSecretBytes.
func NewSigner(secret []byte) (*Signer, error) {
	if len(secret) < MinSecretBytes {
		return nil, fmt.Errorf("%w: got %d bytes, need %d", ErrSecretTooShort, len(secret), MinSecretBytes)
	}
	// Copy so callers can zero their input without affecting us.
	cp := make([]byte, len(secret))
	copy(cp, secret)
	return &Signer{secret: cp}, nil
}

// IssueParams capture the per-token fields a caller supplies at mint time.
// The Signer fills in iss, aud, iat, exp, jti, and fw.version.
type IssueParams struct {
	AgentID   string        // fills sub and fw.agent_id
	PolicyID  string        // fw.policy_id
	DBTargets []string      // fw.db_targets
	TTL       time.Duration // token lifetime (exp = now + TTL)
	JTI       string        // required — ULID/UUID from caller
}

// Issue mints a signed JWT from the given params.
// The caller is responsible for generating a unique JTI.
func (s *Signer) Issue(p IssueParams) (string, error) {
	if p.AgentID == "" {
		return "", errors.New("auth: Issue: empty AgentID")
	}
	if p.JTI == "" {
		return "", errors.New("auth: Issue: empty JTI")
	}
	if p.TTL <= 0 {
		return "", errors.New("auth: Issue: non-positive TTL")
	}
	now := time.Now().UTC()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   SubjectPrefix + p.AgentID,
			Audience:  jwt.ClaimStrings{Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(p.TTL)),
			ID:        p.JTI,
		},
		FW: FaultWallClaims{
			AgentID:   p.AgentID,
			PolicyID:  p.PolicyID,
			DBTargets: p.DBTargets,
			Version:   CurrentClaimVersion,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.secret)
	if err != nil {
		return "", fmt.Errorf("auth: sign: %w", err)
	}
	return signed, nil
}

// ── Verifier ──────────────────────────────────────────────────────────

// VerifierOption tunes verification behavior.
type VerifierOption func(*Verifier)

// WithSkew overrides the allowed clock skew during verification.
// Default is DefaultSkew (60s). Zero disables skew tolerance.
func WithSkew(d time.Duration) VerifierOption {
	return func(v *Verifier) { v.skew = d }
}

// Verifier checks signed tokens, enforcing FaultWall's security invariants.
// One Verifier per process is sufficient; it is safe for concurrent use.
type Verifier struct {
	secret []byte
	skew   time.Duration
	parser *jwt.Parser
}

// NewVerifier constructs a Verifier from the same shared secret used for signing.
func NewVerifier(secret []byte, opts ...VerifierOption) (*Verifier, error) {
	if len(secret) < MinSecretBytes {
		return nil, fmt.Errorf("%w: got %d bytes, need %d", ErrSecretTooShort, len(secret), MinSecretBytes)
	}
	cp := make([]byte, len(secret))
	copy(cp, secret)
	v := &Verifier{
		secret: cp,
		skew:   DefaultSkew,
	}
	for _, opt := range opts {
		opt(v)
	}
	// Build the parser once. Critical: ValidMethods pins HS256 only.
	// This is the primary alg-confusion defense.
	v.parser = jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(Issuer),
		jwt.WithAudience(Audience),
		jwt.WithLeeway(v.skew),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	return v, nil
}

// Verify parses and validates the given token string. On success it returns
// the fully populated Claims. Any failure — bad signature, wrong alg, expired,
// wrong iss/aud, bad subject, missing required fw fields — returns an error
// wrapping one of the sentinel errors in this package.
func (v *Verifier) Verify(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("%w: empty token", ErrInvalidToken)
	}

	claims := &Claims{}
	token, err := v.parser.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		// Belt-and-suspenders with WithValidMethods: reject anything not HMAC.
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%w: %v", ErrUnexpectedSigningMethod, t.Header["alg"])
		}
		return v.secret, nil
	})
	if err != nil {
		// Preserve the sentinel chain. jwt.ErrTokenSignatureInvalid,
		// ErrTokenExpired, etc. are errors.Is-compatible.
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}

	// Post-parse invariants that jwt/v5's built-in validators don't cover.

	// Subject must be exactly `agent:<agent_id>`.
	if !strings.HasPrefix(claims.Subject, SubjectPrefix) {
		return nil, ErrBadSubject
	}
	subjectAgent := strings.TrimPrefix(claims.Subject, SubjectPrefix)
	if subjectAgent == "" {
		return nil, ErrBadSubject
	}

	// fw.agent_id must be present and match the subject. Constant-time compare
	// isn't strictly needed here (both values come from the same signed token),
	// but the extra cost is negligible and removes any timing concern if this
	// check is ever reused in a path with untrusted comparison input.
	if claims.FW.AgentID == "" {
		return nil, ErrMissingAgentID
	}
	if subtle.ConstantTimeCompare([]byte(subjectAgent), []byte(claims.FW.AgentID)) != 1 {
		return nil, fmt.Errorf("%w: sub and fw.agent_id disagree", ErrInvalidToken)
	}

	// Claim version — reject anything newer than we understand.
	if claims.FW.Version <= 0 || claims.FW.Version > CurrentClaimVersion {
		return nil, fmt.Errorf("%w: version=%d", ErrUnsupportedClaimVersion, claims.FW.Version)
	}

	return claims, nil
}
