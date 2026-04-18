package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// newTestKey returns a random 32-byte HMAC secret for tests.
func newTestKey(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// newPair returns a matched Signer/Verifier pair sharing a 32-byte secret.
func newPair(t *testing.T) (*Signer, *Verifier) {
	t.Helper()
	secret := newTestKey(t)
	sig, err := NewSigner(secret)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	ver, err := NewVerifier(secret)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return sig, ver
}

func goodParams() IssueParams {
	return IssueParams{
		AgentID:   "claude-code-prod",
		PolicyID:  "readonly-analytics",
		DBTargets: []string{"analytics", "events"},
		TTL:       24 * time.Hour,
		JTI:       "01HN8K2R9XPQ4M3V7T5B6Y8W0Z",
	}
}

// ── Construction guards ────────────────────────────────────────────────

func TestNewSigner_RejectsShortSecret(t *testing.T) {
	_, err := NewSigner(make([]byte, 31))
	if !errors.Is(err, ErrSecretTooShort) {
		t.Errorf("want ErrSecretTooShort, got %v", err)
	}
}

func TestNewVerifier_RejectsShortSecret(t *testing.T) {
	_, err := NewVerifier(make([]byte, 16))
	if !errors.Is(err, ErrSecretTooShort) {
		t.Errorf("want ErrSecretTooShort, got %v", err)
	}
}

func TestSigner_DoesNotAliasSecret(t *testing.T) {
	secret := newTestKey(t)
	s, err := NewSigner(secret)
	if err != nil {
		t.Fatal(err)
	}
	// Clobber caller's buffer — signer must still work.
	for i := range secret {
		secret[i] = 0
	}
	if _, err := s.Issue(goodParams()); err != nil {
		t.Errorf("signer broke after caller zeroed input: %v", err)
	}
}

// ── Happy path ────────────────────────────────────────────────────────

func TestRoundTrip(t *testing.T) {
	sig, ver := newPair(t)
	tok, err := sig.Issue(goodParams())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}
	c, err := ver.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if c.FW.AgentID != "claude-code-prod" {
		t.Errorf("agent_id: got %q", c.FW.AgentID)
	}
	if c.FW.PolicyID != "readonly-analytics" {
		t.Errorf("policy_id: got %q", c.FW.PolicyID)
	}
	if len(c.FW.DBTargets) != 2 || c.FW.DBTargets[0] != "analytics" {
		t.Errorf("db_targets: got %v", c.FW.DBTargets)
	}
	if c.FW.Version != CurrentClaimVersion {
		t.Errorf("version: got %d want %d", c.FW.Version, CurrentClaimVersion)
	}
	if c.ID != goodParams().JTI {
		t.Errorf("jti: got %q want %q", c.ID, goodParams().JTI)
	}
	if c.Subject != "agent:claude-code-prod" {
		t.Errorf("subject: got %q", c.Subject)
	}
	if c.Issuer != Issuer {
		t.Errorf("iss: got %q want %q", c.Issuer, Issuer)
	}
	if len(c.Audience) == 0 || c.Audience[0] != Audience {
		t.Errorf("aud: got %v", c.Audience)
	}
}

// ── Issue input validation ────────────────────────────────────────────

func TestIssue_RejectsEmptyAgentID(t *testing.T) {
	sig, _ := newPair(t)
	p := goodParams()
	p.AgentID = ""
	if _, err := sig.Issue(p); err == nil {
		t.Error("expected error on empty AgentID")
	}
}

func TestIssue_RejectsEmptyJTI(t *testing.T) {
	sig, _ := newPair(t)
	p := goodParams()
	p.JTI = ""
	if _, err := sig.Issue(p); err == nil {
		t.Error("expected error on empty JTI")
	}
}

func TestIssue_RejectsNonPositiveTTL(t *testing.T) {
	sig, _ := newPair(t)
	p := goodParams()
	p.TTL = 0
	if _, err := sig.Issue(p); err == nil {
		t.Error("expected error on zero TTL")
	}
	p.TTL = -time.Second
	if _, err := sig.Issue(p); err == nil {
		t.Error("expected error on negative TTL")
	}
}

// ── Expiration ────────────────────────────────────────────────────────

func TestVerify_Expired(t *testing.T) {
	sig, ver := newPair(t)
	p := goodParams()
	p.TTL = time.Millisecond
	tok, err := sig.Issue(p)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // blow past both TTL and DefaultSkew=60s? No — we override skew.
	// Use a verifier with zero skew so the short TTL + sleep actually expires.
	secret := ver.secret
	strict, _ := NewVerifier(secret, WithSkew(0))
	if _, err := strict.Verify(tok); err == nil {
		t.Fatal("expected expired token to fail")
	} else if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("want ErrInvalidToken chain, got %v", err)
	}
}

// ── Issuer / Audience pinning ─────────────────────────────────────────

func TestVerify_RejectsWrongIssuer(t *testing.T) {
	secret := newTestKey(t)
	// Mint a token with a foreign issuer using the library directly.
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "evil-issuer",
			Subject:   "agent:x",
			Audience:  jwt.ClaimStrings{Audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "j",
		},
		FW: FaultWallClaims{AgentID: "x", PolicyID: "p", Version: 1},
	}
	tok := mustSign(t, claims, jwt.SigningMethodHS256, secret)
	ver, _ := NewVerifier(secret)
	if _, err := ver.Verify(tok); err == nil {
		t.Error("expected wrong-issuer rejection")
	}
}

func TestVerify_RejectsWrongAudience(t *testing.T) {
	secret := newTestKey(t)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   "agent:x",
			Audience:  jwt.ClaimStrings{"some-other-service"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "j",
		},
		FW: FaultWallClaims{AgentID: "x", PolicyID: "p", Version: 1},
	}
	tok := mustSign(t, claims, jwt.SigningMethodHS256, secret)
	ver, _ := NewVerifier(secret)
	if _, err := ver.Verify(tok); err == nil {
		t.Error("expected wrong-audience rejection")
	}
}

// ── Subject / agent_id invariants ─────────────────────────────────────

func TestVerify_RejectsBadSubjectPrefix(t *testing.T) {
	secret := newTestKey(t)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   "user:x", // wrong prefix
			Audience:  jwt.ClaimStrings{Audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "j",
		},
		FW: FaultWallClaims{AgentID: "x", PolicyID: "p", Version: 1},
	}
	tok := mustSign(t, claims, jwt.SigningMethodHS256, secret)
	ver, _ := NewVerifier(secret)
	_, err := ver.Verify(tok)
	if !errors.Is(err, ErrBadSubject) {
		t.Errorf("want ErrBadSubject, got %v", err)
	}
}

func TestVerify_RejectsSubjectAgentMismatch(t *testing.T) {
	secret := newTestKey(t)
	// sub says "alice", fw.agent_id says "mallory".
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   "agent:alice",
			Audience:  jwt.ClaimStrings{Audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "j",
		},
		FW: FaultWallClaims{AgentID: "mallory", PolicyID: "p", Version: 1},
	}
	tok := mustSign(t, claims, jwt.SigningMethodHS256, secret)
	ver, _ := NewVerifier(secret)
	if _, err := ver.Verify(tok); err == nil {
		t.Error("expected sub/fw.agent_id mismatch rejection")
	}
}

func TestVerify_RejectsMissingAgentID(t *testing.T) {
	secret := newTestKey(t)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   "agent:x",
			Audience:  jwt.ClaimStrings{Audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "j",
		},
		FW: FaultWallClaims{AgentID: "", PolicyID: "p", Version: 1}, // empty
	}
	tok := mustSign(t, claims, jwt.SigningMethodHS256, secret)
	ver, _ := NewVerifier(secret)
	_, err := ver.Verify(tok)
	if !errors.Is(err, ErrMissingAgentID) {
		t.Errorf("want ErrMissingAgentID, got %v", err)
	}
}

// ── Claim version ─────────────────────────────────────────────────────

func TestVerify_RejectsFutureClaimVersion(t *testing.T) {
	secret := newTestKey(t)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   "agent:x",
			Audience:  jwt.ClaimStrings{Audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "j",
		},
		FW: FaultWallClaims{AgentID: "x", PolicyID: "p", Version: 999},
	}
	tok := mustSign(t, claims, jwt.SigningMethodHS256, secret)
	ver, _ := NewVerifier(secret)
	_, err := ver.Verify(tok)
	if !errors.Is(err, ErrUnsupportedClaimVersion) {
		t.Errorf("want ErrUnsupportedClaimVersion, got %v", err)
	}
}

func TestVerify_RejectsZeroClaimVersion(t *testing.T) {
	secret := newTestKey(t)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   "agent:x",
			Audience:  jwt.ClaimStrings{Audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "j",
		},
		FW: FaultWallClaims{AgentID: "x", PolicyID: "p", Version: 0},
	}
	tok := mustSign(t, claims, jwt.SigningMethodHS256, secret)
	ver, _ := NewVerifier(secret)
	if _, err := ver.Verify(tok); !errors.Is(err, ErrUnsupportedClaimVersion) {
		t.Errorf("want ErrUnsupportedClaimVersion on v=0, got %v", err)
	}
}

// ── Alg confusion attacks ─────────────────────────────────────────────

func TestVerify_RejectsAlgNone(t *testing.T) {
	sig, ver := newPair(t)
	good, err := sig.Issue(goodParams())
	if err != nil {
		t.Fatal(err)
	}
	// Craft an alg=none token with the same claims.
	parts := strings.Split(good, ".")
	if len(parts) != 3 {
		t.Fatal("malformed reference token")
	}
	headerNone := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	none := headerNone + "." + parts[1] + "." // empty signature
	if _, err := ver.Verify(none); err == nil {
		t.Fatal("alg=none was accepted — catastrophic")
	}
}

func TestVerify_RejectsRS256ConfusionAttack(t *testing.T) {
	// Classic RS256->HS256 confusion: attacker grabs FaultWall's public key
	// (if we ever had one), passes it as an HMAC secret, signs a token with
	// alg=RS256, and hopes we verify with the public key. We must reject
	// anything that isn't HS256.
	//
	// Flipped here: mint an RS256 token with a fresh RSA key. Our verifier
	// must refuse it regardless of payload.
	sig, ver := newPair(t)
	// We need a parseable token to attack with — start from a legitimate one,
	// then swap the header to advertise RS256.
	good, err := sig.Issue(goodParams())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(good, ".")
	// Replace header with RS256.
	newHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	// Sign with a random RSA key the verifier doesn't know about.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Construct signing input and sign with RS256.
	signingInput := newHdr + "." + parts[1]
	sigMethod := jwt.SigningMethodRS256
	sigBytes, err := sigMethod.Sign(signingInput, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	attacker := signingInput + "." + base64.RawURLEncoding.EncodeToString(sigBytes)
	if _, err := ver.Verify(attacker); err == nil {
		t.Fatal("RS256 confusion attack was accepted — catastrophic")
	}
}

// ── Signature tampering ───────────────────────────────────────────────

func TestVerify_RejectsTamperedSignature(t *testing.T) {
	sig, ver := newPair(t)
	good, err := sig.Issue(goodParams())
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the signature segment.
	parts := strings.Split(good, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if len(raw) == 0 {
		t.Fatal("empty sig")
	}
	raw[0] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(raw)
	tampered := strings.Join(parts, ".")
	if _, err := ver.Verify(tampered); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

func TestVerify_RejectsTamperedPayload(t *testing.T) {
	sig, ver := newPair(t)
	good, err := sig.Issue(goodParams())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(good, ".")
	// Decode, mutate agent_id, re-encode — signature will no longer match.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatal(err)
	}
	if fw, ok := m["fw"].(map[string]any); ok {
		fw["agent_id"] = "mallory"
	}
	mutated, _ := json.Marshal(m)
	parts[1] = base64.RawURLEncoding.EncodeToString(mutated)
	tampered := strings.Join(parts, ".")
	if _, err := ver.Verify(tampered); err == nil {
		t.Fatal("tampered payload accepted")
	}
}

// ── Empty / malformed tokens ──────────────────────────────────────────

func TestVerify_RejectsEmpty(t *testing.T) {
	_, ver := newPair(t)
	if _, err := ver.Verify(""); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("empty token: want ErrInvalidToken, got %v", err)
	}
}

func TestVerify_RejectsGarbage(t *testing.T) {
	_, ver := newPair(t)
	if _, err := ver.Verify("not.a.jwt"); err == nil {
		t.Error("garbage accepted")
	}
	if _, err := ver.Verify("only.two"); err == nil {
		t.Error("too-few-segments accepted")
	}
}

// ── Cross-secret rejection ────────────────────────────────────────────

func TestVerify_RejectsTokensFromDifferentSecret(t *testing.T) {
	sigA, _ := newPair(t)
	_, verB := newPair(t) // different secret
	tok, err := sigA.Issue(goodParams())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verB.Verify(tok); err == nil {
		t.Fatal("token signed by A verified under B's secret")
	}
}

// ── helpers ───────────────────────────────────────────────────────────

func mustSign(t *testing.T, claims Claims, method jwt.SigningMethod, secret []byte) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	s, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf("mustSign: %v", err)
	}
	return s
}
