package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedact_JWT(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantIn string // substring that MUST appear in output
		wantNotIn string // substring that must NOT appear
	}{
		{
			name:      "plain jwt",
			input:     "issued token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZ2VudC0xIn0.abcdefghij for agent",
			wantIn:    "[REDACTED]",
			wantNotIn: "eyJhbGci",
		},
		{
			name:      "jwt inside sentence",
			input:     "agent login failed; token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.signaturepart123",
			wantIn:    "token=[REDACTED]",
			wantNotIn: "eyJhbGci",
		},
		{
			name:      "short dotted id is NOT a jwt",
			input:     "version a.b.c shipped",
			wantIn:    "version a.b.c shipped",
			wantNotIn: "[REDACTED]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.input)
			if !strings.Contains(got, tt.wantIn) {
				t.Errorf("Redact(%q) = %q; want substring %q", tt.input, got, tt.wantIn)
			}
			if tt.wantNotIn != "" && strings.Contains(got, tt.wantNotIn) {
				t.Errorf("Redact(%q) = %q; must NOT contain %q", tt.input, got, tt.wantNotIn)
			}
		})
	}
}

func TestRedact_Bearer(t *testing.T) {
	in := "Authorization: Bearer abc123xyz789deadbeef"
	out := Redact(in)
	if strings.Contains(out, "abc123xyz789deadbeef") {
		t.Errorf("bearer token leaked: %q", out)
	}
	if !strings.Contains(strings.ToLower(out), "bearer [redacted]") {
		t.Errorf("expected 'Bearer [REDACTED]', got %q", out)
	}
}

func TestRedact_TokenKV(t *testing.T) {
	cases := []string{
		`token=abc12345`,
		`token: "supersecretvalue"`,
		`password=hunter2pass`,
		`api_key=sk-1234567890`,
		`secret='my-secret-value'`,
	}
	for _, in := range cases {
		out := Redact(in)
		if !strings.Contains(out, "[REDACTED]") {
			t.Errorf("Redact(%q) did not redact: %q", in, out)
		}
		// The raw value must not appear
		for _, leak := range []string{"abc12345", "supersecretvalue", "hunter2pass", "sk-1234567890", "my-secret-value"} {
			if strings.Contains(out, leak) {
				t.Errorf("Redact(%q) leaked %q in %q", in, leak, out)
			}
		}
	}
}

func TestRedact_PostgresConnString(t *testing.T) {
	in := "connecting to postgres://admin:supersecret@db.internal:5432/faultwall now"
	out := Redact(in)
	if strings.Contains(out, "supersecret") {
		t.Errorf("postgres password leaked: %q", out)
	}
	if !strings.Contains(out, "postgres://admin:[REDACTED]@") {
		t.Errorf("expected redacted conn string, got %q", out)
	}
}

func TestRedact_EmptyAndBenign(t *testing.T) {
	if Redact("") != "" {
		t.Errorf("empty string should pass through unchanged")
	}
	benign := "Proxy: accepted connection from 127.0.0.1:54321 agent=cursor-ai"
	if Redact(benign) != benign {
		t.Errorf("benign log line was modified: %q", Redact(benign))
	}
}

func TestLogger_LevelGate(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelWarn)

	l.Debugf("should not appear")
	l.Infof("also should not appear")
	l.Warnf("should appear")
	l.Errorf("should also appear")

	out := buf.String()
	if strings.Contains(out, "should not appear") || strings.Contains(out, "also should not appear") {
		t.Errorf("below-threshold messages leaked: %q", out)
	}
	if !strings.Contains(out, "[WARN] should appear") {
		t.Errorf("expected WARN message, got %q", out)
	}
	if !strings.Contains(out, "[ERROR] should also appear") {
		t.Errorf("expected ERROR message, got %q", out)
	}
}

func TestLogger_RedactsOnEmit(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelInfo)

	l.Infof("agent logged in with token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZ2VudC0xIn0.verylongsignature")

	out := buf.String()
	if strings.Contains(out, "eyJhbGci") {
		t.Fatalf("JWT leaked to log sink: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] in log output, got %q", out)
	}
}

func TestLogger_PrintfDefaultLevel(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelInfo)
	l.Printf("hello %s", "world")
	if !strings.Contains(buf.String(), "[INFO] hello world") {
		t.Errorf("Printf should map to INFO, got %q", buf.String())
	}
}

func TestDefault_SetAndUse(t *testing.T) {
	var buf bytes.Buffer
	orig := Default()
	defer SetDefault(orig) // restore for other tests

	SetDefault(New(&buf, LevelInfo))
	Infof("package-level call password=leaky123")

	out := buf.String()
	if strings.Contains(out, "leaky123") {
		t.Errorf("package-level default did not redact: %q", out)
	}
	if !strings.Contains(out, "password=[REDACTED]") {
		t.Errorf("expected redacted password, got %q", out)
	}
}

func TestSetLevel_Runtime(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelError)
	l.Infof("before")
	l.SetLevel(LevelDebug)
	l.Debugf("after")
	out := buf.String()
	if strings.Contains(out, "before") {
		t.Errorf("message below original threshold leaked: %q", out)
	}
	if !strings.Contains(out, "[DEBUG] after") {
		t.Errorf("expected DEBUG message after SetLevel, got %q", out)
	}
}
