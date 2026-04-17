// Package logging provides a redacting logger wrapper for FaultWall.
//
// Security requirement (spec §8.1): Never log tokens, secrets, or credentials.
// This package wraps the standard library logger with automatic redaction of
// JWTs, bearer tokens, and other sensitive patterns before emission.
//
// Use logging.Printf / logging.Infof / logging.Errorf instead of log.Printf
// anywhere a message might touch auth material. All auth-package logging
// MUST go through this wrapper.
package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
)

// Level is the emitted log level.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// Logger is a redacting logger that wraps log.Logger.
// It redacts known secret patterns (JWT, Bearer, keyring passwords) before
// writing to the underlying sink.
type Logger struct {
	mu    sync.Mutex
	sink  *log.Logger
	level Level
}

var (
	// jwtPattern matches JWT-shaped strings: 3 base64url segments separated by dots.
	// RFC 7519 JWTs are always 3 segments. Require each segment to be long enough
	// to avoid false positives on short dotted identifiers (e.g. "a.b.c").
	jwtPattern = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)

	// bearerPattern matches "Bearer <token>" in any casing.
	bearerPattern = regexp.MustCompile(`(?i)\b(bearer)\s+[A-Za-z0-9._~+/=_-]{8,}`)

	// tokenKVPattern matches token=..., password=..., secret=... key/value pairs.
	// Captures the key so we can preserve it in the redacted output.
	tokenKVPattern = regexp.MustCompile(`(?i)\b(token|password|secret|api[_-]?key|auth)\s*[:=]\s*("[^"]+"|'[^']+'|[^\s,;}]+)`)

	// pgConnStringPattern matches postgres connection strings that embed a password.
	// e.g. postgres://user:pass@host/db
	pgConnStringPattern = regexp.MustCompile(`(postgres(?:ql)?://[^:\s]+):([^@\s]+)@`)
)

const redacted = "[REDACTED]"

// Redact returns s with known secret patterns replaced by [REDACTED].
// It is safe to call Redact on any string before logging, even outside this
// package — e.g. for error messages that may contain user input.
func Redact(s string) string {
	if s == "" {
		return s
	}
	s = jwtPattern.ReplaceAllString(s, redacted)
	s = bearerPattern.ReplaceAllString(s, "$1 "+redacted)
	s = tokenKVPattern.ReplaceAllStringFunc(s, func(match string) string {
		// Preserve the key, redact the value.
		sub := tokenKVPattern.FindStringSubmatch(match)
		if len(sub) < 3 {
			return redacted
		}
		// Find the separator that was actually used (: or =) to keep output faithful.
		sep := "="
		if idx := strings.IndexAny(match, ":="); idx >= 0 {
			sep = string(match[idx])
		}
		return sub[1] + sep + redacted
	})
	s = pgConnStringPattern.ReplaceAllString(s, "$1:"+redacted+"@")
	return s
}

// New returns a Logger writing to the given sink with the given level.
// If sink is nil, os.Stderr is used.
func New(sink io.Writer, level Level) *Logger {
	if sink == nil {
		sink = os.Stderr
	}
	return &Logger{
		sink:  log.New(sink, "", log.LstdFlags|log.Lmicroseconds),
		level: level,
	}
}

// Default is the package-level logger used by the package-level helpers.
// Tests may replace it via SetDefault.
var defaultLogger = New(os.Stderr, LevelInfo)

// SetDefault replaces the package-level default logger. Intended for tests and
// for main() to configure verbosity/sink at startup.
func SetDefault(l *Logger) {
	if l == nil {
		return
	}
	defaultLogger = l
}

// Default returns the package-level default logger.
func Default() *Logger {
	return defaultLogger
}

// SetLevel updates the minimum level emitted by this logger.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// logf is the internal entry point — applies redaction, level gate, and emit.
func (l *Logger) logf(level Level, format string, args ...any) {
	l.mu.Lock()
	threshold := l.level
	l.mu.Unlock()
	if level < threshold {
		return
	}
	msg := fmt.Sprintf(format, args...)
	msg = Redact(msg)
	l.sink.Printf("[%s] %s", level.String(), msg)
}

// Debugf logs at DEBUG level after redaction.
func (l *Logger) Debugf(format string, args ...any) { l.logf(LevelDebug, format, args...) }

// Infof logs at INFO level after redaction.
func (l *Logger) Infof(format string, args ...any) { l.logf(LevelInfo, format, args...) }

// Warnf logs at WARN level after redaction.
func (l *Logger) Warnf(format string, args ...any) { l.logf(LevelWarn, format, args...) }

// Errorf logs at ERROR level after redaction.
func (l *Logger) Errorf(format string, args ...any) { l.logf(LevelError, format, args...) }

// Printf mirrors log.Printf semantics at INFO level, with redaction applied.
// Exists so call sites doing a mechanical `log.Printf` → `logging.Printf` swap
// do not need to pick a level.
func (l *Logger) Printf(format string, args ...any) { l.logf(LevelInfo, format, args...) }

// Package-level conveniences — delegate to defaultLogger.
// These let callers write `logging.Infof(...)` without threading a logger around.

func Debugf(format string, args ...any) { defaultLogger.Debugf(format, args...) }
func Infof(format string, args ...any)  { defaultLogger.Infof(format, args...) }
func Warnf(format string, args ...any)  { defaultLogger.Warnf(format, args...) }
func Errorf(format string, args ...any) { defaultLogger.Errorf(format, args...) }
func Printf(format string, args ...any) { defaultLogger.Printf(format, args...) }
