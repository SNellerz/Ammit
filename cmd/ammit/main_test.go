package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func TestRunReturnsErrorOnInvalidFlag(t *testing.T) {
	err := run([]string{"--definitely-invalid-flag"})
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

func TestRunInvalidFlagReturnsMachineCode(t *testing.T) {
	err := run([]string{"--json", "--definitely-invalid-flag"})
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
	if got := errorCode(err); got != errInvalidFlags {
		t.Fatalf("error code = %q, want %q", got, errInvalidFlags)
	}
}

func TestWatchOnlySupportedForStats(t *testing.T) {
	err := run([]string{"--watch", "ls"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := errorCode(err); got != errInvalidFlags {
		t.Fatalf("error code = %q, want %q", got, errInvalidFlags)
	}
}

func TestWatchCannotBeCombinedWithJSON(t *testing.T) {
	err := run([]string{"--watch", "--json", "stats", "abc"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := errorCode(err); got != errInvalidFlags {
		t.Fatalf("error code = %q, want %q", got, errInvalidFlags)
	}
}

func TestJSONHelpIncludesData(t *testing.T) {
	out, err := captureStdoutForTest(func() error {
		return run([]string{"--json", "help"})
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	var env map[string]any
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}
	if ok, _ := env["ok"].(bool); !ok {
		t.Fatalf("expected ok=true, got %v", env["ok"])
	}
	data, ok := env["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected data object, got %T", env["data"])
	}
	usage, _ := data["usage"].(string)
	if !strings.Contains(usage, "USAGE:") {
		t.Fatalf("expected usage text in data, got %q", usage)
	}
}

func TestJSONVersionIncludesData(t *testing.T) {
	out, err := captureStdoutForTest(func() error {
		return run([]string{"--json", "--version"})
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	var env map[string]any
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}
	data, ok := env["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected data object, got %T", env["data"])
	}
	if got, _ := data["name"].(string); got != "ammit" {
		t.Fatalf("expected name=ammit, got %q", got)
	}
	if _, ok := data["version"].(string); !ok {
		t.Fatalf("expected version field, got %+v", data)
	}
}

func TestMaskSecretDefaultHeuristic(t *testing.T) {
	t.Setenv("AMMIT_MASK_ENV", "")
	t.Setenv("AMMIT_ENV_MASK", "")
	t.Setenv("AMMIT_ENV_UNMASK", "")

	masked := maskSecret("API_TOKEN=abc123")
	if !strings.Contains(masked, "(masked)") {
		t.Fatalf("expected token to be masked, got %q", masked)
	}

	clear := maskSecret("LOG_LEVEL=debug")
	if clear != "LOG_LEVEL=debug" {
		t.Fatalf("expected non-secret env unchanged, got %q", clear)
	}
}

func TestMaskSecretStrictModeWithAllowlist(t *testing.T) {
	t.Setenv("AMMIT_MASK_ENV", "strict")
	t.Setenv("AMMIT_ENV_MASK", "")
	t.Setenv("AMMIT_ENV_UNMASK", "LOG_LEVEL, FEATURE_FLAG")

	masked := maskSecret("DB_HOST=localhost")
	if !strings.Contains(masked, "(masked)") {
		t.Fatalf("expected strict mode masking, got %q", masked)
	}

	unmasked := maskSecret("LOG_LEVEL=debug")
	if unmasked != "LOG_LEVEL=debug" {
		t.Fatalf("expected allowlisted key to remain visible, got %q", unmasked)
	}
}

func TestMaskSecretExplicitMaskList(t *testing.T) {
	t.Setenv("AMMIT_MASK_ENV", "")
	t.Setenv("AMMIT_ENV_MASK", "SAFE_VALUE")
	t.Setenv("AMMIT_ENV_UNMASK", "")

	masked := maskSecret("SAFE_VALUE=123")
	if !strings.Contains(masked, "(masked)") {
		t.Fatalf("expected explicit mask list to apply, got %q", masked)
	}
}

func TestMaskSecretLegacyEnvFallback(t *testing.T) {
	t.Setenv("AMMIT_MASK_ENV", "")
	t.Setenv("AMMIT_ENV_MASK", "")
	t.Setenv("AMMIT_ENV_UNMASK", "")
	t.Setenv("CDEBUG_ENV_MASK", "LEGACY_SECRET")

	masked := maskSecret("LEGACY_SECRET=1")
	if !strings.Contains(masked, "(masked)") {
		t.Fatalf("expected legacy env fallback to mask key, got %q", masked)
	}
}

func captureStdoutForTest(fn func() error) (string, error) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdout = w
	runErr := fn()
	_ = w.Close()
	os.Stdout = old

	b, readErr := io.ReadAll(r)
	_ = r.Close()
	if readErr != nil {
		return "", readErr
	}
	if runErr != nil {
		return "", runErr
	}
	return string(b), nil
}
