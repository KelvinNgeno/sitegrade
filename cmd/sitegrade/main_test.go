package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-version"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "sitegrade") {
		t.Errorf("output = %q", out.String())
	}
}

func TestRunWithoutTargetsShowsUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(nil, &out, &errOut); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "Usage:") {
		t.Errorf("expected usage text, got %q", errOut.String())
	}
}

func TestRunRejectsBadFlags(t *testing.T) {
	tests := [][]string{
		{"-format", "xml", "example.com"},
		{"-min-grade", "Z", "example.com"},
		{"-no-such-flag"},
	}
	for _, args := range tests {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != 2 {
			t.Errorf("run(%v) = %d, want 2", args, code)
		}
	}
}

func TestParseArgsAllowsFlagsAfterTargets(t *testing.T) {
	var out, errOut bytes.Buffer
	// "-version" after a target should still be honoured.
	if code := run([]string{"example.com", "-version"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, errOut.String())
	}
}
