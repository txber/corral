package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if got := stdout.String(); got != "corral 0.1.0\n" {
		t.Errorf("stdout = %q, want %q", got, "corral 0.1.0\n")
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

func TestUnknownSubcommandIsUsageError(t *testing.T) {
	for _, args := range [][]string{nil, {"nonsense"}} {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		if code != 2 {
			t.Errorf("run(%v) exit code = %d, want 2", args, code)
		}
		if stdout.Len() != 0 {
			t.Errorf("run(%v) wrote to stdout: %q", args, stdout.String())
		}
		if !strings.Contains(stderr.String(), "usage:") {
			t.Errorf("run(%v) stderr = %q, want a usage text", args, stderr.String())
		}
	}
}
