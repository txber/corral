package netns

import (
	"slices"
	"testing"
)

func TestExecCommandLine(t *testing.T) {
	got := execCommandLine("/usr/bin/nsenter", "/usr/bin/setpriv", "/opt/corral/bin/corral", "w1", 1000, 1001,
		"/home/you/env", []string{"/opt/bin/agent", "--flag", "--", "x"})
	want := []string{
		"/usr/bin/nsenter", "--net=/run/netns/oc-w1", "--",
		"/usr/bin/setpriv", "--reuid=1000", "--regid=1001", "--init-groups", "--inh-caps=-all", "--no-new-privs", "--",
		"/opt/corral/bin/corral", "netns", "enter", "--env-file", "/home/you/env", "--",
		"/opt/bin/agent", "--flag", "--", "x",
	}
	if !slices.Equal(got, want) {
		t.Errorf("execCommandLine =\n%q\nwant\n%q", got, want)
	}
}

func TestEffectiveCapabilitiesAreRead(t *testing.T) {
	tests := map[string]bool{
		"Name:\tsh\nCapInh:\t0000000000000000\nCapEff:\t0000000000000000\n": false,
		"Name:\tsh\nCapEff:\t000001ffffffffff\n":                            true,
		"Name:\tsh\nCapEff:\t0000000000000400\n":                            true,
		"Name:\tsh\n":                                                       true, // unknown counts as capable
	}
	for status, want := range tests {
		if got := hasEffectiveCapabilities(status); got != want {
			t.Errorf("hasEffectiveCapabilities(%q) = %v, want %v", status, got, want)
		}
	}
}

func TestCallerIDAcceptsAnUnprivilegedID(t *testing.T) {
	if id, err := callerID("SUDO_UID", "1000"); err != nil || id != 1000 {
		t.Errorf("callerID(1000) = %d, %v; want 1000", id, err)
	}
}

func TestCallerIDRefuses(t *testing.T) {
	for _, text := range []string{"", "0", "-1", "+5", "01000", "1e3", " 1000", "4294967295", "99999999999"} {
		if id, err := callerID("SUDO_UID", text); err == nil {
			t.Errorf("callerID(%q) = %d, want an error", text, id)
		}
	}
}

func TestNoNewPrivsIsRead(t *testing.T) {
	tests := map[string]bool{
		"Name:\tsh\nNoNewPrivs:\t1\nSeccomp:\t0\n": true,
		"Name:\tsh\nNoNewPrivs:\t0\n":              false,
		"Name:\tsh\n":                              false,
	}
	for status, want := range tests {
		if got := hasNoNewPrivs(status); got != want {
			t.Errorf("hasNoNewPrivs(%q) = %v, want %v", status, got, want)
		}
	}
}
