package netns

import (
	"slices"
	"testing"
)

func TestExecCommandLine(t *testing.T) {
	got := execCommandLine("/usr/bin/nsenter", "/usr/bin/setpriv", "w1", 1000, 1001,
		[]string{"/opt/bin/agent", "--flag", "--", "x"})
	want := []string{
		"/usr/bin/nsenter", "--net=/run/netns/oc-w1", "--",
		"/usr/bin/setpriv", "--reuid=1000", "--regid=1001", "--init-groups", "--inh-caps=-all", "--",
		"/opt/bin/agent", "--flag", "--", "x",
	}
	if !slices.Equal(got, want) {
		t.Errorf("execCommandLine =\n%q\nwant\n%q", got, want)
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
