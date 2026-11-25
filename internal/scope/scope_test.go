package scope

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestTargetRoundTrips(t *testing.T) {
	for _, text := range []string{"10.10.4.7:tcp:445", "10.10.4.0/24:tcp:1-1024", "10.10.4.7:udp:53"} {
		target, err := ParseTarget(text)
		if err != nil {
			t.Errorf("ParseTarget(%q): %v", text, err)
			continue
		}
		if got := target.String(); got != text {
			t.Errorf("ParseTarget(%q).String() = %q", text, got)
		}
	}
}

func TestSingleHostIsSlash32AndNormalised(t *testing.T) {
	target, err := ParseTarget("10.10.4.7/32:tcp:80-80")
	if err != nil {
		t.Fatal(err)
	}
	if target.Network.Bits() != 32 {
		t.Errorf("bits = %d, want 32", target.Network.Bits())
	}
	if got := target.String(); got != "10.10.4.7:tcp:80" {
		t.Errorf("String() = %q, want %q", got, "10.10.4.7:tcp:80")
	}
}

func TestBadTargetsAreRefused(t *testing.T) {
	for _, text := range []string{
		"::1:tcp:80",
		"example.com:tcp:80",
		"0.0.0.0/0:tcp:80",
		"10.0.0.0/7:tcp:80",
		"10.10.4.7:tcp:0",
		"10.10.4.7:tcp:70000",
		"10.10.4.7:tcp:90-80",
		"10.10.4.7:icmp:1",
		"10.10.4.7/24:tcp:80",
		"10.10.4.7:tcp",
		"",
		"10.10.4.7:tcp:80;x",
		"10.10.4.7/33:tcp:80",
		"10.10.4.7:TCP:80",
		"::ffff:10.10.4.7:tcp:80",
		"10.10.4.7:tcp:80-",
		"10.10.4.7:tcp:-80",
		"10.10.4.7:tcp:80-90-100",
		"10.10.4.7:tcp:+80",
		"10.10.4.7:tcp: 80",
		"10.10.4.7:tcp:٨٠",
		"10.10.4.7:tcp:80:x",
	} {
		if _, err := ParseTarget(text); err == nil {
			t.Errorf("ParseTarget(%q) succeeded, want an error", text)
		}
	}
}

func TestNetmaskFormAndLeadingZerosAreRefused(t *testing.T) {
	for _, text := range []string{
		"10.0.0.0/255.0.0.0:tcp:80",
		"10.0.0.0/08:tcp:80",
		"10.10.4.0/024:tcp:80",
		"010.10.4.7:tcp:80",
		"10.10.4.7:tcp:080",
		"10.10.4.7:tcp:1-080",
		"10.10.4.7:tcp:00",
	} {
		if _, err := ParseTarget(text); err == nil {
			t.Errorf("ParseTarget(%q) succeeded, want an error", text)
		}
	}
}

func TestOverlongPortIsRefusedWithoutPanic(t *testing.T) {
	for _, port := range []string{
		"000001",
		"100000",
		"99999999999999999999",
		strings.Repeat("9", 10000),
	} {
		_, err := ParseTarget("10.10.4.7:tcp:" + port)
		if err == nil {
			t.Errorf("port %.30q accepted, want an error", port)
			continue
		}
		var numErr *strconv.NumError
		if errors.As(err, &numErr) {
			t.Errorf("port %.30q: error %v comes from strconv, want the package's own", port, err)
		}
		if len(err.Error()) > 200 {
			t.Errorf("port %.30q: error is %d bytes long, want it short", port, len(err.Error()))
		}
	}
}

func TestAllowsTargetMatchesNetworkProtoAndPortRange(t *testing.T) {
	s, err := New([]string{"10.10.4.0/24:tcp:1-1024"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		ip    string
		proto string
		port  int
		want  bool
	}{
		{"10.10.4.9", "tcp", 80, true},
		{"10.10.4.9", "tcp", 1, true},
		{"10.10.4.9", "tcp", 1024, true},
		{"10.10.4.9", "tcp", 2000, false},
		{"10.10.4.9", "udp", 80, false},
		{"10.10.5.9", "tcp", 80, false},
	}
	for _, tt := range tests {
		if got := s.AllowsTarget(tt.ip, tt.proto, tt.port); got != tt.want {
			t.Errorf("AllowsTarget(%q, %q, %d) = %v, want %v", tt.ip, tt.proto, tt.port, got, tt.want)
		}
	}
}

func TestAllowsTargetRefusesGarbage(t *testing.T) {
	s, err := New([]string{"10.10.4.0/24:tcp:1-1024"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		ip   string
		port int
	}{
		{"not-an-ip", 80},
		{"10.10.4.9", -1},
		{"10.10.4.9", 0},
		{"10.10.4.9", 1 << 40},
		{"::1", 80},
		{"::ffff:10.10.4.9", 80},
		{"", 80},
	}
	for _, tt := range tests {
		if s.AllowsTarget(tt.ip, "tcp", tt.port) {
			t.Errorf("AllowsTarget(%q, tcp, %d) = true, want false", tt.ip, tt.port)
		}
	}
}

func TestAllowsPathIsInsideOnly(t *testing.T) {
	s, err := New(nil, []string{"/w/a"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path string
		want bool
	}{
		{"/w/a", true},
		{"/w/a/b", true},
		{"/w/a/", true},
		{"/w/ab", false},
		{"/w", false},
		{"/w/a/../b", false},
		{"w/a", false},
		{"", false},
		{"/w/a/x\x00y", false},
	}
	for _, tt := range tests {
		if got := s.AllowsPath(tt.path); got != tt.want {
			t.Errorf("AllowsPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestRootPathAllowsEveryAbsolutePath(t *testing.T) {
	s, err := New(nil, []string{"/"})
	if err != nil {
		t.Fatal(err)
	}
	if !s.AllowsPath("/etc/passwd") {
		t.Error(`AllowsPath("/etc/passwd") = false under "/", want true`)
	}
}

func TestNewRefusesBadInput(t *testing.T) {
	tests := []struct {
		name    string
		targets []string
		paths   []string
	}{
		{"relative path", nil, []string{"relative/dir"}},
		{"empty path", nil, []string{""}},
		{"path with ..", nil, []string{"/w/../etc"}},
		{"bad target", []string{"10.10.4.7:tcp"}, nil},
		{"too many targets", repeat("10.0.0.1:tcp:1", 257), nil},
	}
	for _, tt := range tests {
		if _, err := New(tt.targets, tt.paths); err == nil {
			t.Errorf("%s: New succeeded, want an error", tt.name)
		}
	}
}

func TestNewKeepsTargetsAndCleansPaths(t *testing.T) {
	s, err := New(repeat("10.0.0.1:tcp:1", 256), []string{"/w/./a/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Targets) != 256 {
		t.Errorf("len(Targets) = %d, want 256", len(s.Targets))
	}
	if len(s.Paths) != 1 || s.Paths[0] != "/w/a" {
		t.Errorf("Paths = %q, want [/w/a]", s.Paths)
	}
}

// FuzzParseTarget checks that parsing never panics and that every accepted
// target reads back to itself.
func FuzzParseTarget(f *testing.F) {
	for _, seed := range []string{"10.10.4.7:tcp:445", "10.10.4.0/24:udp:1-1024", "10.0.0.0/255.0.0.0:tcp:80", "::1:tcp:80", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		target, err := ParseTarget(text)
		if err != nil {
			return
		}
		again, err := ParseTarget(target.String())
		if err != nil {
			t.Fatalf("ParseTarget(%q) does not accept its own String %q: %v", text, target.String(), err)
		}
		if again != target {
			t.Fatalf("ParseTarget(%q) = %+v, but its String reads back as %+v", text, target, again)
		}
	})
}

func repeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}
