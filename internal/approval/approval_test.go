package approval

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/txber/corral/integration"
	"github.com/txber/corral/internal/scope"
)

func testScope(t *testing.T) scope.Scope {
	t.Helper()
	s, err := scope.New([]string{"10.10.4.0/24:tcp:1-1024"}, []string{"/w/a"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// identity resolves a path to itself, so that tests about the scope do not
// depend on the folders of this machine.
func identity(path string) (string, error) { return path, nil }

func pathRequest(path string) integration.Request {
	return integration.Request{Kind: "path", ID: "r", Path: path, Access: "read"}
}

func networkRequest(port int, addresses ...string) integration.Request {
	return integration.Request{Kind: "network", Host: "h", Port: port, Addresses: addresses}
}

func TestPathInsideScopeIsGranted(t *testing.T) {
	d := Decide(pathRequest("/w/a/file"), testScope(t), identity)
	if d.Decision != "granted" {
		t.Errorf("decision = %q (%s), want granted", d.Decision, d.Reason)
	}
	if !strings.Contains(d.Reason, "/w/a/file") {
		t.Errorf("reason %q does not name the path", d.Reason)
	}
}

func TestPathOutsideScopeIsDenied(t *testing.T) {
	d := Decide(pathRequest("/etc/passwd"), testScope(t), identity)
	if d.Decision != "denied" {
		t.Errorf("decision = %q (%s), want denied", d.Decision, d.Reason)
	}
	if !strings.Contains(d.Reason, "/etc/passwd") {
		t.Errorf("reason %q does not name the path", d.Reason)
	}
}

func TestPathIsNeverASessionAnswer(t *testing.T) {
	for _, path := range []string{"/w/a/x", "/etc/passwd"} {
		d := Decide(pathRequest(path), testScope(t), identity)
		if d.Decision != "granted" && d.Decision != "denied" {
			t.Errorf("%s: decision = %q, want granted or denied", path, d.Decision)
		}
	}
}

func TestSymlinkOutOfScopeIsDenied(t *testing.T) {
	dir := realTempDir(t)
	allowed := filepath.Join(dir, "a")
	outside := filepath.Join(dir, "secret")
	for _, d := range []string{allowed, outside} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(allowed, "link")); err != nil {
		t.Fatal(err)
	}
	s, err := scope.New(nil, []string{allowed})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path string
		want string
	}{
		{filepath.Join(allowed, "link", "x"), "denied"},
		{filepath.Join(allowed, "link"), "denied"},
		{filepath.Join(allowed, "x"), "granted"},
	}
	for _, tt := range tests {
		if d := Decide(pathRequest(tt.path), s, nil); d.Decision != tt.want {
			t.Errorf("%s: decision = %q (%s), want %s", tt.path, d.Decision, d.Reason, tt.want)
		}
	}
}

func TestDanglingSymlinkOutOfScopeIsDenied(t *testing.T) {
	dir := realTempDir(t)
	allowed := filepath.Join(dir, "a")
	if err := os.Mkdir(allowed, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(allowed, "link")
	if err := os.Symlink(filepath.Join(dir, "secret", "new"), link); err != nil {
		t.Fatal(err)
	}
	s, err := scope.New(nil, []string{allowed})
	if err != nil {
		t.Fatal(err)
	}
	if d := Decide(pathRequest(link), s, nil); d.Decision != "denied" {
		t.Errorf("decision = %q (%s), want denied", d.Decision, d.Reason)
	}
}

func TestDotDotAfterAMissingFolderIsDenied(t *testing.T) {
	dir := realTempDir(t)
	allowed := filepath.Join(dir, "a")
	if err := os.Mkdir(allowed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir, filepath.Join(allowed, "up")); err != nil {
		t.Fatal(err)
	}
	s, err := scope.New(nil, []string{allowed})
	if err != nil {
		t.Fatal(err)
	}
	path := allowed + "/missing/../up/x"
	if d := Decide(pathRequest(path), s, nil); d.Decision != "denied" {
		t.Errorf("decision = %q (%s), want denied", d.Decision, d.Reason)
	}
}

func TestNonExistentPathInsideScopeIsGranted(t *testing.T) {
	dir := realTempDir(t)
	s, err := scope.New(nil, []string{dir})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "new", "deeper", "file")
	d := Decide(pathRequest(path), s, nil)
	if d.Decision != "granted" {
		t.Errorf("decision = %q (%s), want granted", d.Decision, d.Reason)
	}
	got, err := Realpath(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Errorf("Realpath(%q) = %q, want it unchanged", path, got)
	}
}

func TestRealpathResolvesDotDotThroughASymlink(t *testing.T) {
	dir := realTempDir(t)
	deep := filepath.Join(dir, "x", "y")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "a"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(deep, filepath.Join(dir, "a", "link")); err != nil {
		t.Fatal(err)
	}
	// The kernel follows link before applying "..", so this names dir/x/new.
	got, err := Realpath(dir + "/a/link/../new")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "x", "new"); got != want {
		t.Errorf("Realpath = %q, want %q", got, want)
	}
}

func TestRealpathRefusesARelativePath(t *testing.T) {
	for _, path := range []string{"", "x", "./x", "../x"} {
		if got, err := Realpath(path); err == nil {
			t.Errorf("Realpath(%q) = %q, want an error", path, got)
		}
	}
}

func TestRelativePathIsDeniedEvenIfTheWorkingFolderIsInScope(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	s, err := scope.New(nil, []string{cwd})
	if err != nil {
		t.Fatal(err)
	}
	resolved := false
	resolve := func(path string) (string, error) {
		resolved = true
		return filepath.Join(cwd, path), nil
	}
	for _, path := range []string{"x", "./x", ""} {
		d := Decide(pathRequest(path), s, resolve)
		if d.Decision != "denied" {
			t.Errorf("%q: decision = %q, want denied", path, d.Decision)
		}
		if !strings.Contains(d.Reason, "absolute") {
			t.Errorf("%q: reason %q does not say the path is not absolute", path, d.Reason)
		}
	}
	if resolved {
		t.Error("a relative path was passed to resolve")
	}
}

func TestMalformedPathRequestIsDenied(t *testing.T) {
	s := testScope(t)
	if d := Decide(pathRequest("/w/a/x\x00y"), s, identity); d.Decision != "denied" {
		t.Errorf("path with NUL: decision = %q, want denied", d.Decision)
	}
	failing := func(string) (string, error) { return "", errors.New("boom") }
	if d := Decide(pathRequest("/w/a/x"), s, failing); d.Decision != "denied" {
		t.Errorf("failing resolve: decision = %q, want denied", d.Decision)
	}
	escaping := func(string) (string, error) { return "/w/a/../b", nil }
	if d := Decide(pathRequest("/w/a/x"), s, escaping); d.Decision != "denied" {
		t.Errorf("resolve with ..: decision = %q, want denied", d.Decision)
	}
}

func TestNetworkWithAllAddressesAllowedIsGrantSession(t *testing.T) {
	d := Decide(networkRequest(445, "10.10.4.7", "10.10.4.8"), testScope(t), nil)
	if d.Decision != "grant_session" {
		t.Errorf("decision = %q (%s), want grant_session", d.Decision, d.Reason)
	}
	if !strings.Contains(d.Reason, "445") {
		t.Errorf("reason %q does not name the port", d.Reason)
	}
}

func TestNetworkIsDeniedUnlessEveryAddressIsAllowed(t *testing.T) {
	tests := []struct {
		name    string
		request integration.Request
	}{
		{"one address outside", networkRequest(445, "10.10.4.7", "10.99.0.1")},
		{"no addresses", networkRequest(445)},
		{"port outside", networkRequest(2000, "10.10.4.7")},
		{"port zero", networkRequest(0, "10.10.4.7")},
		{"negative port", networkRequest(-1, "10.10.4.7")},
		{"address is not an IP", networkRequest(445, "10.10.4.7", "h")},
		{"empty address", networkRequest(445, "")},
		{"IPv6 address", networkRequest(445, "::1")},
	}
	for _, tt := range tests {
		if d := Decide(tt.request, testScope(t), nil); d.Decision != "denied" {
			t.Errorf("%s: decision = %q (%s), want denied", tt.name, d.Decision, d.Reason)
		}
	}
}

func TestNetworkIsCheckedAsTCP(t *testing.T) {
	s, err := scope.New([]string{"10.10.4.7:udp:53"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := Decide(networkRequest(53, "10.10.4.7"), s, nil); d.Decision != "denied" {
		t.Errorf("decision = %q (%s), want denied: only a udp target is in scope", d.Decision, d.Reason)
	}
}

func TestOtherAndUnknownKindsAreDenied(t *testing.T) {
	for _, kind := range []string{"other", "endpoint", "command", "unix_socket", "", "PATH", "Network"} {
		r := integration.Request{Kind: kind, Path: "/w/a/x", Port: 445, Addresses: []string{"10.10.4.7"}, Detail: "something"}
		d := Decide(r, testScope(t), identity)
		if d.Decision != "denied" {
			t.Errorf("kind %q: decision = %q, want denied", kind, d.Decision)
		}
		if !strings.Contains(d.Reason, "kind") {
			t.Errorf("kind %q: reason %q does not name the kind", kind, d.Reason)
		}
	}
}

func TestLongRequestTextsAreCutInTheReason(t *testing.T) {
	long := strings.Repeat("a", 10000)
	tests := []struct {
		name    string
		request integration.Request
		resolve func(string) (string, error)
	}{
		{"path outside", pathRequest("/" + long), identity},
		{"path that cannot be resolved", pathRequest("/" + long), nil},
		{"relative path", pathRequest(long), identity},
		{"host without addresses", integration.Request{Kind: "network", Host: long, Port: 445}, nil},
		{"address", networkRequest(445, long), nil},
		{"kind", integration.Request{Kind: long}, nil},
	}
	for _, tt := range tests {
		d := Decide(tt.request, testScope(t), tt.resolve)
		if d.Decision != "denied" {
			t.Errorf("%s: decision = %q, want denied", tt.name, d.Decision)
		}
		if len(d.Reason) >= 400 {
			t.Errorf("%s: reason is %d bytes long, want under 400", tt.name, len(d.Reason))
		}
	}
}

// realTempDir returns a fresh temporary folder with every symbolic link in
// its path resolved, so that it can serve as a scope path.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
