package nono

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/txber/corral/integration"
)

// TestMain lets the test binary stand in for the corral binary: started
// with CORRAL_TEST_APPROVALD=1, it runs the approvald command on its
// arguments instead of the tests.
func TestMain(m *testing.M) {
	if os.Getenv("CORRAL_TEST_APPROVALD") == "1" {
		os.Exit(Approvald(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// startApprovald runs the command as its own process and returns its
// standard output, one line at a time.
func startApprovald(t *testing.T, socket, scopeFile string) (*exec.Cmd, *bufio.Scanner) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "--socket", socket, "--scope", scopeFile)
	cmd.Env = append(os.Environ(), "CORRAL_TEST_APPROVALD=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for range 100 {
		if _, err := os.Lstat(socket); err == nil {
			return cmd, bufio.NewScanner(stdout)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("approvald did not create its socket")
	return nil, nil
}

// nextLine reads one JSON line the command printed.
func nextLine(t *testing.T, lines *bufio.Scanner) map[string]any {
	t.Helper()
	if !lines.Scan() {
		t.Fatalf("no line printed: %v", lines.Err())
	}
	var line map[string]any
	if err := json.Unmarshal(lines.Bytes(), &line); err != nil {
		t.Fatalf("line %q: %v", lines.Text(), err)
	}
	if ts, _ := line["ts"].(string); !strings.HasSuffix(ts, "Z") {
		t.Errorf("ts = %q, want a UTC time", ts)
	}
	return line
}

func TestApprovaldAnswersFromAScopeFileAndPrintsEachDecision(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(dir, "inside")
	if err := os.Mkdir(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	scopeFile := filepath.Join(dir, "scope.toml")
	scope := fmt.Sprintf("targets = [\"192.0.2.10:tcp:443\"]\npaths = [%q]\n", inside)
	if err := os.WriteFile(scopeFile, []byte(scope), 0o600); err != nil {
		t.Fatal(err)
	}
	socket := socketPath(t)
	cmd, lines := startApprovald(t, socket, scopeFile)

	notes := filepath.Join(inside, "notes.txt")
	answer := exchange(t, socket, post(t, with(capability, "request_id", "in", "path", notes), 60))
	if answer.status != 200 || answer.body["decision"] != "granted" {
		t.Errorf("inside: answer %d %v, want 200 granted", answer.status, answer.body)
	}
	line := nextLine(t, lines)
	want := map[string]any{"kind": "path", "decision": "granted", "request_id": "in", "path": notes, "reason": answer.body["reason"]}
	for k, v := range want {
		if line[k] != v {
			t.Errorf("inside: line %s = %v, want %v", k, line[k], v)
		}
	}

	answer = exchange(t, socket, post(t, with(capability, "request_id", "out", "path", "/etc/shadow"), 60))
	if answer.body["decision"] != "denied" {
		t.Errorf("outside: answer %v, want denied", answer.body)
	}
	line = nextLine(t, lines)
	if line["decision"] != "denied" || line["request_id"] != "out" {
		t.Errorf("outside: line %v, want a denial of request out", line)
	}

	network := map[string]any{"capability_type": "network", "request_id": "net", "host": "api.example", "port": 443, "protocol": "tcp", "resolved_ips": []string{"192.0.2.10"}}
	answer = exchange(t, socket, post(t, network, 60))
	if answer.body["decision"] != "grant_session" {
		t.Errorf("network: answer %v, want grant_session", answer.body)
	}
	line = nextLine(t, lines)
	if line["kind"] != "network" || line["host"] != "api.example" || line["port"] != float64(443) {
		t.Errorf("network: line %v, want kind network, host api.example and port 443", line)
	}

	answer = exchange(t, socket, postBytes([]byte("{not json"), 60))
	if answer.status != 400 {
		t.Errorf("invalid JSON: status %d, want 400", answer.status)
	}
	line = nextLine(t, lines)
	if line["decision"] != "denied" || line["status"] != float64(400) || line["reason"] != answer.body["reason"] {
		t.Errorf("invalid JSON: line %v, want a denial with status 400 and reason %q", line, answer.body["reason"])
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Errorf("approvald after SIGTERM: %v, want exit 0", err)
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Errorf("socket still there after exit: %v", err)
	}
}

func TestApprovaldRefusesABadCommandLineOrScope(t *testing.T) {
	dir := t.TempDir()
	badScope := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(badScope, []byte("targets = [\"192.0.2.10\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unknownKey := filepath.Join(dir, "unknown.toml")
	if err := os.WriteFile(unknownKey, []byte("targets = []\nhosts = []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "a.sock")
	for _, args := range [][]string{
		nil,
		{"--socket", socket},
		{"--scope", badScope},
		{"--socket", socket, "--scope", badScope},
		{"--socket", socket, "--scope", unknownKey},
		{"--socket", socket, "--scope", filepath.Join(dir, "missing.toml")},
	} {
		var stdout, stderr bytes.Buffer
		if code := Approvald(args, &stdout, &stderr); code != 2 {
			t.Errorf("Approvald(%q) = %d, want 2", args, code)
		}
		if stdout.Len() != 0 || stderr.Len() == 0 {
			t.Errorf("Approvald(%q): stdout %q, stderr %q; want only a message on stderr", args, stdout.String(), stderr.String())
		}
	}
}

func TestScopeFileTakesOnlyTargetsAndPathsSpeltExactly(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		content string
		key     string // the key the error must name; "" when any error will do
	}{
		{"Targets = [\"192.0.2.10:tcp:443\"]\n", "Targets"},
		{"targets = []\nPATHS = [\"/home/you/shared\"]\n", "PATHS"},
		{"targets = []\nhosts = []\n", "hosts"},
		{"targets = []\n[extra]\nx = 1\n", "extra"},
		{"extra.x = 1\n", "extra"},
		{"targets.x = 1\n", ""},
		{"[paths]\nx = \"/home/you\"\n", ""},
		{"targets = \"192.0.2.10:tcp:443\"\n", ""},
	}
	for i, tt := range tests {
		file := filepath.Join(dir, fmt.Sprintf("scope%d.toml", i))
		if err := os.WriteFile(file, []byte(tt.content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadScope(file)
		if err == nil || !strings.Contains(err.Error(), tt.key) {
			t.Errorf("scope file %q: loadScope = %v, want an error naming %q", tt.content, err, tt.key)
		}
	}
	file := filepath.Join(dir, "good.toml")
	if err := os.WriteFile(file, []byte("targets = [\"192.0.2.10:tcp:443\"]\npaths = [\"/home/you/shared\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := loadScope(file)
	if err != nil || len(s.Targets) != 1 || len(s.Paths) != 1 {
		t.Errorf("loadScope = %+v, %v; want one target and one path", s, err)
	}
}

func TestApprovaldCutsEveryPrintedTextTo200Characters(t *testing.T) {
	long := strings.Repeat("é", 5000)
	var out bytes.Buffer
	p := &printer{w: &out}
	denied := integration.Decision{Decision: "denied", Reason: long}
	p.decision(integration.Request{Kind: "path", ID: long, Path: long, Access: long}, denied)
	p.decision(integration.Request{Kind: "network", ID: long, Host: long, Port: 443}, denied)
	p.decision(integration.Request{Kind: long, ID: long, Detail: long}, denied)
	p.denial(map[string]any{"status": 400, "reason": long, "backend": long, "request_id": long})
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("printed %d lines, want 4", len(lines))
	}
	for i, text := range lines {
		var line map[string]any
		if err := json.Unmarshal([]byte(text), &line); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if long := longTexts(line); len(long) > 0 {
			t.Errorf("line %d has texts longer than 200 characters: %v", i, long)
		}
	}
}

// lockedBuffer is a bytes.Buffer that the test may read while the server
// writes to it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestADecisionTooLateToBeSentIsNotPrinted(t *testing.T) {
	release := make(chan struct{})
	finished := make(chan struct{})
	slow := func(integration.Request) integration.Decision {
		defer close(finished)
		<-release
		return integration.Decision{Decision: "granted", Reason: "too late"}
	}
	var out lockedBuffer
	p := &printer{w: &out}
	path := socketPath(t)
	s, err := serveWithSent(path, slow, p.denial, p.decision)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// nono waits 2 s, so the deadline is already over.
	answer := exchange(t, path, post(t, capability, 2))
	close(release)
	<-finished
	time.Sleep(100 * time.Millisecond) // a wrong print would come now
	if answer.body["decision"] != "denied" {
		t.Errorf("answer = %v, want a denial", answer.body)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], `"decision":"denied"`) {
		t.Errorf("printed %q, want exactly one line, the denial", lines)
	}
}
