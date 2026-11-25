package nono

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/txber/corral/integration"
)

func FuzzParseRequest(f *testing.F) {
	for _, seed := range []string{
		toolFileRequest,
		toolNetworkRequest,
		`{"capability_type":"capability","path":"","access":""}`,
		`{"capability_type":"capability","path":"x","access":"Read"}`,
		`{"capability_type":"network","host":"h","port":65536,"resolved_ips":[]}`,
		`{"capability_type":"network","host":"h","port":80,"protocol":"TCP","resolved_ips":[]}`,
		`{"capability_type":"network","capability_type":"capability","path":"/x","access":"Read"}`,
		`{"capability_type":"x\u0000` + "\xff" + `","request_id":7}`,
		`null`, `[]`, `{}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, err := parseRequest(raw)
		if err != nil {
			return
		}
		// What the body says, read on its own.
		var view struct {
			Protocol *string         `json:"protocol"`
			ID       json.RawMessage `json:"request_id"`
		}
		_ = json.Unmarshal(raw, &view)
		if len(view.ID) > 0 && string(view.ID) != "null" && view.ID[0] != '"' {
			t.Errorf("request id %s is not a string, yet %q was accepted", view.ID, raw)
		}
		switch r.Kind {
		case "path":
			if !filepath.IsAbs(r.Path) || r.Access == "" {
				t.Errorf("file request without an absolute path or an access: %+v", r)
			}
			if r.Host != "" || r.Port != 0 || r.Addresses != nil || r.Detail != "" {
				t.Errorf("file request with fields of another kind: %+v", r)
			}
		case "network":
			if r.Port < 1 || r.Port > 65535 {
				t.Errorf("network request with port %d", r.Port)
			}
			if view.Protocol != nil && *view.Protocol != "tcp" {
				t.Errorf("network request with protocol %q", *view.Protocol)
			}
			if r.Path != "" || r.Access != "" || r.Detail != "" {
				t.Errorf("network request with fields of another kind: %+v", r)
			}
		case "other":
			if utf8.RuneCountInString(r.Detail) > 100 {
				t.Errorf("detail of %d characters", utf8.RuneCountInString(r.Detail))
			}
			if r.Path != "" || r.Access != "" || r.Host != "" || r.Port != 0 || r.Addresses != nil {
				t.Errorf("other request with fields of another kind: %+v", r)
			}
		default:
			t.Errorf("kind %q", r.Kind)
		}
	})
}

// FuzzServer sends any bytes over one connection to a fresh endpoint whose
// decide grants one request only.
func FuzzServer(f *testing.F) {
	valid, _ := json.Marshal(map[string]any{"backend": "sup", "request": capability})
	long := strings.Repeat("é", 300)
	for _, seed := range []string{
		string(postBytes(valid, 60)),
		string(postBytes(valid, 1)),
		string(postBytes(valid, 60)) + string(postBytes(valid, 60)),
		"POST / HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}",
		"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}",
		"POST / HTTP/1.0\r\nContent-Length: 2\r\n\r\n{}",
		"GET / HTTP/1.1\r\n\r\n",
		"POST /" + long + " HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
		string(postBytes([]byte(`{"backend":"`+long+`","request":{"capability_type":5,"request_id":"`+long+`"}}`), 60)),
		string(postBytes([]byte(`{"backend":"sup","request":{"capability_type":"capability","path":"x","access":"Read"}}`), 60)),
		string(postBytes([]byte(`{"backend":"sup","request":{"capability_type":"capability","path":"/etc/shadow","access":"Read","path":"/srv/data/x","request_id":"r1"}}`), 60)),
		"",
	} {
		f.Add([]byte(seed))
	}
	saved := receiveTimeout
	receiveTimeout = 150 * time.Millisecond
	f.Cleanup(func() { receiveTimeout = saved })

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		checkOneConnection(t, data)
	})
}

// checkOneConnection sends data, half-closes the connection, reads what
// comes back and closes the server.
func checkOneConnection(t *testing.T, data []byte) {
	granted := integration.Request{Kind: "path", ID: "r1", Path: "/srv/data/x", Access: "Read"}
	var mu sync.Mutex
	var seen []integration.Request
	var reported []map[string]any
	decide := func(r integration.Request) integration.Decision {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, r)
		if r.Kind == granted.Kind && r.ID == granted.ID && r.Path == granted.Path && r.Access == granted.Access {
			return integration.Decision{Decision: "granted", Reason: "the one"}
		}
		return integration.Decision{Decision: "denied", Reason: "not the one"}
	}
	report := func(m map[string]any) {
		mu.Lock()
		defer mu.Unlock()
		reported = append(reported, m)
	}

	goroutines := runtime.NumGoroutine()
	path := filepath.Join(t.TempDir(), "s")
	s, err := serve(path, decide, report)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write(data)
	_ = conn.CloseWrite()
	all, _ := io.ReadAll(conn)
	conn.Close()
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket file after Close: %v", err)
	}
	for range 100 {
		if runtime.NumGoroutine() <= goroutines {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if now := runtime.NumGoroutine(); now > goroutines {
		t.Errorf("%d goroutines before serve, %d after Close", goroutines, now)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, m := range reported {
		if long := longTexts(m); len(long) > 0 {
			t.Errorf("report %v has texts longer than 200 characters: %v", m, long)
		}
	}
	for _, r := range seen {
		if r.Kind == "path" && (!filepath.IsAbs(r.Path) || r.Access == "") {
			t.Errorf("decide got a file request without an absolute path or an access: %+v", r)
		}
	}
	if len(data) == 0 {
		if len(all) != 0 || len(reported) != 0 {
			t.Errorf("empty connection: answer %q, reports %v; want neither", all, reported)
		}
		return
	}
	if len(all) == 0 {
		// The server may close before it has read everything, and the
		// client then sees its connection reset instead of the answer.
		return
	}

	reader := bufio.NewReader(bytes.NewReader(all))
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("answer %q is not HTTP: %v", all, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if _, err := reader.Peek(1); err == nil {
		t.Fatalf("more than one answer: %q", all)
	}
	var answer struct{ Decision, Reason string }
	if err := json.Unmarshal(raw, &answer); err != nil {
		t.Fatalf("answer body %q: %v", raw, err)
	}

	switch answer.Decision {
	case "granted":
		if resp.StatusCode != 200 || answer.Reason != "the one" {
			t.Errorf("grant %d %q that decide did not give", resp.StatusCode, answer.Reason)
		}
	case "denied":
	default:
		t.Errorf("decision %q", answer.Decision)
	}
	serverMade := resp.StatusCode != 200 || strings.HasPrefix(answer.Reason, "no decision within") || answer.Reason == "approval handler failed"
	if serverMade {
		if len(reported) != 1 || reported[0]["status"] != resp.StatusCode || reported[0]["reason"] != answer.Reason {
			t.Errorf("denial %d %q, reports %v; want one report of it", resp.StatusCode, answer.Reason, reported)
		}
	} else if len(reported) != 0 || len(seen) != 1 {
		t.Errorf("answer of decide, but %d reports and %d calls of decide", len(reported), len(seen))
	}
}

// FuzzProfile prepares and wraps an agent with any values. Prepare either
// refuses or writes profiles that hold every value exactly as given.
func FuzzProfile(f *testing.F) {
	f.Add("none", "a1", "/home/you/work/a1", "a1", "/home/you/x", "/usr/local/lib/tool", "2G", 18007,
		"example", "https://gateway.example/v1", "/home/you/.keys/example", "POST", "/chat/completions", "rpc")
	f.Add("direct", "a1", "/w", "a1", "/w/s\xff", "/r", "", 0, "example", "https://gateway.example/v1", "/k", "GET", "/models", "")
	f.Add("direct", "0", "\xb0", "/", "\xd3", "0", "0", 18007, "0", "0", "0", "0", "0", "0")
	f.Add("proxy", "--force", "-rf", "x", "/a\n", "/b\x00", "--allow=/", 0, "e\u0085", "://", "rel", "", "", "--")
	f.Fuzz(func(t *testing.T, mode, id, workdir, state, deny, read, memory string, proxyPort int,
		name, upstream, keyFile, method, endpoint, arg string) {
		// The state folder is a fresh folder of its own, so that no input
		// decides where a file is written.
		stateDir := filepath.Join(t.TempDir(), "s"+strings.ReplaceAll(state, "/", "_"))
		_ = os.Mkdir(stateDir, 0o700)
		a := integration.Agent{
			ID: id, Network: mode, Workdir: workdir, StateDir: stateDir,
			Limits: integration.Limits{Memory: memory},
			Deny:   []string{"/home/you/.keys", deny},
			Gateway: integration.Gateway{
				Name: name, Upstream: upstream, KeyFile: keyFile,
				Endpoints: []integration.Endpoint{{Method: method, Path: endpoint}},
			},
			ProxyPort: proxyPort,
		}
		readPaths := []string{read}
		s := sandbox{binary: binary}

		err := s.Prepare(a, readPaths)
		file := filepath.Join(stateDir, sandboxProfileFile)
		if err != nil {
			if _, statErr := os.Stat(file); statErr == nil {
				t.Errorf("Prepare refused (%v) but wrote %s", err, file)
			}
		} else {
			checkPrepared(t, a, readPaths, file)
			if stop := s.StopCommand(a); slices.ContainsFunc(stop[2:], func(arg string) bool { return strings.HasPrefix(arg, "-") }) {
				t.Errorf("StopCommand %q has an option after stop", stop)
			}
		}

		if mode == "direct" {
			k := keyProxy{binary: binary}
			err := k.Prepare(a, a.Gateway, netip.MustParseAddrPort("198.18.7.1:18007"))
			file := filepath.Join(stateDir, proxyProfileFile)
			if err != nil {
				if _, statErr := os.Stat(file); statErr == nil {
					t.Errorf("key proxy Prepare refused (%v) but wrote %s", err, file)
				}
			} else {
				if !plainText(stateDir, name, upstream, keyFile, method, endpoint) {
					t.Errorf("key proxy Prepare accepted text it cannot write as given")
				}
				var p profile
				readProfile(t, file, &p)
				checkGateway(t, a.Gateway, p.Network)
			}
		}

		command := []string{"pi", arg}
		argv := s.Wrap(a, command)
		end := len(argv) - len(command) - 1
		if argv[0] != binary || argv[1] != "run" || argv[end] != "--" || !slices.Equal(argv[end+1:], command) {
			t.Fatalf("Wrap = %q, want the binary, run, the options, -- and the command", argv)
		}
		options := argv[2:end]
		for _, option := range options {
			if !strings.HasPrefix(option, "--") || option == "--" {
				t.Errorf("%q before -- is not an option", option)
			}
		}
		for _, want := range []string{"--name=" + id, "--allow=" + workdir} {
			if !slices.Contains(options, want) {
				t.Errorf("Wrap = %q, want %q", argv, want)
			}
		}
		if slices.Contains(options, "--sandbox-policy=external") != (mode == "direct") {
			t.Errorf("mode %q: Wrap = %q", mode, argv)
		}
		if slices.Contains(options, "--block-net") != (mode != "none" && mode != "direct") {
			t.Errorf("mode %q: Wrap = %q", mode, argv)
		}
	})
}

// plainText reports whether every value is valid UTF-8 without a control
// character.
func plainText(values ...string) bool {
	for _, v := range values {
		if !utf8.ValidString(v) {
			return false
		}
		for _, r := range v {
			if r < 0x20 || (r >= 0x7f && r < 0xa0) {
				return false
			}
		}
	}
	return true
}

// checkPrepared checks a sandbox profile that Prepare wrote for a.
func checkPrepared(t *testing.T, a integration.Agent, readPaths []string, file string) {
	t.Helper()
	if a.Network != "none" && a.Network != "direct" {
		t.Errorf("Prepare accepted mode %q", a.Network)
	}
	if !agentID.MatchString(a.ID) {
		t.Errorf("Prepare accepted id %q", a.ID)
	}
	values := append([]string{a.Workdir, a.StateDir, a.Limits.Memory}, a.Deny...)
	if !plainText(append(values, readPaths...)...) {
		t.Errorf("Prepare accepted text it cannot write as given: %+v", a)
	}
	var p profile
	readProfile(t, file, &p)
	if !slices.Equal(p.Filesystem.Deny, a.Deny) || !slices.Equal(p.Filesystem.Read, readPaths) {
		t.Errorf("profile denies %q and reads %q, want %q and %q", p.Filesystem.Deny, p.Filesystem.Read, a.Deny, readPaths)
	}
	if (p.Network != nil) != (a.Network == "none") {
		t.Errorf("mode %q: network section %v", a.Network, p.Network)
	}
	if p.Network != nil {
		checkGateway(t, a.Gateway, p.Network)
	}
}

// checkGateway checks that a network section routes the gateway g as given.
func checkGateway(t *testing.T, g integration.Gateway, n *networkSection) {
	t.Helper()
	if !plainText(g.Name, g.Upstream, g.KeyFile, g.Endpoints[0].Method, g.Endpoints[0].Path) {
		t.Errorf("gateway text that cannot be written as given was accepted: %+v", g)
	}
	route, ok := n.CustomCredentials[g.Name]
	if !ok || !slices.Equal(n.Credentials, []string{g.Name}) || route.Upstream != g.Upstream || route.CredentialKey != "file://"+g.KeyFile {
		t.Errorf("gateway %+v written as %+v", g, n)
	}
	want := []endpointRule{{Method: g.Endpoints[0].Method, Path: g.Endpoints[0].Path}}
	if !slices.Equal(route.EndpointRules, want) {
		t.Errorf("endpoint rules %+v, want %+v", route.EndpointRules, want)
	}
}

func readProfile(t *testing.T, file string, p *profile) {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, p); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
}
