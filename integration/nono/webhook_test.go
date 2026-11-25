package nono

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/txber/corral/integration"
)

// capability is a file request as the sandbox sends it.
var capability = map[string]any{
	"capability_type": "capability",
	"request_id":      "r1",
	"session_id":      "s1",
	"path":            "/srv/data/x",
	"access":          "Read",
	"reason":          nil,
	"child_pid":       7,
}

// with returns a copy of request with the given fields changed.
func with(request map[string]any, changes ...any) map[string]any {
	out := map[string]any{}
	for k, v := range request {
		out[k] = v
	}
	for i := 0; i+1 < len(changes); i += 2 {
		out[changes[i].(string)] = changes[i+1]
	}
	return out
}

func granting(integration.Request) integration.Decision {
	return integration.Decision{Decision: "grant_session", Reason: "in scope"}
}

// socketPath returns a socket path in a fresh folder. The folder is short,
// because a Unix socket path may not exceed 107 bytes.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "corral")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "a.sock")
}

// quietLog drops the log lines of the test, such as the stack of a
// panic the server recovered from.
func quietLog(t *testing.T) {
	t.Helper()
	saved := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(saved) })
}

// reports collects what the server reports, safe for concurrent use.
type reports struct {
	mu   sync.Mutex
	list []map[string]any
}

func (r *reports) add(m map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.list = append(r.list, m)
}

func (r *reports) all() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]map[string]any(nil), r.list...)
}

// serving starts a server on a fresh socket and closes it when the test ends.
func serving(t *testing.T, decide func(integration.Request) integration.Decision, report func(map[string]any)) string {
	t.Helper()
	if report == nil {
		report = func(map[string]any) {}
	}
	path := socketPath(t)
	s, err := serve(path, decide, report)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return path
}

// reply is one answer of the server.
type reply struct {
	status int
	header http.Header
	close  bool // the server said Connection: close
	body   map[string]any
}

// exchange sends raw bytes over a new connection and reads one response.
func exchange(t *testing.T, path string, data []byte) reply {
	t.Helper()
	r, err := roundTrip(path, data)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// roundTrip is exchange for goroutines other than the test's own.
func roundTrip(path string, data []byte) (reply, error) {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return reply{}, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return reply{}, err
	}
	// The server may answer before it has read everything, for example when
	// the headers are too large, and close; the answer still arrives.
	_, _ = conn.Write(data)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return reply{}, fmt.Errorf("reading the response: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return reply{}, fmt.Errorf("reading the response body: %w", err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return reply{}, fmt.Errorf("response body %q: %w", raw, err)
	}
	return reply{status: resp.StatusCode, header: resp.Header, close: resp.Close, body: body}, nil
}

// postBytes is a request as the sandbox sends it, with body as it is.
func postBytes(body []byte, timeoutSecs int) []byte {
	head := "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body))
	if timeoutSecs > 0 {
		head += fmt.Sprintf("X-Nono-Timeout-Secs: %d\r\n", timeoutSecs)
	}
	return append([]byte(head+"\r\n"), body...)
}

// post is a request for backend "sup" carrying request.
func post(t *testing.T, request any, timeoutSecs int) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"backend": "sup", "request": request})
	if err != nil {
		t.Fatal(err)
	}
	return postBytes(body, timeoutSecs)
}

func TestValidRequestReturnsTheDecision(t *testing.T) {
	var seen []integration.Request
	var mu sync.Mutex
	path := serving(t, func(r integration.Request) integration.Decision {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, r)
		return integration.Decision{Decision: "grant_session", Reason: "in scope"}
	}, nil)
	got := exchange(t, path, post(t, capability, 60))
	if got.status != 200 {
		t.Errorf("status = %d, want 200", got.status)
	}
	if !got.close {
		t.Error("response does not say Connection: close")
	}
	if v := got.header.Get("Content-Type"); v != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", v)
	}
	if want := map[string]any{"decision": "grant_session", "reason": "in scope"}; !reflect.DeepEqual(got.body, want) {
		t.Errorf("body = %v, want %v", got.body, want)
	}
	want := integration.Request{Kind: "path", ID: "r1", Path: "/srv/data/x", Access: "Read"}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || !reflect.DeepEqual(seen[0], want) {
		t.Errorf("decide saw %+v, want one %+v", seen, want)
	}
}

func TestPanickingDecideIsADenial(t *testing.T) {
	quietLog(t)
	path := serving(t, func(integration.Request) integration.Decision { panic("boom") }, nil)
	got := exchange(t, path, post(t, capability, 60))
	if got.status != 200 || got.body["decision"] != "denied" || got.body["reason"] == "" {
		t.Errorf("got %d %v, want 200 and a denial with a reason", got.status, got.body)
	}
}

func TestSlowDecideIsADenialBeforeTheSandboxGivesUp(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	path := serving(t, func(integration.Request) integration.Decision {
		<-release
		return integration.Decision{Decision: "granted", Reason: "too late"}
	}, nil)
	started := time.Now()
	got := exchange(t, path, post(t, capability, 3))
	elapsed := time.Since(started)
	if got.status != 200 || got.body["decision"] != "denied" {
		t.Errorf("got %d %v, want 200 and a denial", got.status, got.body)
	}
	// The deadline is the sandbox's 3 s minus a 2 s margin.
	if elapsed > 1500*time.Millisecond {
		t.Errorf("answer took %v, want under 1.5 s", elapsed)
	}
}

func TestInvalidJSONIs400WithADenialBody(t *testing.T) {
	path := serving(t, granting, nil)
	got := exchange(t, path, postBytes([]byte("{not json"), 60))
	if got.status != 400 || got.body["decision"] != "denied" {
		t.Errorf("got %d %v, want 400 and a denial", got.status, got.body)
	}
}

func TestBodyThatIsNotAnObjectIsADenial(t *testing.T) {
	path := serving(t, granting, nil)
	for _, payload := range []string{`[1, 2]`, `"text"`, `null`, `3`} {
		got := exchange(t, path, postBytes([]byte(payload), 60))
		if got.status != 400 || got.body["decision"] != "denied" {
			t.Errorf("body %s: got %d %v, want 400 and a denial", payload, got.status, got.body)
		}
	}
}

func TestRequestMemberThatIsNotAnObjectIsADenial(t *testing.T) {
	called := false
	var mu sync.Mutex
	path := serving(t, func(integration.Request) integration.Decision {
		mu.Lock()
		defer mu.Unlock()
		called = true
		return integration.Decision{Decision: "granted"}
	}, nil)
	for _, request := range []any{[]any{capability}, "capability", nil} {
		got := exchange(t, path, post(t, request, 60))
		if got.status != 400 || got.body["decision"] != "denied" {
			t.Errorf("request %v: got %d %v, want 400 and a denial", request, got.status, got.body)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if called {
		t.Error("decide was called")
	}
}

func TestGetIs405(t *testing.T) {
	path := serving(t, granting, nil)
	got := exchange(t, path, []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	if got.status != 405 || got.body["decision"] != "denied" {
		t.Errorf("got %d %v, want 405 and a denial", got.status, got.body)
	}
	if v := got.header.Get("Allow"); v != "POST" {
		t.Errorf("Allow = %q, want POST", v)
	}
}

func TestTwoRequestsAreServedConcurrently(t *testing.T) {
	release := make(chan struct{})
	path := serving(t, func(r integration.Request) integration.Decision {
		if r.ID == "first" {
			<-release
			return integration.Decision{Decision: "granted", Reason: "first"}
		}
		return integration.Decision{Decision: "denied", Reason: "second"}
	}, nil)
	first := make(chan reply, 1)
	firstRequest := post(t, with(capability, "request_id", "first"), 60)
	go func() {
		r, err := roundTrip(path, firstRequest)
		if err != nil {
			t.Error(err)
		}
		first <- r
	}()
	time.Sleep(100 * time.Millisecond)
	second := exchange(t, path, post(t, with(capability, "request_id", "second"), 60))
	if second.body["reason"] != "second" {
		t.Errorf("second answer = %v, want reason second", second.body)
	}
	select {
	case got := <-first:
		t.Fatalf("first answered before release: %v", got.body)
	default:
	}
	close(release)
	select {
	case got := <-first:
		if got.body["reason"] != "first" {
			t.Errorf("first answer = %v, want reason first", got.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first request not answered")
	}
}

func TestSocketIs600WithoutTouchingTheUmask(t *testing.T) {
	// With an empty umask the socket would be created with mode 0777; the
	// server must narrow it itself, and leave the umask as it found it.
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })
	path := socketPath(t)
	s, err := serve(path, granting, func(map[string]any) {})
	if err != nil {
		t.Fatal(err)
	}
	if now := syscall.Umask(0); now != 0 {
		t.Errorf("umask after serve = %#o, want 0", now)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Type() != os.ModeSocket || info.Mode().Perm() != 0o600 {
		t.Errorf("socket mode = %v, want a socket with 0600", info.Mode())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("socket still there after Close: %v", err)
	}
}

func TestStaleSocketIsReplacedAndALiveOneRefused(t *testing.T) {
	path := socketPath(t)

	// A socket file left behind by a server that is gone.
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	stale.Close()
	live, err := serve(path, granting, func(map[string]any) {})
	if err != nil {
		t.Fatalf("serve over a stale socket: %v", err)
	}
	defer live.Close()

	if _, err := serve(path, granting, func(map[string]any) {}); err == nil {
		t.Fatal("a second server on a live socket started, want an error")
	}
	// The refused second server must leave the first one working.
	if got := exchange(t, path, post(t, capability, 60)); got.body["decision"] != "grant_session" {
		t.Errorf("first server answered %v after the refused start", got.body)
	}
}

func TestServeRefusesAPathThatIsARegularFile(t *testing.T) {
	path := socketPath(t)
	if err := os.WriteFile(path, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := serve(path, granting, func(map[string]any) {}); err == nil {
		t.Fatal("serve over a regular file succeeded")
	}
	if data, _ := os.ReadFile(path); string(data) != "keep me" {
		t.Errorf("file content = %q, want it untouched", data)
	}
}

func TestServeRefusesASocketPathTooLongToBind(t *testing.T) {
	path := filepath.Join(t.TempDir(), strings.Repeat("s", 108))
	if _, err := serve(path, granting, func(map[string]any) {}); err == nil || !strings.Contains(err.Error(), "longer than 107 bytes") {
		t.Errorf("serve = %v, want an error about the path's length", err)
	}
}

func TestEveryServerMadeDenialIsReportedOnce(t *testing.T) {
	big := "POST / HTTP/1.1\r\nHost: localhost\r\nX-Filler: " + strings.Repeat("a", 17*1024) + "\r\nContent-Length: 2\r\n\r\n{}"
	tests := []struct {
		name   string
		data   func(t *testing.T) []byte
		slow   bool // decide never answers
		status int
	}{
		{"invalid JSON", func(*testing.T) []byte { return postBytes([]byte("{not json"), 60) }, false, 400},
		{"not an object", func(*testing.T) []byte { return postBytes([]byte(`[1]`), 60) }, false, 400},
		{"request not an object", func(t *testing.T) []byte { return post(t, "capability", 60) }, false, 400},
		{"unreadable request", func(t *testing.T) []byte { return post(t, map[string]any{"capability_type": "capability"}, 60) }, false, 400},
		{"wrong method", func(*testing.T) []byte { return []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n") }, false, 405},
		{"body too large", func(*testing.T) []byte {
			return fmt.Appendf(nil, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\n\r\n", 1024*1024+1)
		}, false, 413},
		{"headers too large", func(*testing.T) []byte { return []byte(big) }, false, 431},
		{"unknown path", func(*testing.T) []byte { return []byte("POST /x HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}") }, false, 404},
		{"chunked body", func(*testing.T) []byte {
			return []byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n")
		}, false, 501},
		{"HTTP/2", func(*testing.T) []byte { return []byte("POST / HTTP/2.0\r\nContent-Length: 2\r\n\r\n{}") }, false, 505},
		{"no length", func(*testing.T) []byte { return []byte("POST / HTTP/1.1\r\nHost: localhost\r\n\r\n{}") }, false, 411},
		{"slow client", func(*testing.T) []byte { return []byte("POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n{}") }, false, 408},
		{"slow decide", func(t *testing.T) []byte { return post(t, capability, 2) }, true, 200},
	}
	saved := receiveTimeout
	receiveTimeout = 300 * time.Millisecond
	t.Cleanup(func() { receiveTimeout = saved })
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			decide := granting
			if tt.slow {
				decide = func(integration.Request) integration.Decision {
					<-release
					return integration.Decision{Decision: "granted"}
				}
			}
			var got reports
			path := serving(t, decide, got.add)
			answer := exchange(t, path, tt.data(t))
			if answer.status != tt.status || answer.body["decision"] != "denied" {
				t.Errorf("answer %d %v, want %d and a denial", answer.status, answer.body, tt.status)
			}
			list := got.all()
			if len(list) != 1 {
				t.Fatalf("reports = %v, want exactly one", list)
			}
			if list[0]["status"] != answer.status || list[0]["reason"] != answer.body["reason"] {
				t.Errorf("report = %v, want status %d and reason %q", list[0], answer.status, answer.body["reason"])
			}
		})
	}
}

func TestReportsSayWhatTheRequestSaidAboutItself(t *testing.T) {
	quietLog(t)
	var got reports
	path := serving(t, func(integration.Request) integration.Decision { panic("boom") }, got.add)
	exchange(t, path, postBytes([]byte("{not json"), 60))
	exchange(t, path, post(t, "capability", 60))
	exchange(t, path, post(t, capability, 60))
	list := got.all()
	if len(list) != 3 {
		t.Fatalf("reports = %v, want three", list)
	}
	if _, ok := list[0]["backend"]; ok {
		t.Errorf("report for invalid JSON names a backend: %v", list[0])
	}
	if list[1]["backend"] != "sup" || list[1]["kind"] != nil {
		t.Errorf("report for a request that is not an object = %v, want backend sup and no kind", list[1])
	}
	want := map[string]any{"backend": "sup", "kind": "path", "request_id": "r1"}
	for k, v := range want {
		if list[2][k] != v {
			t.Errorf("report for a failed decide: %s = %v, want %v", k, list[2][k], v)
		}
	}
}

func TestDecisionsOfDecideAreNotReported(t *testing.T) {
	var got reports
	path := serving(t, func(integration.Request) integration.Decision {
		return integration.Decision{Decision: "denied", Reason: "outside"}
	}, got.add)
	answer := exchange(t, path, post(t, capability, 60))
	if answer.body["reason"] != "outside" {
		t.Errorf("answer = %v, want reason outside", answer.body)
	}
	if list := got.all(); len(list) != 0 {
		t.Errorf("reports = %v, want none", list)
	}
}

func TestPanickingReportKeepsTheAnswer(t *testing.T) {
	quietLog(t)
	path := serving(t, granting, func(map[string]any) { panic("report broke") })
	got := exchange(t, path, postBytes([]byte("{not json"), 60))
	if got.status != 400 || got.body["decision"] != "denied" {
		t.Errorf("got %d %v, want 400 and a denial", got.status, got.body)
	}
	if reason, _ := got.body["reason"].(string); !strings.HasPrefix(reason, "body is not valid JSON") {
		t.Errorf("reason = %q, want it to start with %q", reason, "body is not valid JSON")
	}
}

func TestParseRequestMapsTheRequestTypes(t *testing.T) {
	tests := []struct {
		request map[string]any
		want    integration.Request
	}{
		{capability, integration.Request{Kind: "path", ID: "r1", Path: "/srv/data/x", Access: "Read"}},
		{
			map[string]any{"capability_type": "network", "request_id": "r2", "host": "api.example", "port": 443, "protocol": "tcp", "resolved_ips": []string{"192.0.2.10"}},
			integration.Request{Kind: "network", ID: "r2", Host: "api.example", Port: 443, Addresses: []string{"192.0.2.10"}},
		},
		{map[string]any{"capability_type": "endpoint", "request_id": "r3"}, integration.Request{Kind: "other", ID: "r3", Detail: "endpoint"}},
		{map[string]any{"capability_type": "command", "request_id": "r4"}, integration.Request{Kind: "other", ID: "r4", Detail: "command"}},
		{map[string]any{"capability_type": "unix_socket", "request_id": "r5", "path": 5}, integration.Request{Kind: "other", ID: "r5", Detail: "unix_socket"}},
		{map[string]any{"capability_type": "something_new"}, integration.Request{Kind: "other", Detail: "something_new"}},
	}
	for _, tt := range tests {
		raw, err := json.Marshal(tt.request)
		if err != nil {
			t.Fatal(err)
		}
		got, err := parseRequest(raw)
		if err != nil {
			t.Errorf("parseRequest(%s): %v", raw, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parseRequest(%s) = %+v, want %+v", raw, got, tt.want)
		}
	}
}

func TestParseRequestRefusesWhatItCannotRead(t *testing.T) {
	for _, raw := range []string{
		`null`,
		`[]`,
		`"x"`,
		`{}`,
		`{"capability_type": 5}`,
		`{"capability_type": "capability"}`,
		`{"capability_type": "capability", "path": "/x"}`,
		`{"capability_type": "capability", "path": "/x", "access": "Read", "request_id": 7}`,
		`{"capability_type": "network", "host": "h", "port": "x", "resolved_ips": []}`,
		`{"capability_type": "network", "host": "h", "port": 80, "resolved_ips": [1]}`,
		`{"capability_type": "network", "host": "h", "port": 70000, "resolved_ips": []}`,
		`{"capability_type": "network", "host": "h", "port": 80}`,
		`{"capability_type": "network", "port": 80, "resolved_ips": []}`,
		`{"capability_type": "network", "host": "h", "port": 53, "protocol": "udp", "resolved_ips": []}`,
		`{"capability_type": "network", "host": "h", "port": 53, "protocol": 6, "resolved_ips": []}`,
	} {
		if got, err := parseRequest(json.RawMessage(raw)); err == nil {
			t.Errorf("parseRequest(%s) = %+v, want an error", raw, got)
		}
	}
}

// Request bodies as nono 0.82 sends them.
const (
	toolFileRequest    = `{"capability_type":"capability","request_id":"seccomp-18eb49333da944fc-0","path":"/proc/sys/crypto/fips_enabled","access":"Read","reason":"Sandbox intercepted file operation (seccomp-notify)","child_pid":49407,"session_id":"a4dbc8095a4031e7"}`
	toolNetworkRequest = `{"capability_type":"network","request_id":"4cc5a503-939c-4f6f-bf2d-b0aea3a28a53","host":"example.com","port":443,"protocol":"tcp","resolved_ips":[],"reason":null,"child_pid":0,"session_id":"a4dbc8095a4031e7"}`
)

func TestParseRequestReadsTheToolsOwnBodies(t *testing.T) {
	got, err := parseRequest(json.RawMessage(toolFileRequest))
	want := integration.Request{Kind: "path", ID: "seccomp-18eb49333da944fc-0", Path: "/proc/sys/crypto/fips_enabled", Access: "Read"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("file request: parseRequest = %+v, %v; want %+v", got, err, want)
	}
	// A host asked about through the sandbox's proxy comes without the
	// addresses it resolves to, so it can only be denied.
	got, err = parseRequest(json.RawMessage(toolNetworkRequest))
	want = integration.Request{Kind: "network", ID: "4cc5a503-939c-4f6f-bf2d-b0aea3a28a53", Host: "example.com", Port: 443, Addresses: []string{}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("network request: parseRequest = %+v, %v; want %+v", got, err, want)
	}
}

func TestRequestThatEndsEarlyIsAReportedDenial(t *testing.T) {
	for name, data := range map[string]string{
		"body cut short":    "POST / HTTP/1.1\r\nContent-Length: 20\r\n\r\n{\"backend\"",
		"headers cut short": "POST / HTTP/1.1\r\nContent-Length: 2\r\n",
		// A first line without a line end that fills the read buffer
		// exactly must not pass for a connection that sent nothing.
		"4096 bytes, no line end":  strings.Repeat("x", 4096),
		"8192 bytes, no line end":  "POST /" + strings.Repeat("a", 8186),
		"12288 bytes, no line end": strings.Repeat("x", 12288),
	} {
		t.Run(name, func(t *testing.T) {
			var got reports
			path := serving(t, granting, got.add)
			conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			// The client sends part of a request and says it will send no more.
			if _, err := conn.Write([]byte(data)); err != nil {
				t.Fatal(err)
			}
			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("no answer: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != 400 {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
			if list := got.all(); len(list) != 1 || list[0]["status"] != 400 {
				t.Errorf("reports = %v, want one with status 400", list)
			}
		})
	}
}

func TestEmptyConnectionIsNotReported(t *testing.T) {
	var got reports
	path := serving(t, granting, got.add)
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	time.Sleep(200 * time.Millisecond)
	if list := got.all(); len(list) != 0 {
		t.Errorf("reports = %v, want none for a connection that sent nothing", list)
	}
}

func TestRefusedSecondServerLeavesNoReport(t *testing.T) {
	var got reports
	path := serving(t, granting, got.add)
	if _, err := serve(path, granting, func(map[string]any) {}); err == nil {
		t.Fatal("a second server on a live socket started")
	}
	time.Sleep(200 * time.Millisecond)
	if list := got.all(); len(list) != 0 {
		t.Errorf("the live server reported %v after the probe, want nothing", list)
	}
}

func TestReportKeepsTheRequestIDOfARequestWithoutAType(t *testing.T) {
	for _, request := range []map[string]any{
		{"request_id": "r9"},
		{"capability_type": nil, "request_id": "r9"},
		{"capability_type": 5, "request_id": "r9"},
		{"capability_type": map[string]any{}, "request_id": "r9"},
	} {
		var got reports
		path := serving(t, granting, got.add)
		exchange(t, path, post(t, request, 60))
		if list := got.all(); len(list) != 1 || list[0]["request_id"] != "r9" {
			t.Errorf("request %v: reports = %v, want one with request_id r9", request, list)
		}
	}
}

func TestHandlerBudgetTakesOnlyAPlausibleTimeout(t *testing.T) {
	tests := []struct {
		header string
		want   time.Duration
	}{
		{"", 58 * time.Second},
		{"30", 28 * time.Second},
		{"1", 0},
		{"3600", 3598 * time.Second},
		{"3601", 58 * time.Second},
		{"0", 58 * time.Second},
		{"1000000", 58 * time.Second},
		{"-5", 58 * time.Second},
	}
	for _, tt := range tests {
		if got := handlerBudget(tt.header); got != tt.want {
			t.Errorf("handlerBudget(%q) = %v, want %v", tt.header, got, tt.want)
		}
	}
}
