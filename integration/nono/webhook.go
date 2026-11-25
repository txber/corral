// The approval endpoint: a server for nono's approval webhook protocol on a
// Unix socket.
//
// nono sends one blocking HTTP/1.1 "POST /" per permission request, with
// the body {"backend": <name>, "request": {...}} and the header
// X-Nono-Timeout-Secs. The answer is status 200 with
// {"decision": ..., "reason": ...}. nono counts anything else as a denial;
// the server still puts a denial in every error body so that the reason
// shows up in nono's log, and reports every denial it makes itself.

package nono

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/txber/corral/integration"
)

// Limits on one request.
const (
	maxHeaderBytes     = 16 << 10
	maxBodyBytes       = 1 << 20
	defaultTimeoutSecs = 60 // when the request does not say how long nono waits
	timeoutMarginSecs  = 2  // answer this long before nono gives up
	writeTimeout       = 5 * time.Second
)

// receiveTimeout is how long a client may take to send its request. It is
// a variable so that tests can shorten it.
var receiveTimeout = 10 * time.Second

// server answers permission requests on a Unix socket.
type server struct {
	path     string
	listener *net.UnixListener
	socket   os.FileInfo // the socket file as bound, to remove only that one
	decide   func(integration.Request) integration.Decision
	report   func(map[string]any)
	sent     func(integration.Request, integration.Decision) // may be nil
	done     chan struct{}                                   // closed by Close

	mu     sync.Mutex
	conns  map[net.Conn]bool
	closed bool
	wg     sync.WaitGroup // the accept loop and one per connection
}

// serve starts answering requests on socketPath with decide. report
// receives every denial the server makes without decide: a malformed,
// oversized or incomplete request, a decide that panics or misses its
// deadline. Each report has "status" and "reason" as sent, plus "backend",
// "kind" and "request_id" when the body was read far enough to know them.
// decide and report may be called from several goroutines at once.
//
// The socket file gets mode 600. A stale socket file is replaced; a socket
// that a server still answers on, and anything that is not a socket, is
// refused.
func serve(socketPath string, decide func(integration.Request) integration.Decision, report func(map[string]any)) (*server, error) {
	return serveWithSent(socketPath, decide, report, nil)
}

// serveWithSent is serve that also calls sent with each decision of decide
// once its answer has been written to the client, so that a record of it
// never shows an answer the sandbox did not get. sent may be nil.
func serveWithSent(socketPath string, decide func(integration.Request) integration.Decision, report func(map[string]any), sent func(integration.Request, integration.Decision)) (*server, error) {
	if err := removeStale(socketPath); err != nil {
		return nil, err
	}
	listener, err := listenUnix(socketPath)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(socketPath)
	if err != nil {
		listener.Close()
		return nil, err
	}
	s := &server{
		path:     socketPath,
		listener: listener,
		socket:   info,
		decide:   decide,
		report:   report,
		sent:     sent,
		done:     make(chan struct{}),
		conns:    map[net.Conn]bool{},
	}
	s.wg.Go(s.acceptLoop)
	return s, nil
}

// removeStale removes a socket file that no server answers on. It does
// not wait for a busy server: any answer other than "refused" counts as a
// live server.
func removeStale(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("%s exists and is not a socket", path)
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		conn.Close()
		return fmt.Errorf("%s is in use by a running server", path)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("%s may be in use: %w", path, err)
	}
	return os.Remove(path)
}

// listenUnix binds a socket at path, gives it mode 600 and only then
// listens. Until listen, every connection to the bound socket is refused,
// so nobody can connect while the mode is still the one the umask gave
// it, and the process umask is left alone.
func listenUnix(path string) (*net.UnixListener, error) {
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("socket path %q is longer than %d bytes", path, maxSocketPath)
	}
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close() // net.FileListener works on its own copy
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		return nil, &os.PathError{Op: "bind", Path: path, Err: err}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		os.Remove(path)
		return nil, err
	}
	if err := syscall.Listen(fd, 64); err != nil {
		os.Remove(path)
		return nil, &os.PathError{Op: "listen", Path: path, Err: err}
	}
	listener, err := net.FileListener(file)
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	return listener.(*net.UnixListener), nil
}

// Close stops serving, drops requests still in progress and removes the
// socket file. It does not wait for a decide call that is still running.
func (s *server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.done)
	for conn := range s.conns {
		conn.Close()
	}
	s.mu.Unlock()
	err := s.listener.Close()
	s.wg.Wait()
	// Remove the file only if it is still the socket this server bound.
	if info, statErr := os.Lstat(s.path); statErr == nil && os.SameFile(info, s.socket) {
		if rmErr := os.Remove(s.path); err == nil {
			err = rmErr
		}
	}
	return err
}

func (s *server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			// Such as too many open files: wait for some to close.
			time.Sleep(100 * time.Millisecond)
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			return
		}
		s.conns[conn] = true
		s.wg.Go(func() {
			s.handle(conn)
			s.mu.Lock()
			delete(s.conns, conn)
			s.mu.Unlock()
		})
		s.mu.Unlock()
	}
}

// rejection ends a request early with an HTTP status and a denial.
type rejection struct {
	status  int
	reason  string
	context map[string]any // backend, kind and request_id, when known
}

func (r *rejection) Error() string { return r.reason }

func reject(status int, format string, args ...any) *rejection {
	return &rejection{status: status, reason: fmt.Sprintf(format, args...)}
}

// handle answers the first request on conn and closes it. Anything the
// client sends after that request, such as a second one, is not read.
func (s *server) handle(conn net.Conn) {
	defer conn.Close()
	request, decision, err := s.answer(conn)
	status, extra := http.StatusOK, ""
	if err != nil {
		var r *rejection
		if !errors.As(err, &r) {
			return // the client went away or the server is closing: nobody to answer
		}
		status = r.status
		decision = integration.Decision{Decision: "denied", Reason: r.reason}
		if status == http.StatusMethodNotAllowed {
			extra = "Allow: POST\r\n"
		}
		s.reportDenial(r)
	}
	body, _ := json.Marshal(struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}{decision.Decision, decision.Reason})
	head := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n%s\r\n",
		status, http.StatusText(status), len(body), extra)
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, writeErr := conn.Write(append([]byte(head), body...))
	if err == nil && writeErr == nil && s.sent != nil {
		s.sent(request, decision)
	}
}

// reportDenial passes a denial to report. A report that panics loses its
// record but not the answer.
func (s *server) reportDenial(r *rejection) {
	defer func() {
		if p := recover(); p != nil {
			log.Printf("approval endpoint: report panicked: %v\n%s", p, debug.Stack())
		}
	}()
	record := map[string]any{"status": r.status, "reason": r.reason}
	for k, v := range r.context {
		record[k] = v
	}
	s.report(record)
}

// answer reads one request from conn and decides it. An error that is not
// a *rejection means there is nobody to answer: the client closed the
// connection without sending anything, or the server is closing.
func (s *server) answer(conn net.Conn) (integration.Request, integration.Decision, error) {
	var none integration.Decision
	var nothing integration.Request
	_ = conn.SetReadDeadline(time.Now().Add(receiveTimeout))
	limited := &io.LimitedReader{R: conn, N: maxHeaderBytes}
	req, err := http.ReadRequest(bufio.NewReader(limited))
	if err != nil {
		if limited.N == 0 && !isTimeout(err) {
			return nothing, none, reject(http.StatusRequestHeaderFieldsTooLarge, "headers larger than %d bytes", maxHeaderBytes)
		}
		return nothing, none, readError(err)
	}
	if err := checkRequest(req); err != nil {
		return nothing, none, err
	}
	// The body follows the headers; checkRequest has bounded its length.
	limited.N = maxBodyBytes
	body := make([]byte, req.ContentLength)
	if _, err := io.ReadFull(req.Body, body); err != nil {
		return nothing, none, readError(err)
	}
	request, context, err := parseBody(body)
	if err != nil {
		return nothing, none, err
	}
	budget := handlerBudget(req.Header.Get("X-Nono-Timeout-Secs"))
	decision, err := s.decideWithin(request, budget, context)
	return request, decision, err
}

func isTimeout(err error) bool { return errors.Is(err, os.ErrDeadlineExceeded) }

// readError turns a failed read into a rejection: a request that is late,
// incomplete or malformed is a reported denial. Only a read cut off by
// Close is a plain error.
func readError(err error) error {
	switch {
	case isTimeout(err):
		return reject(http.StatusRequestTimeout, "request not received within %v", receiveTimeout)
	case errors.Is(err, net.ErrClosed):
		return err
	}
	return reject(http.StatusBadRequest, "incomplete or malformed request: %.200v", err)
}

// checkRequest accepts only what nono sends: POST / over HTTP/1 with a
// plain Content-Length of at most maxBodyBytes.
func checkRequest(req *http.Request) error {
	switch {
	case req.ProtoMajor != 1:
		return reject(http.StatusHTTPVersionNotSupported, "unsupported HTTP version %.20q", req.Proto)
	case req.Method != http.MethodPost:
		return reject(http.StatusMethodNotAllowed, "method %.20q is not allowed", req.Method)
	case req.RequestURI != "/":
		return reject(http.StatusNotFound, "no endpoint at %.200q", req.RequestURI)
	case len(req.TransferEncoding) > 0:
		return reject(http.StatusNotImplemented, "transfer encodings are not supported")
	case req.Header.Get("Content-Length") == "":
		return reject(http.StatusLengthRequired, "Content-Length is required")
	case req.ContentLength > maxBodyBytes:
		return reject(http.StatusRequestEntityTooLarge, "body larger than %d bytes", maxBodyBytes)
	}
	return nil
}

// parseBody reads {"backend": ..., "request": {...}}. It also returns what
// the body says about itself, for the report of a later denial.
func parseBody(body []byte) (integration.Request, map[string]any, error) {
	if !json.Valid(body) {
		return integration.Request{}, nil, reject(http.StatusBadRequest, "body is not valid JSON")
	}
	var message map[string]json.RawMessage
	if err := json.Unmarshal(body, &message); err != nil || message == nil {
		return integration.Request{}, nil, reject(http.StatusBadRequest, "body is not a JSON object")
	}
	context := map[string]any{}
	var backend *string
	if json.Unmarshal(message["backend"], &backend) == nil && backend != nil {
		context["backend"] = *backend
	}
	var about struct {
		Type *string `json:"capability_type"`
		ID   *string `json:"request_id"`
	}
	if json.Unmarshal(message["request"], &about) == nil {
		if about.Type != nil {
			context["kind"] = kindOf(*about.Type)
		}
		if about.ID != nil {
			context["request_id"] = *about.ID
		}
	}
	fail := func(format string, args ...any) (integration.Request, map[string]any, error) {
		r := reject(http.StatusBadRequest, format, args...)
		r.context = context
		return integration.Request{}, context, r
	}
	if _, ok := context["backend"]; !ok {
		return fail("'backend' is not a string")
	}
	request, err := parseRequest(message["request"])
	if err != nil {
		return fail("%.300v", err)
	}
	return request, context, nil
}

// kindOf is corral's kind for one of nono's request types.
func kindOf(capabilityType string) string {
	switch capabilityType {
	case "capability":
		return "path"
	case "network":
		return "network"
	}
	return "other"
}

// parseRequest turns nono's request object into corral's request. A file
// request ("capability") needs path and access, a network request needs
// host, port and the addresses nono resolved; every other type becomes
// "other" with the type as its detail.
func parseRequest(raw json.RawMessage) (integration.Request, error) {
	var fields struct {
		Path        *string   `json:"path"`
		Access      *string   `json:"access"`
		Host        *string   `json:"host"`
		Port        *int      `json:"port"`
		Protocol    *string   `json:"protocol"`
		ResolvedIPs *[]string `json:"resolved_ips"`
	}
	var head struct {
		Type *string `json:"capability_type"`
		ID   *string `json:"request_id"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return integration.Request{}, fmt.Errorf("request: %w", err)
	}
	if head.Type == nil {
		return integration.Request{}, errors.New("request is not an object with a capability_type")
	}
	r := integration.Request{Kind: kindOf(*head.Type)}
	if head.ID != nil {
		r.ID = *head.ID
	}
	switch r.Kind {
	case "other":
		r.Detail = fmt.Sprintf("%.100s", *head.Type)
		return r, nil
	case "path":
		if err := json.Unmarshal(raw, &fields); err != nil {
			return integration.Request{}, fmt.Errorf("file request: %w", err)
		}
		if fields.Path == nil || fields.Access == nil {
			return integration.Request{}, errors.New("file request needs the strings path and access")
		}
		r.Path, r.Access = *fields.Path, *fields.Access
	case "network":
		if err := json.Unmarshal(raw, &fields); err != nil {
			return integration.Request{}, fmt.Errorf("network request: %w", err)
		}
		if fields.Host == nil || fields.Port == nil || fields.ResolvedIPs == nil {
			return integration.Request{}, errors.New("network request needs host, port and resolved_ips")
		}
		// The scope is checked for tcp; nono's proxy only asks about tcp.
		if fields.Protocol != nil && *fields.Protocol != "tcp" {
			return integration.Request{}, fmt.Errorf("network request protocol %.20q is not tcp", *fields.Protocol)
		}
		if *fields.Port < 1 || *fields.Port > 65535 {
			return integration.Request{}, fmt.Errorf("network request port %d is out of range", *fields.Port)
		}
		r.Host, r.Port, r.Addresses = *fields.Host, *fields.Port, *fields.ResolvedIPs
	}
	return r, nil
}

// handlerBudget is how long decide may take: nono's patience as the header
// gives it, minus a margin, so that the answer arrives before nono stops
// waiting.
func handlerBudget(header string) time.Duration {
	seconds := defaultTimeoutSecs
	if isDigits(header) && len(header) <= 6 {
		seconds, _ = strconv.Atoi(header)
	}
	return time.Duration(max(0, seconds-timeoutMarginSecs)) * time.Second
}

func isDigits(text string) bool {
	if text == "" {
		return false
	}
	for _, c := range text {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// decideWithin runs decide and gives up after budget. A decide call that
// is still running when the answer is sent goes on in the background.
func (s *server) decideWithin(request integration.Request, budget time.Duration, context map[string]any) (integration.Decision, error) {
	type outcome struct {
		decision integration.Decision
		ok       bool
	}
	done := make(chan outcome, 1) // buffered: a late decide must not block
	go func() {
		var o outcome
		defer func() {
			if p := recover(); p != nil {
				log.Printf("approval endpoint: decide panicked: %v\n%s", p, debug.Stack())
			}
			done <- o
		}()
		o.decision = s.decide(request)
		o.ok = true
	}()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	var r *rejection
	select {
	case o := <-done:
		if o.ok {
			return o.decision, nil
		}
		r = reject(http.StatusOK, "approval handler failed")
	case <-timer.C:
		r = reject(http.StatusOK, "no decision within %v", budget)
	case <-s.done:
		return integration.Decision{}, net.ErrClosed
	}
	r.context = context
	return integration.Decision{}, r
}
