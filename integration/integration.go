// Package integration is the interface between corral and the tools it
// drives. A tool is added by a Go package that implements one of the three
// interfaces below (Sandbox, KeyProxy or Runtime) and registers a factory for
// it under a name in an init function; corral links the package in and
// builds the tool by the name its configuration gives.
package integration

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
)

// Request is one permission request, in corral's terms.
type Request struct {
	Kind      string // "path", "network" or "other"
	ID        string
	Path      string
	Access    string
	Host      string
	Port      int
	Addresses []string
	Detail    string // for "other": what was asked, for the log
}

// Decision is the answer to one Request.
type Decision struct {
	Decision string // "granted", "denied", "grant_session" or "deny_session"
	Reason   string
}

// Endpoint is one HTTP method and path that the model gateway serves.
type Endpoint struct{ Method, Path string }

// Gateway is where models are reached.
type Gateway struct {
	Name      string
	Upstream  string
	Endpoints []Endpoint
	KeyFile   string
}

// Cost is the price of a model in USD per million tokens.
type Cost struct{ Input, Output, CacheRead, CacheWrite float64 }

// Limits are the resource limits of one agent.
type Limits struct {
	Memory       string // for example "2G"; empty: no limit
	MaxProcesses int    // 0: no limit
}

// Agent is everything an integration may know about one agent.
type Agent struct {
	ID, Role     string
	Network      string // "direct", "proxy" or "none"
	Model        string
	Options      map[string]any // the role's free-form options, meant for the runtime
	Cost         Cost
	Workdir      string // the only folder the agent may write
	StateDir     string // private to the supervisor; integrations put generated files here
	Limits       Limits
	Deny         []string // folders the agent must never read
	Gateway      Gateway  // the model gateway this agent uses
	ProxyPort    int      // the port reserved for this agent's key proxy
	GatewayURL   string   // the address the agent uses for the model gateway
	GatewayToken string   // the stand-in credential for that address; never on a command line; empty in mode "none"
}

// TokenEnv is the environment variable in which an agent program finds the
// stand-in credential for GatewayURL, whoever put it there.
const TokenEnv = "CORRAL_GATEWAY_TOKEN"

// Usage is the token count and cost that one Record reports.
type Usage struct {
	Input, Output, CacheRead, CacheWrite int64
	Cost                                 float64
}

// Record is one line of a runtime's output, in corral's terms.
type Record struct {
	Kind   string // "event", "response", "settled" or "garbage"
	Type   string // event type for the log
	Fields map[string]any
	ID     string // for a response: the id passed to Encode
	OK     bool
	Usage  *Usage // tokens and cost, when the record carries them
}

// Network modes, and who does what:
//   "direct"  The network is confined from outside (namespace and firewall), so the
//             sandbox must not restrict it. A KeyProxy serves the gateway at
//             GatewayURL; the runtime passes GatewayToken on in TokenEnv.
//   "none"    The sandbox itself confines the agent to the model gateway and injects
//             the key: it serves the gateway inside the sandbox at
//             http://127.0.0.1:<ProxyPort>/<Gateway.Name>, which is GatewayURL, and sets
//             TokenEnv for the agent program. No KeyProxy is used and GatewayToken is empty.

// Sandbox confines one agent process.
type Sandbox interface {
	Prepare(a Agent, readPaths []string) error
	Wrap(a Agent, command []string) []string
	// Approvals serves the sandbox's own run-time permission requests until stop is
	// called: decide answers each, report receives every denial the integration
	// makes itself. It returns a nil stop if the sandbox has no such requests.
	Approvals(a Agent, decide func(Request) Decision, report func(map[string]any)) (stop func() error, err error)
	StopCommand(a Agent) []string // a command that ends the sandbox by force, or nil
	AuditPath(a Agent) string     // where the sandbox keeps its own record of the run, or ""
}

// KeyProxy lets an agent use the gateway without holding the key.
type KeyProxy interface {
	Prepare(a Agent, g Gateway, listen netip.AddrPort) error
	Command(a Agent, g Gateway, listen netip.AddrPort) (argv, env []string)
	URL(g Gateway, listen netip.AddrPort) string
}

// Runtime runs one agent program and speaks its control protocol.
type Runtime interface {
	Prepare(a Agent) error
	Command(a Agent) []string
	Env(a Agent) []string
	ReadPaths() []string
	Encode(op, id string, args map[string]any) ([]byte, error) // "prompt", "steer", "follow_up", "abort", "exec", "stats"
	Decode(line []byte) *Record                                // nil: nothing to record
}

// ErrUnsupported is returned by Runtime.Encode for an operation the agent
// program does not offer.
var ErrUnsupported = errors.New("operation not supported by this runtime")

// The registry: one factory per name and kind, filled by init functions.
var (
	mu         sync.Mutex
	sandboxes  = map[string]func(options map[string]any) (Sandbox, error){}
	keyProxies = map[string]func(options map[string]any) (KeyProxy, error){}
	runtimes   = map[string]func(options map[string]any) (Runtime, error){}
)

// RegisterSandbox makes a sandbox available under name. It panics if the
// name is already taken or factory is nil.
func RegisterSandbox(name string, factory func(options map[string]any) (Sandbox, error)) {
	mu.Lock()
	defer mu.Unlock()
	if _, taken := sandboxes[name]; taken || factory == nil {
		panic(fmt.Sprintf("integration: RegisterSandbox %q twice or with a nil factory", name))
	}
	sandboxes[name] = factory
}

// RegisterKeyProxy makes a key proxy available under name. It panics if the
// name is already taken or factory is nil.
func RegisterKeyProxy(name string, factory func(options map[string]any) (KeyProxy, error)) {
	mu.Lock()
	defer mu.Unlock()
	if _, taken := keyProxies[name]; taken || factory == nil {
		panic(fmt.Sprintf("integration: RegisterKeyProxy %q twice or with a nil factory", name))
	}
	keyProxies[name] = factory
}

// RegisterRuntime makes a runtime available under name. It panics if the
// name is already taken or factory is nil.
func RegisterRuntime(name string, factory func(options map[string]any) (Runtime, error)) {
	mu.Lock()
	defer mu.Unlock()
	if _, taken := runtimes[name]; taken || factory == nil {
		panic(fmt.Sprintf("integration: RegisterRuntime %q twice or with a nil factory", name))
	}
	runtimes[name] = factory
}

// NewSandbox builds the sandbox registered under name with options.
func NewSandbox(name string, options map[string]any) (Sandbox, error) {
	mu.Lock()
	factory, ok := sandboxes[name]
	known := slices.Sorted(maps.Keys(sandboxes))
	mu.Unlock()
	if !ok {
		return nil, unknown("sandbox", name, known)
	}
	return factory(options)
}

// NewKeyProxy builds the key proxy registered under name with options.
func NewKeyProxy(name string, options map[string]any) (KeyProxy, error) {
	mu.Lock()
	factory, ok := keyProxies[name]
	known := slices.Sorted(maps.Keys(keyProxies))
	mu.Unlock()
	if !ok {
		return nil, unknown("key proxy", name, known)
	}
	return factory(options)
}

// NewRuntime builds the runtime registered under name with options.
func NewRuntime(name string, options map[string]any) (Runtime, error) {
	mu.Lock()
	factory, ok := runtimes[name]
	known := slices.Sorted(maps.Keys(runtimes))
	mu.Unlock()
	if !ok {
		return nil, unknown("runtime", name, known)
	}
	return factory(options)
}

// unknown is the error for a name nobody registered.
func unknown(kind, name string, known []string) error {
	return fmt.Errorf("unknown %s %q (registered: %s)", kind, name, strings.Join(known, ", "))
}
