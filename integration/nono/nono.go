// Package nono drives the sandbox tool nono. It confines an agent with
// `nono run` and a generated profile, serves the model gateway with
// `nono proxy` so that the agent never holds the key, and answers the
// sandbox's run-time permission requests on a Unix socket (webhook.go).
// Both are registered under the name "nono".
package nono

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/txber/corral/integration"
)

func init() {
	integration.RegisterSandbox("nono", func(options map[string]any) (integration.Sandbox, error) {
		binary, err := binaryOption(options)
		if err != nil {
			return nil, err
		}
		return sandbox{binary: binary}, nil
	})
	integration.RegisterKeyProxy("nono", func(options map[string]any) (integration.KeyProxy, error) {
		binary, err := binaryOption(options)
		if err != nil {
			return nil, err
		}
		return keyProxy{binary: binary}, nil
	})
}

// binaryOption reads the one option both integrations take: binary, the
// absolute path of the nono program.
func binaryOption(options map[string]any) (string, error) {
	for _, key := range slices.Sorted(maps.Keys(options)) {
		if key != "binary" {
			return "", fmt.Errorf("nono: unknown option %q", key)
		}
	}
	binary, ok := options["binary"].(string)
	if !ok || !filepath.IsAbs(binary) {
		return "", errors.New("nono: option binary must be the absolute path of the nono program")
	}
	return binary, nil
}

// The files the integration keeps in an agent's state folder.
const (
	sandboxProfileFile = "sandbox.json"
	proxyProfileFile   = "proxy.json"
	approvalSocketFile = "approval.sock"
)

// maxSocketPath is the longest path a Unix socket can be bound at.
const maxSocketPath = 107

// agentID is the form of an agent id the sandbox accepts: it can never be
// read as an option.
var agentID = regexp.MustCompile(`^[a-z][a-z0-9]{0,11}$`)

// sessionName is the name of an agent's nono session. nono stop takes a
// session's exact name or the start of its random hex id; the prefix holds
// letters that are not hex digits, so the name can only ever stop this
// agent's session, never another one whose id happens to start with the
// agent id.
func sessionName(a integration.Agent) string { return "corral-" + a.ID }

// backendName is the name the profiles give the approval endpoint.
const backendName = "corral"

// approvalTimeoutSecs is how long the sandbox waits for an answer. The
// endpoint answers 2 s before that (see webhook.go).
const approvalTimeoutSecs = 30

// profile is the part of nono's profile format that corral writes.
type profile struct {
	Extends    string             `json:"extends"`
	Linux      *linuxSection      `json:"linux,omitempty"`
	Security   *securitySection   `json:"security,omitempty"`
	Filesystem *filesystemSection `json:"filesystem,omitempty"`
	Network    *networkSection    `json:"network,omitempty"`
}

type linuxSection struct {
	// "pathname": the agent may connect to a Unix socket only if it is
	// granted or approved, so it cannot reach other programs' sockets.
	AfUnixMediation string `json:"af_unix_mediation"`
}

type securitySection struct {
	CapabilityElevation bool                       `json:"capability_elevation"`
	ApprovalBackends    map[string]approvalBackend `json:"approval_backends"`
	ApprovalDefaults    approvalDefaults           `json:"approval_defaults"`
}

type approvalBackend struct {
	Type        string `json:"type"`
	URL         string `json:"url"`
	TimeoutSecs int    `json:"timeout_secs"`
}

type approvalDefaults struct {
	Backend string `json:"backend"`
}

type filesystemSection struct {
	Read []string `json:"read,omitempty"`
	Deny []string `json:"deny,omitempty"`
}

type networkSection struct {
	AllowDomain       []allowedDomain            `json:"allow_domain"`
	Credentials       []string                   `json:"credentials"`
	CustomCredentials map[string]credentialRoute `json:"custom_credentials"`
	ApprovalBackends  map[string]approvalBackend `json:"approval_backends,omitempty"`
	ApprovalDefaults  *approvalDefaults          `json:"approval_defaults,omitempty"`
}

type allowedDomain struct {
	Domain    string         `json:"domain"`
	Endpoints []endpointRule `json:"endpoints"`
}

type endpointRule struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// credentialRoute is a route on nono's reverse proxy: requests to
// /<route name>/... go to upstream with the key added, and the program in
// the sandbox only ever sees a stand-in token in env_var.
type credentialRoute struct {
	Upstream         string         `json:"upstream"`
	CredentialKey    string         `json:"credential_key"`
	EnvVar           string         `json:"env_var"`
	InjectHeader     string         `json:"inject_header"`
	CredentialFormat string         `json:"credential_format"`
	EndpointRules    []endpointRule `json:"endpoint_rules"`
}

// sandbox runs an agent under `nono run`.
type sandbox struct{ binary string }

// Prepare writes the agent's profile to <StateDir>/sandbox.json.
func (s sandbox) Prepare(a integration.Agent, readPaths []string) error {
	p, err := sandboxProfile(a, readPaths)
	if err != nil {
		return err
	}
	return writeJSON(filepath.Join(a.StateDir, sandboxProfileFile), p)
}

// sandboxProfile is the profile for one agent. File requests outside it
// go to the approval endpoint on the agent's socket. In network mode
// "none" the sandbox also serves the gateway and asks the same endpoint
// about every other host; in mode "direct" the network is confined from
// outside and the profile says nothing about it. Any other mode is
// refused, because the profile alone would leave the network open.
func sandboxProfile(a integration.Agent, readPaths []string) (profile, error) {
	if a.Network != "none" && a.Network != "direct" {
		return profile{}, fmt.Errorf("nono: network mode %q is not supported, only \"none\" and \"direct\"", a.Network)
	}
	// The id is an argument of its own on the stop command line.
	if !agentID.MatchString(a.ID) {
		return profile{}, fmt.Errorf("nono: agent id %q must match %s", a.ID, agentID)
	}
	fields := []textField{
		{"working folder", a.Workdir},
		{"state folder", a.StateDir},
		{"share folder", a.ShareDir},
		{"memory limit", a.Limits.Memory},
	}
	for _, p := range a.Deny {
		fields = append(fields, textField{"deny path", p})
	}
	for _, p := range readPaths {
		fields = append(fields, textField{"read path", p})
	}
	if err := checkText(fields); err != nil {
		return profile{}, err
	}
	if !filepath.IsAbs(a.StateDir) {
		return profile{}, fmt.Errorf("nono: state folder %q is not absolute", a.StateDir)
	}
	socket := filepath.Join(a.StateDir, approvalSocketFile)
	if len(socket) > maxSocketPath {
		return profile{}, fmt.Errorf("nono: approval socket path %q is longer than %d bytes", socket, maxSocketPath)
	}
	approvals := map[string]approvalBackend{backendName: {
		Type:        "webhook",
		URL:         "unix://" + socket,
		TimeoutSecs: approvalTimeoutSecs,
	}}
	p := profile{
		Extends: "default",
		Linux:   &linuxSection{AfUnixMediation: "pathname"},
		Security: &securitySection{
			CapabilityElevation: true,
			ApprovalBackends:    approvals,
			ApprovalDefaults:    approvalDefaults{Backend: backendName},
		},
		Filesystem: &filesystemSection{Read: readPaths, Deny: a.Deny},
	}
	if a.Network == "direct" {
		return p, nil
	}
	if a.ProxyPort < 1 || a.ProxyPort > 65535 {
		return profile{}, fmt.Errorf("nono: network mode none needs a proxy port, got %d", a.ProxyPort)
	}
	network, err := gatewayNetwork(a.Gateway, integration.TokenEnv)
	if err != nil {
		return profile{}, err
	}
	network.ApprovalBackends = approvals
	network.ApprovalDefaults = &approvalDefaults{Backend: backendName}
	p.Network = &network
	return p, nil
}

// gatewayNetwork allows the gateway and nothing else, and routes it with
// the key from the gateway's key file; envVar names the variable that
// holds the stand-in token.
func gatewayNetwork(g integration.Gateway, envVar string) (networkSection, error) {
	fields := []textField{
		{"gateway name", g.Name},
		{"gateway upstream", g.Upstream},
		{"gateway key file", g.KeyFile},
	}
	for _, e := range g.Endpoints {
		fields = append(fields, textField{"gateway endpoint method", e.Method}, textField{"gateway endpoint path", e.Path})
	}
	if err := checkText(fields); err != nil {
		return networkSection{}, err
	}
	upstream, err := url.Parse(g.Upstream)
	if err != nil || upstream.Hostname() == "" {
		return networkSection{}, fmt.Errorf("nono: gateway upstream %q has no host", g.Upstream)
	}
	if !filepath.IsAbs(g.KeyFile) {
		return networkSection{}, fmt.Errorf("nono: gateway key file %q is not absolute", g.KeyFile)
	}
	// nono checks a routed request against both lists with the path below
	// the route (/<name>/models is checked as /models), so both take the
	// endpoints as configured. allow_domain must not be left out: without an
	// allowlist, nono proxy forwards to any host.
	var rules []endpointRule
	for _, e := range g.Endpoints {
		rules = append(rules, endpointRule{Method: e.Method, Path: e.Path})
	}
	return networkSection{
		AllowDomain: []allowedDomain{{Domain: upstream.Hostname(), Endpoints: rules}},
		Credentials: []string{g.Name},
		CustomCredentials: map[string]credentialRoute{g.Name: {
			Upstream:         g.Upstream,
			CredentialKey:    "file://" + g.KeyFile,
			EnvVar:           envVar,
			InjectHeader:     "Authorization",
			CredentialFormat: "Bearer {}",
			EndpointRules:    rules,
		}},
	}, nil
}

// Wrap returns the command line that runs command in the sandbox. Every
// value is joined to its option with "=", so that a value starting with
// "-" cannot be read as another option.
func (s sandbox) Wrap(a integration.Agent, command []string) []string {
	argv := []string{s.binary, "run", "--silent"}
	switch a.Network {
	case "direct":
		// The agent's namespace and firewall confine the network; nono's
		// own TCP lock would block the addresses the agent was given.
		argv = append(argv, "--sandbox-policy=external")
	case "none":
	default:
		// Prepare refuses this mode first; should the command still be run,
		// it gets no network at all rather than an open one.
		argv = append(argv, "--block-net")
	}
	argv = append(argv,
		"--name="+sessionName(a),
		"--profile="+filepath.Join(a.StateDir, sandboxProfileFile),
		"--allow="+a.Workdir,
	)
	if a.Limits.Memory != "" {
		argv = append(argv, "--memory="+a.Limits.Memory)
	}
	if a.Limits.MaxProcesses > 0 {
		argv = append(argv, "--max-processes="+strconv.Itoa(a.Limits.MaxProcesses))
	}
	if a.Network == "none" {
		// The gateway is served at http://127.0.0.1:<ProxyPort>/<name>.
		argv = append(argv, "--proxy-port="+strconv.Itoa(a.ProxyPort))
	}
	argv = append(argv, "--")
	return append(argv, command...)
}

// Approvals answers the sandbox's requests on <StateDir>/approval.sock.
func (s sandbox) Approvals(a integration.Agent, decide func(integration.Request) integration.Decision, report func(map[string]any)) (func() error, error) {
	srv, err := serve(filepath.Join(a.StateDir, approvalSocketFile), decide, report)
	if err != nil {
		return nil, err
	}
	return srv.Close, nil
}

// StopCommand ends the agent's sandbox session by its name (see
// sessionName), which starts with a letter and so cannot be read as an
// option. The supervisor allows the stop command 5 s; a grace of 3 s keeps
// nono's own escalation to SIGKILL inside that.
func (s sandbox) StopCommand(a integration.Agent) []string {
	return []string{s.binary, "stop", "--timeout=3", sessionName(a)}
}

// AuditPath is empty: nono keeps a session's audit record in a folder
// named after a session id it picks itself, not after the name given with
// --name, so the path is not known from the agent.
func (s sandbox) AuditPath(integration.Agent) string { return "" }

// keyProxy serves the gateway with `nono proxy`.
type keyProxy struct{ binary string }

// Prepare writes the proxy's profile to <StateDir>/proxy.json. The proxy
// serves only network mode "direct": in mode "none" the sandbox serves the
// gateway itself.
func (k keyProxy) Prepare(a integration.Agent, g integration.Gateway, _ netip.AddrPort) error {
	if a.Network != "direct" {
		return fmt.Errorf("nono: the key proxy serves only network mode \"direct\", not %q", a.Network)
	}
	// The profile's path goes on the proxy's command line.
	if err := checkText([]textField{{"state folder", a.StateDir}}); err != nil {
		return err
	}
	p, err := proxyProfile(g)
	if err != nil {
		return err
	}
	return writeJSON(filepath.Join(a.StateDir, proxyProfileFile), p)
}

// proxyProfile allows the gateway and nothing else.
func proxyProfile(g integration.Gateway) (profile, error) {
	network, err := gatewayNetwork(g, strings.ToUpper(g.Name)+"_API_KEY")
	if err != nil {
		return profile{}, err
	}
	return profile{Extends: "default", Network: &network}, nil
}

// Command starts the proxy on listen. The stand-in token the agent must
// present goes into the environment, never into the arguments; the other
// values are joined to their options with "=", as in Wrap.
func (k keyProxy) Command(a integration.Agent, g integration.Gateway, listen netip.AddrPort) (argv, env []string) {
	argv = []string{
		k.binary, "proxy",
		"--listen=" + listen.Addr().String(),
		"--port=" + strconv.Itoa(int(listen.Port())),
		"--profile=" + filepath.Join(a.StateDir, proxyProfileFile),
	}
	return argv, []string{"NONO_PROXY_PASS=" + a.GatewayToken}
}

// URL is where the agent reaches the gateway through the proxy.
func (k keyProxy) URL(g integration.Gateway, listen netip.AddrPort) string {
	return "http://" + listen.String() + "/" + g.Name
}

// textField is a value the integration writes into a profile or puts on a
// command line, with the name an error gives it.
type textField struct{ name, value string }

// checkText refuses a value that is not valid UTF-8 or holds a control
// character. JSON writes an invalid byte as U+FFFD, so a folder to deny
// would become a folder that does not exist while the real one stayed
// open; a control character has no place in a path, a name or an option.
func checkText(fields []textField) error {
	for _, f := range fields {
		if !utf8.ValidString(f.value) {
			return fmt.Errorf("nono: %s %q is not valid UTF-8", f.name, f.value)
		}
		if strings.IndexFunc(f.value, unicode.IsControl) >= 0 {
			return fmt.Errorf("nono: %s %q contains a control character", f.name, f.value)
		}
	}
	return nil
}

// writeJSON writes v to path with mode 600. It writes a new file and
// renames it into place, so that a reader never sees half a file and an
// old file's looser mode does not carry over.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, err = f.Write(append(data, '\n'))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		os.Remove(f.Name())
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
