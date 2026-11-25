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
	"slices"
	"strconv"
	"strings"

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
// about every other host; in the other modes the network is confined
// from outside and the profile says nothing about it.
func sandboxProfile(a integration.Agent, readPaths []string) (profile, error) {
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
	if a.Network != "none" {
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
	upstream, err := url.Parse(g.Upstream)
	if err != nil || upstream.Hostname() == "" {
		return networkSection{}, fmt.Errorf("nono: gateway upstream %q has no host", g.Upstream)
	}
	if !filepath.IsAbs(g.KeyFile) {
		return networkSection{}, fmt.Errorf("nono: gateway key file %q is not absolute", g.KeyFile)
	}
	// The route's rules apply to the path below the route; allow_domain
	// matches the full path on the gateway's host, which begins with the
	// upstream's own path.
	prefix := strings.TrimSuffix(upstream.Path, "/")
	var routeRules, hostRules []endpointRule
	for _, e := range g.Endpoints {
		routeRules = append(routeRules, endpointRule{Method: e.Method, Path: e.Path})
		hostRules = append(hostRules, endpointRule{Method: e.Method, Path: prefix + e.Path})
	}
	return networkSection{
		AllowDomain: []allowedDomain{{Domain: upstream.Hostname(), Endpoints: hostRules}},
		Credentials: []string{g.Name},
		CustomCredentials: map[string]credentialRoute{g.Name: {
			Upstream:         g.Upstream,
			CredentialKey:    "file://" + g.KeyFile,
			EnvVar:           envVar,
			InjectHeader:     "Authorization",
			CredentialFormat: "Bearer {}",
			EndpointRules:    routeRules,
		}},
	}, nil
}

// Wrap returns the command line that runs command in the sandbox.
func (s sandbox) Wrap(a integration.Agent, command []string) []string {
	argv := []string{s.binary, "run", "--silent"}
	if a.Network == "direct" {
		// The agent's namespace and firewall confine the network; nono's
		// own TCP lock would block the addresses the agent was given.
		argv = append(argv, "--sandbox-policy", "external")
	}
	argv = append(argv,
		"--name", a.ID,
		"--profile", filepath.Join(a.StateDir, sandboxProfileFile),
		"--allow", a.Workdir,
	)
	if a.Limits.Memory != "" {
		argv = append(argv, "--memory", a.Limits.Memory)
	}
	if a.Limits.MaxProcesses > 0 {
		argv = append(argv, "--max-processes", strconv.Itoa(a.Limits.MaxProcesses))
	}
	if a.Network == "none" {
		// The gateway is served at http://127.0.0.1:<ProxyPort>/<name>.
		argv = append(argv, "--proxy-port", strconv.Itoa(a.ProxyPort))
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

// StopCommand ends the agent's sandbox session by its name.
func (s sandbox) StopCommand(a integration.Agent) []string {
	return []string{s.binary, "stop", a.ID}
}

// AuditPath is empty: corral does not read nono's own audit log yet.
func (s sandbox) AuditPath(integration.Agent) string { return "" }

// keyProxy serves the gateway with `nono proxy`.
type keyProxy struct{ binary string }

// Prepare writes the proxy's profile to <StateDir>/proxy.json.
func (k keyProxy) Prepare(a integration.Agent, g integration.Gateway, _ netip.AddrPort) error {
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
// present goes into the environment, never into the arguments.
func (k keyProxy) Command(a integration.Agent, g integration.Gateway, listen netip.AddrPort) (argv, env []string) {
	argv = []string{
		k.binary, "proxy",
		"--listen", listen.Addr().String(),
		"--port", strconv.Itoa(int(listen.Port())),
		"--profile", filepath.Join(a.StateDir, proxyProfileFile),
	}
	return argv, []string{"NONO_PROXY_PASS=" + a.GatewayToken}
}

// URL is where the agent reaches the gateway through the proxy.
func (k keyProxy) URL(g integration.Gateway, listen netip.AddrPort) string {
	return "http://" + listen.String() + "/" + g.Name
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
