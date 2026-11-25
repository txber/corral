package nono

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/txber/corral/integration"
)

const binary = "/usr/local/bin/nono"

// sampleAgent is an agent with every field an integration reads.
func sampleAgent(t *testing.T, network string) integration.Agent {
	t.Helper()
	return integration.Agent{
		ID:       "a1",
		Role:     "worker",
		Network:  network,
		Workdir:  "/home/you/work/a1",
		StateDir: t.TempDir(),
		Limits:   integration.Limits{Memory: "2G", MaxProcesses: 256},
		Deny:     []string{"/home/you/.keys"},
		Gateway: integration.Gateway{
			Name:      "example",
			Upstream:  "https://gateway.example/v1",
			Endpoints: []integration.Endpoint{{Method: "POST", Path: "/chat/completions"}, {Method: "GET", Path: "/models"}},
			KeyFile:   "/home/you/.keys/example",
		},
		ProxyPort: 18007,
	}
}

func newSandbox(t *testing.T) integration.Sandbox {
	t.Helper()
	s, err := integration.NewSandbox("nono", map[string]any{"binary": binary})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newKeyProxy(t *testing.T) integration.KeyProxy {
	t.Helper()
	p, err := integration.NewKeyProxy("nono", map[string]any{"binary": binary})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// readJSON reads a generated profile back as plain JSON values and checks
// that only its owner may read it.
func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("%s has mode %v, want 0600", path, mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return v
}

// prepared runs Prepare for a and returns the profile it wrote.
func prepared(t *testing.T, a integration.Agent, readPaths []string) map[string]any {
	t.Helper()
	if err := newSandbox(t).Prepare(a, readPaths); err != nil {
		t.Fatal(err)
	}
	return readJSON(t, filepath.Join(a.StateDir, "sandbox.json"))
}

// field walks into nested JSON objects by key.
func field(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

// asJSON turns a Go value into the plain form json.Unmarshal gives, for
// comparing against a profile read back.
func asJSON(t *testing.T, v any) any {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func checkField(t *testing.T, profile map[string]any, want any, keys ...string) {
	t.Helper()
	got := field(profile, keys...)
	if !reflect.DeepEqual(got, asJSON(t, want)) {
		t.Errorf("%s = %#v, want %#v", strings.Join(keys, "."), got, want)
	}
}

func TestSandboxProfileMediatesUnixSocketsAndDeniesTheGivenFolders(t *testing.T) {
	a := sampleAgent(t, "direct")
	profile := prepared(t, a, []string{"/usr/local/lib/tool"})
	checkField(t, profile, "default", "extends")
	checkField(t, profile, "pathname", "linux", "af_unix_mediation")
	checkField(t, profile, []string{"/home/you/.keys"}, "filesystem", "deny")
	checkField(t, profile, []string{"/usr/local/lib/tool"}, "filesystem", "read")
}

func TestSandboxProfilePointsApprovalsAtItsSocket(t *testing.T) {
	a := sampleAgent(t, "direct")
	profile := prepared(t, a, nil)
	checkField(t, profile, true, "security", "capability_elevation")
	checkField(t, profile, map[string]any{
		"corral": map[string]any{
			"type":         "webhook",
			"url":          "unix://" + filepath.Join(a.StateDir, "approval.sock"),
			"timeout_secs": 30,
		},
	}, "security", "approval_backends")
	checkField(t, profile, map[string]any{"backend": "corral"}, "security", "approval_defaults")
}

func TestWrapPutsTheCommandAfterADoubleDash(t *testing.T) {
	a := sampleAgent(t, "direct")
	command := []string{"/usr/local/lib/pi/pi", "--mode", "rpc"}
	argv := newSandbox(t).Wrap(a, command)
	want := []string{
		binary, "run", "--silent", "--sandbox-policy", "external",
		"--name", "a1",
		"--profile", filepath.Join(a.StateDir, "sandbox.json"),
		"--allow", "/home/you/work/a1",
		"--memory", "2G",
		"--max-processes", "256",
		"--", "/usr/local/lib/pi/pi", "--mode", "rpc",
	}
	if !slices.Equal(argv, want) {
		t.Errorf("Wrap =\n%q\nwant\n%q", argv, want)
	}
}

func TestWrapUsesExternalPolicyOnlyForDirectNetwork(t *testing.T) {
	s := newSandbox(t)
	for _, network := range []string{"direct", "proxy", "none"} {
		argv := s.Wrap(sampleAgent(t, network), []string{"true"})
		external := strings.Contains(strings.Join(argv, " "), "--sandbox-policy external")
		if external != (network == "direct") {
			t.Errorf("network %q: Wrap = %q; external policy %v, want %v", network, argv, external, network == "direct")
		}
	}
}

func TestWrapLeavesOutLimitsThatAreUnset(t *testing.T) {
	a := sampleAgent(t, "direct")
	a.Limits = integration.Limits{}
	argv := newSandbox(t).Wrap(a, []string{"true"})
	for _, flag := range []string{"--memory", "--max-processes"} {
		if slices.Contains(argv, flag) {
			t.Errorf("Wrap = %q, want no %s", argv, flag)
		}
	}
}

func TestStopCommandNamesTheSession(t *testing.T) {
	got := newSandbox(t).StopCommand(sampleAgent(t, "direct"))
	if want := []string{binary, "stop", "a1"}; !slices.Equal(got, want) {
		t.Errorf("StopCommand = %q, want %q", got, want)
	}
}

func TestModeNoneProfileRoutesOnlyTheGatewayAndNamesTheTokenVariable(t *testing.T) {
	a := sampleAgent(t, "none")
	profile := prepared(t, a, nil)
	checkField(t, profile, []string{"example"}, "network", "credentials")
	checkField(t, profile, map[string]any{
		"example": map[string]any{
			"upstream":          "https://gateway.example/v1",
			"credential_key":    "file:///home/you/.keys/example",
			"env_var":           integration.TokenEnv,
			"inject_header":     "Authorization",
			"credential_format": "Bearer {}",
			"endpoint_rules": []any{
				map[string]any{"method": "POST", "path": "/chat/completions"},
				map[string]any{"method": "GET", "path": "/models"},
			},
		},
	}, "network", "custom_credentials")
	// nono checks a routed request against allow_domain with the path below
	// the route, as it does for the route's own rules.
	checkField(t, profile, []any{
		map[string]any{
			"domain": "gateway.example",
			"endpoints": []any{
				map[string]any{"method": "POST", "path": "/chat/completions"},
				map[string]any{"method": "GET", "path": "/models"},
			},
		},
	}, "network", "allow_domain")
	checkField(t, profile, field(profile, "security", "approval_backends"), "network", "approval_backends")
	checkField(t, profile, map[string]any{"backend": "corral"}, "network", "approval_defaults")
}

func TestModeNoneWrapFixesTheProxyPortAndKeepsNonosNetworkLock(t *testing.T) {
	a := sampleAgent(t, "none")
	argv := newSandbox(t).Wrap(a, []string{"true"})
	line := strings.Join(argv, " ")
	if !strings.Contains(line, "--proxy-port 18007 ") {
		t.Errorf("Wrap = %q, want --proxy-port 18007", argv)
	}
	if strings.Contains(line, "--sandbox-policy") {
		t.Errorf("Wrap = %q, want no --sandbox-policy", argv)
	}
}

func TestModeNoneNeedsAProxyPortAndAnAbsoluteKeyFile(t *testing.T) {
	s := newSandbox(t)
	a := sampleAgent(t, "none")
	a.ProxyPort = 0
	if err := s.Prepare(a, nil); err == nil {
		t.Error("Prepare without a proxy port succeeded, want an error")
	}
	a = sampleAgent(t, "none")
	a.Gateway.KeyFile = "keys/example"
	if err := s.Prepare(a, nil); err == nil {
		t.Error("Prepare with a relative key file succeeded, want an error")
	}
}

func TestModeDirectProfileHasNoNetworkSection(t *testing.T) {
	for _, network := range []string{"direct", "proxy"} {
		profile := prepared(t, sampleAgent(t, network), nil)
		if n, ok := profile["network"]; ok {
			t.Errorf("network %q: profile has a network section: %v", network, n)
		}
	}
}

func TestProxyProfileListsOnlyTheGateway(t *testing.T) {
	a := sampleAgent(t, "direct")
	listen := netip.MustParseAddrPort("198.18.7.1:18007")
	if err := newKeyProxy(t).Prepare(a, a.Gateway, listen); err != nil {
		t.Fatal(err)
	}
	profile := readJSON(t, filepath.Join(a.StateDir, "proxy.json"))
	checkField(t, profile, "default", "extends")
	checkField(t, profile, []any{
		map[string]any{
			"domain": "gateway.example",
			"endpoints": []any{
				map[string]any{"method": "POST", "path": "/chat/completions"},
				map[string]any{"method": "GET", "path": "/models"},
			},
		},
	}, "network", "allow_domain")
	checkField(t, profile, []string{"example"}, "network", "credentials")
	routes, _ := field(profile, "network", "custom_credentials").(map[string]any)
	if len(routes) != 1 || routes["example"] == nil {
		t.Fatalf("custom_credentials = %v, want one route named example", routes)
	}
	checkField(t, profile, "file:///home/you/.keys/example", "network", "custom_credentials", "example", "credential_key")
	checkField(t, profile, "EXAMPLE_API_KEY", "network", "custom_credentials", "example", "env_var")
	for _, key := range []string{"security", "linux", "filesystem"} {
		if _, ok := profile[key]; ok {
			t.Errorf("proxy profile has a %s section", key)
		}
	}
	if _, ok := field(profile, "network").(map[string]any)["approval_backends"]; ok {
		t.Error("proxy profile asks an approval backend")
	}
}

func TestProxyCommandKeepsTheTokenOutOfTheArguments(t *testing.T) {
	a := sampleAgent(t, "direct")
	a.GatewayToken = "stand-in-token-1234"
	listen := netip.MustParseAddrPort("198.18.7.1:18007")
	argv, env := newKeyProxy(t).Command(a, a.Gateway, listen)
	want := []string{
		binary, "proxy", "--listen", "198.18.7.1", "--port", "18007",
		"--profile", filepath.Join(a.StateDir, "proxy.json"),
	}
	if !slices.Equal(argv, want) {
		t.Errorf("argv = %q, want %q", argv, want)
	}
	if strings.Contains(strings.Join(argv, " "), a.GatewayToken) {
		t.Errorf("argv %q holds the token", argv)
	}
	if want := []string{"NONO_PROXY_PASS=stand-in-token-1234"}; !slices.Equal(env, want) {
		t.Errorf("env = %q, want %q", env, want)
	}
}

func TestProxyURLFollowsAddressAndGatewayName(t *testing.T) {
	g := integration.Gateway{Name: "example"}
	got := newKeyProxy(t).URL(g, netip.MustParseAddrPort("198.18.7.1:18007"))
	if want := "http://198.18.7.1:18007/example"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
}

func TestFactoriesRefuseAMissingOrRelativeBinaryAndUnknownOptions(t *testing.T) {
	bad := []map[string]any{
		nil,
		{},
		{"binary": "nono"},
		{"binary": "bin/nono"},
		{"binary": 5},
		{"binary": binary, "extra": true},
	}
	for _, options := range bad {
		if _, err := integration.NewSandbox("nono", options); err == nil {
			t.Errorf("NewSandbox(%v) succeeded, want an error", options)
		}
		if _, err := integration.NewKeyProxy("nono", options); err == nil {
			t.Errorf("NewKeyProxy(%v) succeeded, want an error", options)
		}
	}
	newSandbox(t)
	newKeyProxy(t)
}

func TestSandboxProfileRefusesASocketPathTooLongToBind(t *testing.T) {
	a := sampleAgent(t, "direct")
	a.StateDir = "/" + strings.Repeat("d", 100)
	if err := newSandbox(t).Prepare(a, nil); err == nil || !strings.Contains(err.Error(), "longer than 107 bytes") {
		t.Errorf("Prepare = %v, want an error about the socket path's length", err)
	}
}
