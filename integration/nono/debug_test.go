package nono

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const debugConfig = `max_agents = 4

[gateway]
name = "example"
upstream = "https://gateway.example/v1"
endpoints = ["POST /chat/completions", "GET /models"]
key_file = "/home/you/.keys/example"

[paths]
state = "/home/you/state"
run = "/home/you/run"
work = "/home/you/work"
roles = "/home/you/roles.toml"

[sandbox]
use = "nono"
binary = "/usr/local/bin/nono"

[key_proxy]
use = "nono"
binary = "/usr/local/bin/nono"

[runtime]
use = "pi"
`

func TestDebugProfilesWritesBothNetworkModesAndTheProxy(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "corral.toml")
	if err := os.WriteFile(config, []byte(debugConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "profiles")
	var stdout, stderr bytes.Buffer
	if code := DebugProfiles([]string{"--config", config, "--dir", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("DebugProfiles = %d, stderr %q", code, stderr.String())
	}
	none := readJSON(t, filepath.Join(out, "sandbox-none.json"))
	if field(none, "network", "custom_credentials", "example") == nil {
		t.Errorf("sandbox-none.json has no route for the gateway: %v", none["network"])
	}
	direct := readJSON(t, filepath.Join(out, "sandbox-direct.json"))
	if _, ok := direct["network"]; ok {
		t.Errorf("sandbox-direct.json has a network section")
	}
	proxy := readJSON(t, filepath.Join(out, "proxy.json"))
	if field(proxy, "network", "allow_domain") == nil {
		t.Errorf("proxy.json lists no gateway")
	}
}

func TestDebugProfilesRefusesAMissingConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := DebugProfiles([]string{"--config", filepath.Join(t.TempDir(), "none.toml"), "--dir", t.TempDir()}, &stdout, &stderr)
	if code == 0 || stderr.Len() == 0 {
		t.Errorf("DebugProfiles = %d, stderr %q; want a failure with a message", code, stderr.String())
	}
}
