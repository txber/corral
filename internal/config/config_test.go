package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// validConfig is a complete corral.toml; each refusal test changes one line of it.
const validConfig = `max_agents = 4

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
use = "sandboxer"
binary = "/usr/local/bin/sandboxer"

[key_proxy]
use = "sandboxer"

[runtime]
use = "runner"
`

// validRole is a complete role table; each refusal test changes one line of it.
const validRole = `[worker]
network = "direct"
model = "example-model"
cost = { input = 1.0, output = 2.0, cacheRead = 0.5, cacheWrite = 0.0 }
`

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "file.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExampleConfigLoads(t *testing.T) {
	t.Setenv("HOME", "/home/you")
	cfg, err := Load("../../examples/corral.toml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway.Name != "example" || cfg.Gateway.KeyFile != "/home/you/.keys/example" {
		t.Errorf("gateway = %+v", cfg.Gateway)
	}
	if len(cfg.Gateway.Endpoints) != 2 || cfg.Gateway.Endpoints[1].Method != "GET" || cfg.Gateway.Endpoints[1].Path != "/models" {
		t.Errorf("endpoints = %+v", cfg.Gateway.Endpoints)
	}
	if cfg.MaxAgents != 4 {
		t.Errorf("max_agents = %d", cfg.MaxAgents)
	}
	if cfg.Paths.State != "/home/you/.local/state/corral" || cfg.Paths.Helper != "" {
		t.Errorf("paths = %+v", cfg.Paths)
	}
	if cfg.Sandbox.Name == "" || cfg.Sandbox.Options["binary"] == nil {
		t.Errorf("sandbox = %+v", cfg.Sandbox)
	}
	if _, ok := cfg.Runtime.Options["use"]; ok || cfg.Runtime.Name == "" {
		t.Errorf("runtime = %+v", cfg.Runtime)
	}
}

func TestExampleRolesLoad(t *testing.T) {
	roles, err := LoadRoles("../../examples/roles.toml")
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 2 {
		t.Fatalf("got %d roles, want 2", len(roles))
	}
	if roles["offline"].Network != "none" {
		t.Errorf("offline network = %q", roles["offline"].Network)
	}
	w := roles["worker"]
	if w.Name != "worker" || w.Network != "direct" || w.Model != "example-model" {
		t.Errorf("worker = %+v", w)
	}
	if w.Limits.Memory != "2G" || w.Limits.MaxProcesses != 256 {
		t.Errorf("limits = %+v", w.Limits)
	}
	if tools, _ := w.Options["tools"].([]any); len(tools) != 7 {
		t.Errorf("options = %+v", w.Options)
	}
}

func TestBadConfigIsRefused(t *testing.T) {
	cases := []struct{ name, old, new, key string }{
		{"gateway name", `name = "example"`, `name = "Example-1"`, "gateway.name"},
		{"upstream", `https://gateway.example/v1`, `http://gateway.example/v1`, "gateway.upstream"},
		{"endpoint", `"GET /models"`, `"/models"`, "gateway.endpoints"},
		{"relative path", `work = "/home/you/work"`, `work = "work"`, "paths.work"},
		{"relative key file", `/home/you/.keys/example`, `keys/example`, "gateway.key_file"},
		{"unknown key", `[paths]`, "[paths]\nelsewhere = \"/x\"", "paths.elsewhere"},
		{"missing use", `use = "runner"`, ``, "runtime.use"},
		{"too few agents", `max_agents = 4`, `max_agents = 0`, "max_agents"},
		{"too many agents", `max_agents = 4`, `max_agents = 251`, "max_agents"},
		{"key in the wrong case", `key_file =`, `KEY_FILE =`, "KEY_FILE"},
		{"top-level key in the wrong case", `max_agents = 4`, `Max_Agents = 4`, "Max_Agents"},
		{"no endpoints", `endpoints = ["POST /chat/completions", "GET /models"]`, `endpoints = []`, "gateway.endpoints"},
		{"odd method", `"GET /models"`, `"P{S /models"`, "gateway.endpoints"},
		{"path with a space", `"GET /models"`, `"GET /mod els"`, "gateway.endpoints"},
		{"path with dot-dot", `work = "/home/you/work"`, `work = "/home/you/../../etc"`, "paths.work"},
		{"key file with dot-dot", `/home/you/.keys/example`, `/home/you/../x`, "gateway.key_file"},
		{"upstream with credentials", `https://gateway.example/v1`, `https://user:pass@gateway.example/v1`, "gateway.upstream"},
		{"upstream with a query", `https://gateway.example/v1`, `https://gateway.example/v1?a=b`, "gateway.upstream"},
		{"upstream with a fragment", `https://gateway.example/v1`, `https://gateway.example/v1#x`, "gateway.upstream"},
		{"upstream without a host", `https://gateway.example/v1`, `https:///v1`, "gateway.upstream"},
		{"relative helper", `roles = "/home/you/roles.toml"`, "roles = \"/home/you/roles.toml\"\nhelper = \"corral\"", "paths.helper"},
		{"use that is not a string", `use = "runner"`, `use = 7`, "runtime.use"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text := strings.Replace(validConfig, c.old, c.new, 1)
			if text == validConfig {
				t.Fatal("the case changes nothing")
			}
			_, err := Load(writeFile(t, text))
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), c.key) {
				t.Errorf("error %q does not name %q", err, c.key)
			}
		})
	}
	if _, err := Load(writeFile(t, validConfig)); err != nil {
		t.Errorf("the valid file is refused: %v", err)
	}
}

func TestHelperIsKept(t *testing.T) {
	text := strings.Replace(validConfig, `roles = "/home/you/roles.toml"`, "roles = \"/home/you/roles.toml\"\nhelper = \"/opt/x/../bin/corral\"", 1)
	_, err := Load(writeFile(t, text))
	if err == nil {
		t.Fatal("a helper with .. must be refused")
	}
	text = strings.Replace(validConfig, `roles = "/home/you/roles.toml"`, "roles = \"/home/you/roles.toml\"\nhelper = \"/opt/bin//corral\"", 1)
	cfg, err := Load(writeFile(t, text))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Paths.Helper != "/opt/bin/corral" {
		t.Errorf("helper = %q", cfg.Paths.Helper)
	}
}

func TestMissingGatewayIsRefused(t *testing.T) {
	i := strings.Index(validConfig, "[gateway]")
	j := strings.Index(validConfig, "[paths]")
	_, err := Load(writeFile(t, validConfig[:i]+validConfig[j:]))
	if err == nil || !strings.Contains(err.Error(), "gateway") {
		t.Errorf("error = %v, want one naming gateway", err)
	}
}

func TestEmptyRolesAreRefused(t *testing.T) {
	if _, err := LoadRoles(writeFile(t, "")); err == nil {
		t.Error("a file without a role must be refused")
	}
}

func TestBadRolesAreRefused(t *testing.T) {
	cases := []struct{ name, old, new, key string }{
		{"unknown key", `model = "example-model"`, "model = \"example-model\"\ncolour = \"red\"", "worker.colour"},
		{"unknown network", `"direct"`, `"open"`, "worker.network"},
		{"missing network", `network = "direct"`, ``, "worker.network"},
		{"cost without a number", `, cacheWrite = 0.0`, ``, "worker.cost.cacheWrite"},
		{"role name with a slash", `[worker]`, `["bad/name"]`, "bad/name"},
		{"role name in upper case", `[worker]`, `[Worker]`, "Worker"},
		{"role name too long", `[worker]`, `[a234567890123456789012345678901234]`, "a2345"},
		{"field in the wrong case", `network =`, `Network =`, "worker.Network"},
		{"cost in the wrong case", `cost =`, `Cost =`, "worker.Cost"},
		{"cost key in the wrong case", `cacheRead`, `cacheread`, "worker.cost.cacheread"},
		{"cost is nan", `input = 1.0`, `input = nan`, "worker.cost.input"},
		{"cost is infinite", `output = 2.0`, `output = inf`, "worker.cost.output"},
		{"cost is negative", `output = 2.0`, `output = -2.0`, "worker.cost.output"},
		{"unknown cost key", `input = 1.0`, `input = 1.0, extra = 1.0`, "worker.cost.extra"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text := strings.Replace(validRole, c.old, c.new, 1)
			_, err := LoadRoles(writeFile(t, text))
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), c.key) {
				t.Errorf("error %q does not name %q", err, c.key)
			}
		})
	}
	if _, err := LoadRoles(writeFile(t, validRole)); err != nil {
		t.Errorf("the valid file is refused: %v", err)
	}
}

func TestTildeIsExpanded(t *testing.T) {
	t.Setenv("HOME", "/home/you")
	text := strings.Replace(validConfig, `work = "/home/you/work"`, `work = "~/work"`, 1)
	cfg, err := Load(writeFile(t, text))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Paths.Work != "/home/you/work" {
		t.Errorf("work = %q", cfg.Paths.Work)
	}
}

// TestPublicTreeNamesNoDeployment checks that no tracked file names the
// private setup. The words are built from parts so that this file does not
// contain them.
func TestPublicTreeNamesNoDeployment(t *testing.T) {
	words := []string{"bif" + "rost", "trusted" + "tokens", "orch" + "est"}
	out, err := exec.Command("git", "ls-files", "-z").Output()
	if err != nil {
		t.Skipf("not in a git checkout: %v", err)
	}
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		data, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(root)), name))
		if err != nil {
			continue // deleted but not yet committed
		}
		text := string(data)
		for _, w := range words {
			if strings.Contains(text, w) {
				t.Errorf("%s contains %q", name, w)
			}
		}
		for rest := text; ; {
			_, after, found := strings.Cut(rest, "/ho"+"me/")
			if !found {
				break
			}
			if !strings.HasPrefix(after, "you") {
				t.Errorf("%s contains a home path", name)
				break
			}
			rest = after
		}
	}
}
