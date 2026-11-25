package config

import (
	"math"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
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

// A dotted key names its tables only through the key itself, as PATHS does in
// PATHS.helper; every part of such a key must still be spelt as the schema
// says. The error names the whole key.
func TestDottedKeysAreCheckedPartByPart(t *testing.T) {
	t.Setenv("HOME", "/home/you")
	configs := []struct{ name, text, key string }{
		{"unknown top-level table", "nope.x = 1\n" + validConfig, "nope.x"},
		{"paths in the wrong case", "PATHS.helper = \"/opt/other\"\n" + validConfig, "PATHS.helper"},
		{"gateway in the wrong case", "GATEWAY.upstream = \"https://other.example/v1\"\n" + validConfig, "GATEWAY.upstream"},
		{"sandbox in the wrong case", "Sandbox.use = \"other\"\n" + validConfig, "Sandbox.use"},
		{"unknown table in gateway", strings.Replace(validConfig, "[gateway]\n", "[gateway]\nX.y = 1\n", 1), "gateway.X.y"},
		{"field used as a table", strings.Replace(validConfig, "[gateway]\n", "[gateway]\nNAME.x = 1\n", 1), "gateway.NAME.x"},
		{"unknown table header", validConfig + "[paths.extra]\nx = 1\n", "paths.extra"},
	}
	for _, c := range configs {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(writeFile(t, c.text))
			if err == nil || !strings.Contains(err.Error(), "unknown key "+c.key) {
				t.Errorf("error = %v, want one naming %s", err, c.key)
			}
		})
	}

	roles := []struct{ name, text, key string }{
		{"unknown role field", validRole + "colour.x = 1\n", "worker.colour.x"},
		{"cost in the wrong case", validRole + "COST.extra = 1\n", "worker.COST.extra"},
		{"cost key in the wrong case", strings.Replace(validRole, "cost = { input = 1.0, output = 2.0, cacheRead = 0.5, cacheWrite = 0.0 }",
			"cost.input = 1.0\ncost.output = 2.0\ncost.cacheRead = 0.5\ncost.CacheWrite = 0.0", 1), "worker.cost.CacheWrite"},
	}
	for _, c := range roles {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadRoles(writeFile(t, c.text))
			if err == nil || !strings.Contains(err.Error(), "unknown key "+c.key) {
				t.Errorf("error = %v, want one naming %s", err, c.key)
			}
		})
	}
}

func TestOptionTablesStayFreeForm(t *testing.T) {
	text := strings.Replace(validConfig, `use = "runner"`, "use = \"runner\"\nFlags.Deep = 1", 1)
	cfg, err := Load(writeFile(t, text))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Runtime.Options["Flags"] == nil {
		t.Errorf("runtime options = %+v", cfg.Runtime.Options)
	}
	roles, err := LoadRoles(writeFile(t, validRole+"options.Some.Thing = 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if roles["worker"].Options["Some"] == nil {
		t.Errorf("role options = %+v", roles["worker"].Options)
	}
}

func TestTextMustBeValidUTF8WithoutControlCharacters(t *testing.T) {
	t.Setenv("HOME", "/home/you")
	configs := []struct{ name, old, new, key string }{
		{"key file", `key_file = "/home/you/.keys/example"`, `key_file = "/home/you/.keys/ex\u0000ample"`, "gateway.key_file"},
		{"path", `work = "/home/you/work"`, `work = "/home/you/work\n"`, "paths.work"},
		{"helper", `roles = "/home/you/roles.toml"`, "roles = \"/home/you/roles.toml\"\nhelper = \"/opt/bin/corral\\u0085\"", "paths.helper"},
		{"use", `use = "runner"`, `use = "run\u001bner"`, "runtime.use"},
		{"option name", `use = "runner"`, "use = \"runner\"\n\"fla\\u0007g\" = 1", "runtime.fla"},
	}
	for _, c := range configs {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(writeFile(t, strings.Replace(validConfig, c.old, c.new, 1)))
			if err == nil || !strings.Contains(err.Error(), c.key) || !strings.Contains(err.Error(), "control characters") {
				t.Errorf("error = %v, want one naming %s", err, c.key)
			}
		})
	}

	roles := []struct{ name, old, new, key string }{
		{"model", `model = "example-model"`, `model = "example-model\t"`, "worker.model"},
		{"memory", `model = "example-model"`, "model = \"example-model\"\nmemory = \"2G\\u007f\"", "worker.memory"},
		{"option name", `model = "example-model"`, "model = \"example-model\"\noptions = { \"a\\u0000\" = 1 }", "worker.options.a"},
	}
	for _, c := range roles {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadRoles(writeFile(t, strings.Replace(validRole, c.old, c.new, 1)))
			if err == nil || !strings.Contains(err.Error(), c.key) || !strings.Contains(err.Error(), "control characters") {
				t.Errorf("error = %v, want one naming %s", err, c.key)
			}
		})
	}

	// The TOML reader refuses bytes that are not UTF-8, so this is checked
	// on the function itself.
	if err := checkText("file.toml", "paths.work", "/home/you/\xffwork"); err == nil {
		t.Error("text that is not UTF-8 was accepted")
	}
}

func TestEndpointPathHasNoSpaceOrControlCharacter(t *testing.T) {
	for _, path := range []string{"/mod\tels", "/models\n", "/mod els", "/mod　els", "/mod els", "/mod\u007fels"} {
		text := strings.Replace(validConfig, `"GET /models"`, strconv.Quote("GET "+path), 1)
		_, err := Load(writeFile(t, text))
		if err == nil || !strings.Contains(err.Error(), "gateway.endpoints") {
			t.Errorf("path %q: error = %v, want one naming gateway.endpoints", path, err)
		}
	}
}

func TestUpstreamBeginsWithLowerCaseHTTPS(t *testing.T) {
	for _, upstream := range []string{
		"HTTPS://gateway.example/v1",
		"Https://gateway.example/v1",
		"https://gateway.example/v 1",
		"https://gateway.example/v\t1",
		"https://gateway.example/v1　",
	} {
		text := strings.Replace(validConfig, `"https://gateway.example/v1"`, strconv.Quote(upstream), 1)
		_, err := Load(writeFile(t, text))
		if err == nil || !strings.Contains(err.Error(), "gateway.upstream") {
			t.Errorf("upstream %q: error = %v, want one naming gateway.upstream", upstream, err)
		}
	}
}

func TestErrorsQuoteAtMostEightyCharacters(t *testing.T) {
	long := strings.Repeat("é", 400)
	cut := `"` + strings.Repeat("é", 80) + `"…`

	_, err := Load(writeFile(t, strings.Replace(validConfig, `name = "example"`, `name = "`+long+`"`, 1)))
	if err == nil || !strings.Contains(err.Error(), cut) || strings.Contains(err.Error(), strings.Repeat("é", 81)) {
		t.Errorf("gateway.name: error = %v", err)
	}
	_, err = LoadRoles(writeFile(t, strings.Replace(validRole, `"direct"`, `"`+long+`"`, 1)))
	if err == nil || !strings.Contains(err.Error(), cut) || strings.Contains(err.Error(), strings.Repeat("é", 81)) {
		t.Errorf("worker.network: error = %v", err)
	}

	// A value of 80 characters is quoted whole.
	exact := strings.Repeat("x", 80)
	_, err = Load(writeFile(t, strings.Replace(validConfig, `work = "/home/you/work"`, `work = "`+exact+`"`, 1)))
	if err == nil || !strings.Contains(err.Error(), `"`+exact+`" must`) {
		t.Errorf("paths.work: error = %v", err)
	}
}

// wrongCaseConfig is validConfig written with dotted keys in the wrong case.
const wrongCaseConfig = `max_agents = 4
GATEWAY.name = "example"
GATEWAY.upstream = "https://gateway.example/v1"
GATEWAY.endpoints = ["GET /models"]
GATEWAY.KEY_FILE = "/k"
Paths.STATE = "/s"
Paths.RUN = "/r"
Paths.WORK = "/w"
Paths.ROLES = "/r.toml"
Paths.HELPER = "/h"
Sandbox.use = "a"
Runtime.use = "a"
Key_Proxy.use = "a"
`

// FuzzLoad checks that whatever Load accepts is what the documentation
// promises, and that its own errors are single lines of plain text.
func FuzzLoad(f *testing.F) {
	f.Setenv("HOME", "/home/you")
	example, err := os.ReadFile("../../examples/corral.toml")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(example))
	f.Add(validConfig)
	f.Add(wrongCaseConfig)
	f.Add("nope.x = 1\n" + validConfig)
	f.Add("GATEWAY.upstream = \"https://other.example/v1\"\nPATHS.helper = \"/opt/other\"\n" + validConfig)
	f.Add(strings.Replace(validConfig, "[gateway]\n", "[gateway]\nX.y = 1\n", 1))
	f.Add(strings.Replace(validConfig, `"GET /models"`, `"GET /mod\tels"`, 1))
	f.Add(strings.Replace(validConfig, `https://`, `HTTPS://`, 1))
	f.Add(strings.Replace(validConfig, `/v1"`, `/v 1"`, 1))
	f.Add(strings.Replace(validConfig, `work = "/home/you/work"`, `work = "~/../x"`, 1))
	f.Add(strings.Replace(validConfig, `name = "example"`, `name = "`+strings.Repeat("A", 400)+`"`, 1))
	f.Add(strings.Replace(validConfig, `use = "runner"`, "use = \"runner\"\nx = [{ \"a\\u0000\" = 1 }]", 1))

	f.Fuzz(func(t *testing.T, text string) {
		cfg, err := Load(writeFile(t, text))
		if err != nil {
			checkError(t, err)
			return
		}
		var doc map[string]any
		if _, err := toml.Decode(text, &doc); err != nil {
			t.Fatalf("accepted what the TOML reader refuses: %v", err)
		}
		checkKeys(t, doc, nil, configKeys)

		if cfg.MaxAgents < 1 || cfg.MaxAgents > 250 {
			t.Errorf("max_agents = %d", cfg.MaxAgents)
		}
		g := cfg.Gateway
		if !gatewayName.MatchString(g.Name) {
			t.Errorf("gateway.name = %q", g.Name)
		}
		u, err := url.Parse(g.Upstream)
		if !strings.HasPrefix(g.Upstream, "https://") || !plainWord(g.Upstream) ||
			err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			t.Errorf("gateway.upstream = %q", g.Upstream)
		}
		if len(g.Endpoints) == 0 {
			t.Error("no endpoints")
		}
		for _, e := range g.Endpoints {
			if !httpMethod.MatchString(e.Method) || !strings.HasPrefix(e.Path, "/") || !plainWord(e.Path) {
				t.Errorf("endpoint %q %q", e.Method, e.Path)
			}
		}
		for _, p := range []struct{ table, name, got string }{
			{"gateway", "key_file", g.KeyFile},
			{"paths", "state", cfg.Paths.State},
			{"paths", "run", cfg.Paths.Run},
			{"paths", "work", cfg.Paths.Work},
			{"paths", "roles", cfg.Paths.Roles},
			{"paths", "helper", cfg.Paths.Helper},
		} {
			table, _ := doc[p.table].(map[string]any)
			raw, _ := table[p.name].(string)
			if p.got == "" && raw == "" && p.name == "helper" {
				continue
			}
			want := raw
			if raw == "~" || strings.HasPrefix(raw, "~/") {
				want = "/home/you" + raw[1:]
			}
			if p.got != path.Clean(want) || !path.IsAbs(p.got) || slices.Contains(strings.Split(raw, "/"), "..") || checkText("", "", p.got) != nil {
				t.Errorf("%s.%s %q became %q", p.table, p.name, raw, p.got)
			}
		}
		for table, use := range map[string]Use{"sandbox": cfg.Sandbox, "runtime": cfg.Runtime, "key_proxy": cfg.KeyProxy} {
			m, _ := doc[table].(map[string]any)
			if use.Name == "" || use.Name != m["use"] || checkText("", "", use.Name) != nil {
				t.Errorf("%s.use = %q, the file says %q", table, use.Name, m["use"])
			}
			if _, ok := use.Options["use"]; ok {
				t.Errorf("%s: the options hold use", table)
			}
		}
	})
}

// FuzzLoadRoles checks that whatever LoadRoles accepts is what the
// documentation promises, and that its own errors are single lines of plain
// text.
func FuzzLoadRoles(f *testing.F) {
	example, err := os.ReadFile("../../examples/roles.toml")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(example))
	f.Add(validRole)
	f.Add("")
	f.Add(validRole + "colour.x = 1\n")
	f.Add(validRole + "COST.extra = 1\n")
	f.Add("worker.COST.Input = 99.0\n" + validRole)
	f.Add(strings.Replace(validRole, "[worker]", `["`+strings.Repeat("w", 400)+`"]`, 1))
	f.Add(strings.Replace(validRole, `"direct"`, `"`+strings.Repeat("d", 400)+`"`, 1))
	f.Add(strings.Replace(validRole, "input = 1.0", "input = -0.0", 1))

	f.Fuzz(func(t *testing.T, text string) {
		roles, err := LoadRoles(writeFile(t, text))
		if err != nil {
			checkError(t, err)
			return
		}
		var doc map[string]any
		if _, err := toml.Decode(text, &doc); err != nil {
			t.Fatalf("accepted what the TOML reader refuses: %v", err)
		}
		checkKeys(t, doc, nil, roleKeys)

		if len(roles) == 0 || len(roles) != len(doc) {
			t.Errorf("%d roles from %d tables", len(roles), len(doc))
		}
		for name, r := range roles {
			if _, ok := doc[name]; !ok || r.Name != name || !roleName.MatchString(name) {
				t.Errorf("role %q named %q", name, r.Name)
			}
			if r.Network != "direct" && r.Network != "proxy" && r.Network != "none" {
				t.Errorf("%s.network = %q", name, r.Network)
			}
			if r.Model == "" || checkText("", "", r.Model) != nil || checkText("", "", r.Limits.Memory) != nil {
				t.Errorf("%s: model %q, memory %q", name, r.Model, r.Limits.Memory)
			}
			if r.Limits.MaxProcesses < 0 {
				t.Errorf("%s.max_processes = %d", name, r.Limits.MaxProcesses)
			}
			for _, c := range []float64{r.Cost.Input, r.Cost.Output, r.Cost.CacheRead, r.Cost.CacheWrite} {
				if math.IsNaN(c) || math.IsInf(c, 0) || c < 0 {
					t.Errorf("%s: cost %v", name, c)
				}
			}
		}
	})
}

// checkError fails when one of corral's own errors is not one line of plain
// text. The TOML reader's messages, which follow "read <file>:", may quote
// the file as it is.
func checkError(t *testing.T, err error) {
	t.Helper()
	if !strings.HasPrefix(err.Error(), "read ") && checkText("", "", err.Error()) != nil {
		t.Errorf("error is not one line of plain text: %q", err)
	}
}

// checkKeys fails for every key in v, a value read from a TOML file at key,
// that is not plain text or not allowed by the schema that allowed describes.
func checkKeys(t *testing.T, v any, key toml.Key, allowed func(parent toml.Key) []string) {
	t.Helper()
	switch v := v.(type) {
	case map[string]any:
		names := allowed(key)
		for name, child := range v {
			full := append(slices.Clone(key), name)
			if checkText("", "", name) != nil || names != nil && !slices.Contains(names, name) {
				t.Errorf("accepted the key %s", full)
			}
			checkKeys(t, child, full, allowed)
		}
	case []map[string]any:
		for _, m := range v {
			checkKeys(t, m, key, allowed)
		}
	case []any:
		for _, e := range v {
			checkKeys(t, e, key, allowed)
		}
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
