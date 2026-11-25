// Package config reads corral's two configuration files: corral.toml (the
// model gateway, the paths corral uses, how many agents may run and which
// integrations serve as sandbox, runtime and key proxy) and roles.toml (the
// kinds of agent a job may start). Both are read strictly: an unknown key is
// an error, and every error names the key at fault.
package config

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/txber/corral/integration"
)

// Role is one kind of agent, from roles.toml.
type Role struct {
	Name    string
	Network string // "direct", "proxy" or "none"
	Model   string
	Limits  integration.Limits
	Cost    integration.Cost
	Options map[string]any // handed to the runtime integration as they are
}

// Paths are the files and folders corral uses. Helper is optional: it is the
// program that enables the network mode "direct", and is empty when not set.
type Paths struct{ State, Run, Work, Roles, Helper string }

// Use names the integration that serves one part (sandbox, runtime or key
// proxy) and holds that integration's options, which corral does not interpret.
type Use struct {
	Name    string         // its `use` key
	Options map[string]any // every other key
}

// Config is the content of corral.toml.
type Config struct {
	Gateway                    integration.Gateway
	Paths                      Paths
	MaxAgents                  int
	Sandbox, Runtime, KeyProxy Use
}

// rawConfig mirrors the file; Load checks it and turns it into a Config.
type rawConfig struct {
	MaxAgents int `toml:"max_agents"`
	Gateway   struct {
		Name      string
		Upstream  string
		Endpoints []string
		KeyFile   string `toml:"key_file"`
	}
	Paths struct {
		State, Run, Work, Roles, Helper string
	}
	Sandbox  map[string]any
	Runtime  map[string]any
	KeyProxy map[string]any `toml:"key_proxy"`
}

var gatewayName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Load reads and checks corral.toml. A leading ~ in a path is the home folder.
func Load(path string) (Config, error) {
	var raw rawConfig
	if err := decodeStrict(path, &raw); err != nil {
		return Config{}, err
	}
	var cfg Config
	var err error

	if raw.MaxAgents < 1 || raw.MaxAgents > 250 {
		return Config{}, fmt.Errorf("%s: max_agents is %d, want 1 to 250", path, raw.MaxAgents)
	}
	cfg.MaxAgents = raw.MaxAgents

	g := raw.Gateway
	if !gatewayName.MatchString(g.Name) {
		return Config{}, fmt.Errorf("%s: gateway.name %q must match %s", path, g.Name, gatewayName)
	}
	if u, err := url.Parse(g.Upstream); err != nil || u.Scheme != "https" || u.Host == "" {
		return Config{}, fmt.Errorf("%s: gateway.upstream %q must be an https:// address", path, g.Upstream)
	}
	cfg.Gateway = integration.Gateway{Name: g.Name, Upstream: g.Upstream}
	for _, e := range g.Endpoints {
		method, p, ok := strings.Cut(e, " ")
		if !ok || method == "" || method != strings.ToUpper(method) || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, " \t") {
			return Config{}, fmt.Errorf("%s: gateway.endpoints entry %q must be <METHOD> <path>", path, e)
		}
		cfg.Gateway.Endpoints = append(cfg.Gateway.Endpoints, integration.Endpoint{Method: method, Path: p})
	}
	if cfg.Gateway.KeyFile, err = absolutePath(path, "gateway.key_file", g.KeyFile, true); err != nil {
		return Config{}, err
	}

	p := raw.Paths
	for _, f := range []struct {
		key      string
		in       string
		out      *string
		required bool
	}{
		{"paths.state", p.State, &cfg.Paths.State, true},
		{"paths.run", p.Run, &cfg.Paths.Run, true},
		{"paths.work", p.Work, &cfg.Paths.Work, true},
		{"paths.roles", p.Roles, &cfg.Paths.Roles, true},
		{"paths.helper", p.Helper, &cfg.Paths.Helper, false},
	} {
		if *f.out, err = absolutePath(path, f.key, f.in, f.required); err != nil {
			return Config{}, err
		}
	}

	for _, u := range []struct {
		key string
		in  map[string]any
		out *Use
	}{
		{"sandbox", raw.Sandbox, &cfg.Sandbox},
		{"runtime", raw.Runtime, &cfg.Runtime},
		{"key_proxy", raw.KeyProxy, &cfg.KeyProxy},
	} {
		name, ok := u.in["use"].(string)
		if !ok || name == "" {
			return Config{}, fmt.Errorf("%s: %s.use is missing or not a name", path, u.key)
		}
		delete(u.in, "use")
		*u.out = Use{Name: name, Options: u.in}
	}
	return cfg, nil
}

// rawRole mirrors one role table. The cost numbers are pointers so that a
// missing number can be told from 0.
type rawRole struct {
	Network      string
	Model        string
	Memory       string
	MaxProcesses int `toml:"max_processes"`
	Cost         *struct {
		Input, Output, CacheRead, CacheWrite *float64
	}
	Options map[string]any
}

// LoadRoles reads and checks roles.toml.
func LoadRoles(path string) (map[string]Role, error) {
	var raw map[string]rawRole
	if err := decodeStrict(path, &raw); err != nil {
		return nil, err
	}
	roles := make(map[string]Role, len(raw))
	for name, r := range raw {
		switch r.Network {
		case "direct", "proxy", "none":
		default:
			return nil, fmt.Errorf("%s: %s.network is %q, want \"direct\", \"proxy\" or \"none\"", path, name, r.Network)
		}
		if r.Model == "" {
			return nil, fmt.Errorf("%s: %s.model is missing", path, name)
		}
		if r.MaxProcesses < 0 {
			return nil, fmt.Errorf("%s: %s.max_processes is negative", path, name)
		}
		if r.Cost == nil {
			return nil, fmt.Errorf("%s: %s.cost is missing", path, name)
		}
		var cost integration.Cost
		for _, n := range []struct {
			key string
			in  *float64
			out *float64
		}{
			{"input", r.Cost.Input, &cost.Input},
			{"output", r.Cost.Output, &cost.Output},
			{"cacheRead", r.Cost.CacheRead, &cost.CacheRead},
			{"cacheWrite", r.Cost.CacheWrite, &cost.CacheWrite},
		} {
			if n.in == nil {
				return nil, fmt.Errorf("%s: %s.cost.%s is missing", path, name, n.key)
			}
			if *n.in < 0 {
				return nil, fmt.Errorf("%s: %s.cost.%s is negative", path, name, n.key)
			}
			*n.out = *n.in
		}
		roles[name] = Role{
			Name:    name,
			Network: r.Network,
			Model:   r.Model,
			Limits:  integration.Limits{Memory: r.Memory, MaxProcesses: r.MaxProcesses},
			Cost:    cost,
			Options: r.Options,
		}
	}
	return roles, nil
}

// decodeStrict reads the TOML file at path into v and refuses any key that v
// has no field for.
func decodeStrict(path string, v any) error {
	md, err := toml.DecodeFile(path, v)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if keys := md.Undecoded(); len(keys) > 0 {
		return fmt.Errorf("%s: unknown key %s", path, keys[0])
	}
	return nil
}

// absolutePath expands a leading ~ in value and checks that the result is
// absolute. An empty value is an error when required and "" otherwise.
func absolutePath(file, key, value string, required bool) (string, error) {
	if value == "" {
		if required {
			return "", fmt.Errorf("%s: %s is missing", file, key)
		}
		return "", nil
	}
	if value == "~" || strings.HasPrefix(value, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("%s: %s: expand ~: %w", file, key, err)
		}
		value = home + value[1:]
	}
	if !strings.HasPrefix(value, "/") {
		return "", fmt.Errorf("%s: %s %q must be an absolute path", file, key, value)
	}
	return value, nil
}
