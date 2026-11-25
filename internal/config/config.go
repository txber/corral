// Package config reads corral's two configuration files: corral.toml (the
// model gateway, the paths corral uses, how many agents may run and which
// integrations serve as sandbox, runtime and key proxy) and roles.toml (the
// kinds of agent a job may start). Both are read strictly: an unknown key is
// an error, and every error names the key at fault.
package config

import (
	"fmt"
	"math"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
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

var (
	gatewayName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	httpMethod  = regexp.MustCompile(`^[A-Z]+$`)
	roleName    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
)

// Load reads and checks corral.toml. A leading ~ in a path is the home folder.
func Load(path string) (Config, error) {
	var raw rawConfig
	err := decodeStrict(path, &raw, func(parent toml.Key) []string {
		switch parent.String() {
		case "":
			return []string{"max_agents", "gateway", "paths", "sandbox", "runtime", "key_proxy"}
		case "gateway":
			return []string{"name", "upstream", "endpoints", "key_file"}
		case "paths":
			return []string{"state", "run", "work", "roles", "helper"}
		}
		return nil // the options of an integration are not ours to check
	})
	if err != nil {
		return Config{}, err
	}

	if raw.MaxAgents < 1 || raw.MaxAgents > 250 {
		return Config{}, fmt.Errorf("%s: max_agents is %d, want 1 to 250", path, raw.MaxAgents)
	}

	g := raw.Gateway
	if !gatewayName.MatchString(g.Name) {
		return Config{}, fmt.Errorf("%s: gateway.name %q must match %s", path, g.Name, gatewayName)
	}
	// The upstream is written into files and logs, so it must carry no
	// credentials; the key comes from key_file.
	u, err := url.Parse(g.Upstream)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || strings.ContainsAny(g.Upstream, "?#") {
		return Config{}, fmt.Errorf("%s: gateway.upstream %q must be an https:// address with a host and no user, query or fragment", path, g.Upstream)
	}
	if len(g.Endpoints) == 0 {
		return Config{}, fmt.Errorf("%s: gateway.endpoints is empty", path)
	}
	var endpoints []integration.Endpoint
	for _, e := range g.Endpoints {
		method, p, ok := strings.Cut(e, " ")
		if !ok || !httpMethod.MatchString(method) || !strings.HasPrefix(p, "/") || strings.Contains(p, " ") {
			return Config{}, fmt.Errorf("%s: gateway.endpoints entry %q must be <METHOD> <path>", path, e)
		}
		endpoints = append(endpoints, integration.Endpoint{Method: method, Path: p})
	}
	keyFile, err := absolutePath(path, "gateway.key_file", g.KeyFile, true)
	if err != nil {
		return Config{}, err
	}

	state, err := absolutePath(path, "paths.state", raw.Paths.State, true)
	if err != nil {
		return Config{}, err
	}
	run, err := absolutePath(path, "paths.run", raw.Paths.Run, true)
	if err != nil {
		return Config{}, err
	}
	work, err := absolutePath(path, "paths.work", raw.Paths.Work, true)
	if err != nil {
		return Config{}, err
	}
	roles, err := absolutePath(path, "paths.roles", raw.Paths.Roles, true)
	if err != nil {
		return Config{}, err
	}
	helper, err := absolutePath(path, "paths.helper", raw.Paths.Helper, false)
	if err != nil {
		return Config{}, err
	}

	sandbox, err := useOf(path, "sandbox", raw.Sandbox)
	if err != nil {
		return Config{}, err
	}
	runtime, err := useOf(path, "runtime", raw.Runtime)
	if err != nil {
		return Config{}, err
	}
	keyProxy, err := useOf(path, "key_proxy", raw.KeyProxy)
	if err != nil {
		return Config{}, err
	}

	return Config{
		Gateway:   integration.Gateway{Name: g.Name, Upstream: g.Upstream, Endpoints: endpoints, KeyFile: keyFile},
		Paths:     Paths{State: state, Run: run, Work: work, Roles: roles, Helper: helper},
		MaxAgents: raw.MaxAgents,
		Sandbox:   sandbox,
		Runtime:   runtime,
		KeyProxy:  keyProxy,
	}, nil
}

// useOf turns the table called key into a Use: its `use` entry is the name
// and every other entry is an option.
func useOf(file, key string, table map[string]any) (Use, error) {
	name, ok := table["use"].(string)
	if !ok || name == "" {
		return Use{}, fmt.Errorf("%s: %s.use is missing or not a name", file, key)
	}
	delete(table, "use")
	return Use{Name: name, Options: table}, nil
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
	err := decodeStrict(path, &raw, func(parent toml.Key) []string {
		switch {
		case len(parent) == 1: // inside a role
			return []string{"network", "model", "memory", "max_processes", "cost", "options"}
		case len(parent) == 2 && parent[1] == "cost":
			return []string{"input", "output", "cacheRead", "cacheWrite"}
		}
		return nil // role names are checked below; options are the runtime's
	})
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s: no role is defined", path)
	}
	roles := make(map[string]Role, len(raw))
	for name, r := range raw {
		// Agent ids are derived from the role name, so it must be plain.
		if !roleName.MatchString(name) {
			return nil, fmt.Errorf("%s: role %q must match %s", path, name, roleName)
		}
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
		input, err := price(path, name, "input", r.Cost.Input)
		if err != nil {
			return nil, err
		}
		output, err := price(path, name, "output", r.Cost.Output)
		if err != nil {
			return nil, err
		}
		cacheRead, err := price(path, name, "cacheRead", r.Cost.CacheRead)
		if err != nil {
			return nil, err
		}
		cacheWrite, err := price(path, name, "cacheWrite", r.Cost.CacheWrite)
		if err != nil {
			return nil, err
		}
		roles[name] = Role{
			Name:    name,
			Network: r.Network,
			Model:   r.Model,
			Limits:  integration.Limits{Memory: r.Memory, MaxProcesses: r.MaxProcesses},
			Cost:    integration.Cost{Input: input, Output: output, CacheRead: cacheRead, CacheWrite: cacheWrite},
			Options: r.Options,
		}
	}
	return roles, nil
}

// price checks one cost number of a role: it must be set, finite and not negative.
func price(file, role, key string, v *float64) (float64, error) {
	if v == nil {
		return 0, fmt.Errorf("%s: %s.cost.%s is missing", file, role, key)
	}
	if math.IsNaN(*v) || math.IsInf(*v, 0) || *v < 0 {
		return 0, fmt.Errorf("%s: %s.cost.%s is %v, want a finite number of 0 or more", file, role, key, *v)
	}
	return *v, nil
}

// decodeStrict reads the TOML file at path into v and refuses every key that
// is not spelt exactly as the schema says. The decoder alone would accept
// KEY_FILE for key_file. allowed returns the exact names permitted inside
// the table parent, or nil when anything may be there.
func decodeStrict(path string, v any, allowed func(parent toml.Key) []string) error {
	md, err := toml.DecodeFile(path, v)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	for _, key := range md.Keys() {
		parent, name := key[:len(key)-1], key[len(key)-1]
		if names := allowed(parent); names != nil && !slices.Contains(names, name) {
			return fmt.Errorf("%s: unknown key %s", path, key)
		}
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
	// Refuse ".." rather than resolve it, so that a path says where it goes.
	if slices.Contains(strings.Split(value, "/"), "..") {
		return "", fmt.Errorf("%s: %s %q must not contain ..", file, key, value)
	}
	return path.Clean(value), nil
}
