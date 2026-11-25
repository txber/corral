// Package config reads corral's two configuration files: corral.toml (the
// model gateway, the paths corral uses, how many agents may run and which
// integrations serve as sandbox, runtime and key proxy) and roles.toml (the
// kinds of agent a job may start). Both are read strictly: an unknown key is
// an error, a name, path or address must be plain text, and every error names
// the key at fault.
package config

import (
	"fmt"
	"math"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

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
	if err := decodeStrict(path, &raw, configKeys); err != nil {
		return Config{}, err
	}

	if raw.MaxAgents < 1 || raw.MaxAgents > 250 {
		return Config{}, fmt.Errorf("%s: max_agents is %d, want 1 to 250", path, raw.MaxAgents)
	}

	g := raw.Gateway
	if !gatewayName.MatchString(g.Name) {
		return Config{}, fmt.Errorf("%s: gateway.name %s must match %s", path, quote(g.Name), gatewayName)
	}
	// The upstream is written into files and logs as it is, so it must carry
	// no credentials (the key comes from key_file), and it must read the same
	// to a program that only compares its text.
	u, err := url.Parse(g.Upstream)
	if !strings.HasPrefix(g.Upstream, "https://") || !plainWord(g.Upstream) ||
		err != nil || u.Host == "" || u.User != nil || strings.ContainsAny(g.Upstream, "?#") {
		return Config{}, fmt.Errorf("%s: gateway.upstream %s must begin with https://, have a host and hold no user, query, fragment, white space or control character", path, quote(g.Upstream))
	}
	if len(g.Endpoints) == 0 {
		return Config{}, fmt.Errorf("%s: gateway.endpoints is empty", path)
	}
	var endpoints []integration.Endpoint
	for _, e := range g.Endpoints {
		method, p, ok := strings.Cut(e, " ")
		if !ok || !httpMethod.MatchString(method) || !strings.HasPrefix(p, "/") || !plainWord(p) {
			return Config{}, fmt.Errorf("%s: gateway.endpoints entry %s must be <METHOD> <path>, the path without white space or control characters", path, quote(e))
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
	if err := checkText(file, key+".use", name); err != nil {
		return Use{}, err
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
	Options any // checked to be a table: a map field would drop anything else
}

// LoadRoles reads and checks roles.toml.
func LoadRoles(path string) (map[string]Role, error) {
	var raw map[string]rawRole
	if err := decodeStrict(path, &raw, roleKeys); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s: no role is defined", path)
	}
	roles := make(map[string]Role, len(raw))
	for name, r := range raw {
		// Agent ids are derived from the role name, so it must be plain.
		if !roleName.MatchString(name) {
			return nil, fmt.Errorf("%s: role %s must match %s", path, quote(name), roleName)
		}
		switch r.Network {
		case "direct", "proxy", "none":
		default:
			return nil, fmt.Errorf("%s: %s.network is %s, want \"direct\", \"proxy\" or \"none\"", path, name, quote(r.Network))
		}
		if r.Model == "" {
			return nil, fmt.Errorf("%s: %s.model is missing", path, name)
		}
		if err := checkText(path, name+".model", r.Model); err != nil {
			return nil, err
		}
		if err := checkText(path, name+".memory", r.Memory); err != nil {
			return nil, err
		}
		if r.MaxProcesses < 0 {
			return nil, fmt.Errorf("%s: %s.max_processes is negative", path, name)
		}
		options, ok := r.Options.(map[string]any)
		if r.Options != nil && !ok {
			return nil, fmt.Errorf("%s: %s.options must be a table", path, name)
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
			Options: options,
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

// configKeys returns the names allowed inside the table parent of
// corral.toml, or nil when any name may be there.
func configKeys(parent toml.Key) []string {
	switch parent.String() {
	case "":
		return []string{"max_agents", "gateway", "paths", "sandbox", "runtime", "key_proxy"}
	case "gateway":
		return []string{"name", "upstream", "endpoints", "key_file"}
	case "paths":
		return []string{"state", "run", "work", "roles", "helper"}
	}
	return nil // the options of an integration are not ours to check
}

// roleKeys returns the names allowed inside the table parent of roles.toml,
// or nil when any name may be there.
func roleKeys(parent toml.Key) []string {
	switch {
	case len(parent) == 1: // inside a role
		return []string{"network", "model", "memory", "max_processes", "cost", "options"}
	case len(parent) == 2 && parent[1] == "cost":
		return []string{"input", "output", "cacheRead", "cacheWrite"}
	}
	return nil // role names are checked by LoadRoles; options are the runtime's
}

// decodeStrict reads the TOML file at path into v and refuses every key that
// is not spelt exactly as the schema says. The decoder alone would accept
// KEY_FILE for key_file. allowed returns the exact names permitted inside
// the table parent, or nil when any name may be there. Every name in every
// key must also be plain text, as the names of options are handed on.
func decodeStrict(path string, v any, allowed func(parent toml.Key) []string) error {
	md, err := toml.DecodeFile(path, v)
	// The keys are checked before a decoding error is returned, so that
	// NAME.x = 1 is named as the unknown key it is, not as a table where a
	// string was expected. After a syntax error there are no keys.
	for _, key := range md.Keys() {
		if err := checkText(path, "key", strings.Join(key, ".")); err != nil {
			return err
		}
		// A dotted key such as PATHS.helper names its tables only through
		// the key itself, so each part is checked, not only the last.
		for i, name := range key {
			if names := allowed(key[:i]); names != nil && !slices.Contains(names, name) {
				return fmt.Errorf("%s: unknown key %s", path, key)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}

// checkText refuses a value that is not valid UTF-8 or holds a control
// character: such a value changes, or changes its meaning, when it is
// written into JSON, a command line or a log line.
func checkText(file, key, value string) error {
	if !utf8.ValidString(value) || strings.ContainsFunc(value, unicode.IsControl) {
		return fmt.Errorf("%s: %s %s must be valid UTF-8 without control characters", file, key, quote(value))
	}
	return nil
}

// plainWord reports whether s is valid UTF-8 without white space or control
// characters.
func plainWord(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	})
}

// quote quotes value for an error message, cut to its first 80 characters,
// so that a long value cannot flood a log.
func quote(value string) string {
	n := 0
	for i := range value {
		if n == 80 {
			return strconv.Quote(value[:i]) + "…"
		}
		n++
	}
	return strconv.Quote(value)
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
	if err := checkText(file, key, value); err != nil {
		return "", err
	}
	if value == "~" || strings.HasPrefix(value, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("%s: %s: expand ~: %w", file, key, err)
		}
		value = home + value[1:]
	}
	if !strings.HasPrefix(value, "/") {
		return "", fmt.Errorf("%s: %s %s must be an absolute path", file, key, quote(value))
	}
	// Refuse ".." rather than resolve it, so that a path says where it goes.
	if slices.Contains(strings.Split(value, "/"), "..") {
		return "", fmt.Errorf("%s: %s %s must not contain ..", file, key, quote(value))
	}
	return path.Clean(value), nil
}
