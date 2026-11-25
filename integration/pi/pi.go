// Package pi runs the coding agent pi in its RPC mode: corral writes one JSON
// command per line to its stdin and reads one JSON record per line from its
// stdout. Importing the package registers the runtime under the name "pi".
//
// The runtime takes two options from the configuration file:
//
//	binary   the absolute path of the pi executable (required)
//	headers  a table of extra request headers for the model provider
//
// and two from the role: "thinking" (a thinking level) and "tools" (a list of
// tool names).
package pi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/txber/corral/integration"
)

func init() {
	integration.RegisterRuntime("pi", newProgram)
}

// maxText is how many characters of a text taken from pi's output go into
// the log.
const maxText = 200

// thinkingLevels are the levels pi's --thinking accepts.
var thinkingLevels = []string{"off", "minimal", "low", "medium", "high", "xhigh", "max"}

// program is the pi runtime built from one configuration.
type program struct {
	binary  string
	headers map[string]string // nil when the option is not given
}

// newProgram builds the runtime from the options of the configuration file,
// refusing any key it does not know and any value of the wrong type.
func newProgram(options map[string]any) (integration.Runtime, error) {
	p := &program{}
	for _, key := range sortedKeys(options) {
		switch value := options[key]; key {
		case "binary":
			binary, ok := value.(string)
			if !ok || !filepath.IsAbs(binary) {
				return nil, fmt.Errorf("pi: option binary must be an absolute path, got %v", value)
			}
			p.binary = filepath.Clean(binary)
		case "headers":
			table, ok := value.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("pi: option headers must be a table of strings, got %T", value)
			}
			p.headers = map[string]string{}
			for _, name := range sortedKeys(table) {
				text, ok := table[name].(string)
				if !ok {
					return nil, fmt.Errorf("pi: option headers.%s must be a string, got %T", name, table[name])
				}
				// pi would run a command for a value that starts with "!" and
				// read a variable for one that starts with "$"; this option
				// is for literal text only.
				if strings.HasPrefix(text, "!") || strings.HasPrefix(text, "$") {
					return nil, fmt.Errorf("pi: option headers.%s must be literal text, not start with ! or $", name)
				}
				p.headers[name] = text
			}
		default:
			return nil, fmt.Errorf("pi: unknown option %q", key)
		}
	}
	if p.binary == "" {
		return nil, fmt.Errorf("pi: option binary is required")
	}
	return p, nil
}

// sortedKeys returns the keys of m in order, so that errors do not depend
// on map order.
func sortedKeys(m map[string]any) []string {
	return slices.Sorted(maps.Keys(m))
}

// roleOptions reads the role options pi uses: a thinking level and a list of
// tools, each empty when not given. Any other key is refused, so that a typo
// is not ignored.
func roleOptions(options map[string]any) (thinking string, tools []string, err error) {
	for _, key := range sortedKeys(options) {
		if key != "thinking" && key != "tools" {
			return "", nil, fmt.Errorf("pi: unknown role option %q", key)
		}
	}
	if value, ok := options["thinking"]; ok {
		thinking, _ = value.(string)
		if !slices.Contains(thinkingLevels, thinking) {
			return "", nil, fmt.Errorf("pi: role option thinking must be one of %s, got %v",
				strings.Join(thinkingLevels, ", "), value)
		}
	}
	if value, ok := options["tools"]; ok {
		// A TOML array arrives as []any; a list built in Go may be []string.
		var list []any
		switch v := value.(type) {
		case []any:
			list = v
		case []string:
			for _, s := range v {
				list = append(list, s)
			}
		default:
			return "", nil, fmt.Errorf("pi: role option tools must be a list of tool names, got %T", value)
		}
		if len(list) == 0 {
			return "", nil, fmt.Errorf("pi: role option tools must name at least one tool")
		}
		for _, item := range list {
			name, ok := item.(string)
			// pi takes the tools as one comma-separated argument, and a name
			// that starts with "-" would be read as an option.
			if !ok || name == "" || strings.HasPrefix(name, "-") || strings.Contains(name, ",") {
				return "", nil, fmt.Errorf("pi: role option tools holds a bad tool name %v", item)
			}
			tools = append(tools, name)
		}
	}
	return thinking, tools, nil
}

// The parts of models.json that corral writes.
type (
	modelsFile struct {
		Providers map[string]provider `json:"providers"`
	}
	provider struct {
		BaseURL string            `json:"baseUrl"`
		APIKey  string            `json:"apiKey"`
		API     string            `json:"api"`
		Headers map[string]string `json:"headers,omitempty"`
		Models  []model           `json:"models"`
	}
	model struct {
		ID        string `json:"id"`
		Reasoning bool   `json:"reasoning"`
		Cost      cost   `json:"cost"`
	}
	cost struct {
		Input      float64 `json:"input"`
		Output     float64 `json:"output"`
		CacheRead  float64 `json:"cacheRead"`
		CacheWrite float64 `json:"cacheWrite"`
	}
)

// Prepare checks the role options and sets up the folders pi uses. Its
// configuration, <ShareDir>/pi/models.json with the one provider "gateway",
// goes where the agent can read but not change it, because it names the
// model and its price. Home, temporary files and the session transcript go
// below the working folder. Corral calls Prepare before Command and Env.
func (p *program) Prepare(a integration.Agent) error {
	thinking, _, err := roleOptions(a.Options)
	if err != nil {
		return err
	}
	if a.Model == "" || a.GatewayURL == "" {
		return fmt.Errorf("pi: agent %s has no model or no gateway address", a.ID)
	}
	// The model name follows --model; one that starts with "-" would be read
	// as an option.
	if strings.HasPrefix(a.Model, "-") {
		return fmt.Errorf("pi: model name %q must not start with -", a.Model)
	}
	if a.ShareDir == "" || a.Workdir == "" {
		return fmt.Errorf("pi: agent %s has no share folder or no working folder", a.ID)
	}
	// The agent can write the working folder and may have left symbolic
	// links there from an earlier run, so every folder is made through an
	// os.Root, which refuses a path that leaves it, and must be a plain
	// folder before its mode is set.
	work, err := os.OpenRoot(a.Workdir)
	if err != nil {
		return fmt.Errorf("pi: %w", err)
	}
	defer work.Close()
	for _, name := range []string{".home", ".tmp", ".sessions"} {
		if err := privateDir(work, name); err != nil {
			return err
		}
	}
	share, err := os.OpenRoot(a.ShareDir)
	if err != nil {
		return fmt.Errorf("pi: %w", err)
	}
	defer share.Close()
	if err := privateDir(share, "pi"); err != nil {
		return err
	}
	doc := modelsFile{Providers: map[string]provider{
		"gateway": {
			BaseURL: a.GatewayURL,
			// pi reads the key from the environment when it starts; the
			// token itself never goes into a file.
			APIKey:  "$" + integration.TokenEnv,
			API:     "openai-completions",
			Headers: p.headers,
			Models: []model{{
				ID:        a.Model,
				Reasoning: thinking != "" && thinking != "off",
				Cost:      cost{a.Cost.Input, a.Cost.Output, a.Cost.CacheRead, a.Cost.CacheWrite},
			}},
		},
	}}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("pi: models.json: %w", err)
	}
	return writeNew(share, filepath.Join("pi", "models.json"), append(data, '\n'))
}

// privateDir makes name below root a plain folder with mode 700, creating it
// if needed and refusing a symbolic link or anything else in its place.
func privateDir(root *os.Root, name string) error {
	path := filepath.Join(root.Name(), name)
	if err := root.Mkdir(name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("pi: %w", err)
	}
	info, err := root.Lstat(name)
	if err != nil {
		return fmt.Errorf("pi: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("pi: %s is not a plain folder", path)
	}
	// Mkdir leaves the mode of a folder that already exists alone.
	if err := root.Chmod(name, 0o700); err != nil {
		return fmt.Errorf("pi: %w", err)
	}
	return nil
}

// writeNew writes data to a new file name below root with mode 600. Whatever
// was there before is removed first, so a symbolic link is replaced and
// never written through.
func writeNew(root *os.Root, name string, data []byte) error {
	if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("pi: %w", err)
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("pi: %w", err)
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("pi: %s: %w", name, err)
	}
	return nil
}

// Command returns pi's command line in RPC mode with everything switched off
// that would load code, prompts or context from outside the configuration:
// extensions, skills, prompt templates, context files, MCP and project-local
// resources. Command cannot fail: it relies on Prepare, called first, having
// refused bad role options.
func (p *program) Command(a integration.Agent) []string {
	argv := []string{
		p.binary, "--mode", "rpc", "--offline",
		"-ne", "-ns", "-np", "-nc", "--no-mcp", "--no-approve",
		"--session-dir", filepath.Join(a.Workdir, ".sessions"),
		"--provider", "gateway", "--model", a.Model,
	}
	thinking, tools, _ := roleOptions(a.Options)
	if thinking != "" {
		argv = append(argv, "--thinking", thinking)
	}
	if len(tools) > 0 {
		argv = append(argv, "--tools", strings.Join(tools, ","))
	}
	return argv
}

// Env returns pi's whole environment. The token is set only when corral has
// one; in network mode "none" the sandbox sets it.
func (p *program) Env(a integration.Agent) []string {
	env := []string{
		"PI_CODING_AGENT_DIR=" + filepath.Join(a.ShareDir, "pi"),
		"PI_OFFLINE=1",
		"HOME=" + filepath.Join(a.Workdir, ".home"),
		"TMPDIR=" + filepath.Join(a.Workdir, ".tmp"),
		"PATH=/usr/local/bin:/usr/bin",
	}
	if a.GatewayToken != "" {
		env = append(env, integration.TokenEnv+"="+a.GatewayToken)
	}
	return env
}

// ReadPaths returns the folder that holds pi, which the sandbox must let it
// read.
func (p *program) ReadPaths() []string {
	return []string{filepath.Dir(p.binary)}
}

// Encode turns one corral operation into one line of pi's RPC protocol.
func (p *program) Encode(op, id string, args map[string]any) ([]byte, error) {
	var command map[string]any
	var err error
	switch op {
	case "prompt", "steer", "follow_up":
		command, err = withArgument(op, "message", args)
	case "exec":
		command, err = withArgument("bash", "command", args)
	case "abort":
		command, err = withArgument("abort", "", args)
	case "stats":
		command, err = withArgument("get_session_stats", "", args)
	default:
		return nil, fmt.Errorf("pi: %q: %w", op, integration.ErrUnsupported)
	}
	if err != nil {
		return nil, fmt.Errorf("pi: %s: %w", op, err)
	}
	if id != "" {
		command["id"] = id
	}
	// Marshal escapes LF, U+2028 and U+2029 inside strings, so the command
	// stays on one line.
	line, err := json.Marshal(command)
	if err != nil {
		return nil, fmt.Errorf("pi: %s: %w", op, err)
	}
	return append(line, '\n'), nil
}

// withArgument builds a command of the given type that takes exactly one
// string argument, name, or none when name is empty.
func withArgument(typ, name string, args map[string]any) (map[string]any, error) {
	command := map[string]any{"type": typ}
	if name == "" {
		if len(args) != 0 {
			return nil, fmt.Errorf("takes no arguments")
		}
		return command, nil
	}
	value, ok := args[name].(string)
	if !ok || len(args) != 1 {
		return nil, fmt.Errorf("takes exactly one argument, the string %q", name)
	}
	command[name] = value
	return command, nil
}

// passedOn are the record types logged under their own type with their
// plain (not nested) fields.
var passedOn = []string{
	"agent_start", "agent_end", "turn_start", "turn_end", "extension_error",
	"auto_retry_start", "auto_retry_end",
	"compaction_start", "compaction_end",
	"summarization_retry_scheduled", "summarization_retry_attempt_start", "summarization_retry_finished",
}

// streaming are the record types that only report progress; their final
// form arrives in another record, so they are not logged.
var streaming = []string{"message_start", "message_update", "tool_execution_update", "bash_execution_update"}

// maxFields is how many plain fields of one record are kept.
const maxFields = 32

// Decode turns one line of pi's output into a record for corral. The line
// comes from the agent and may be hostile: the record's Type is always one
// of the names in this file, and every field of an event is a cut string, a
// bool or a finite number.
func (p *program) Decode(line []byte) *integration.Record {
	var rec map[string]any
	if err := json.Unmarshal(line, &rec); err != nil || rec == nil {
		return &integration.Record{Kind: "garbage", Fields: map[string]any{"text": cut(string(line))}}
	}
	typ, _ := rec["type"].(string)
	// Below, typ is used as a Type only where it equals a name of a fixed list.
	switch {
	case typ == "agent_settled":
		return &integration.Record{Kind: "settled", Type: "agent_settled", Fields: plainFields(rec)}
	case typ == "response":
		return decodeResponse(rec)
	case typ == "message_end":
		return decodeMessageEnd(rec)
	case typ == "tool_execution_start" || typ == "tool_execution_end":
		return decodeTool(typ, rec)
	case slices.Contains(streaming, typ):
		return nil
	case slices.Contains(passedOn, typ):
		r := &integration.Record{Kind: "event", Type: typ, Fields: plainFields(rec)}
		if typ == "compaction_end" {
			// The model calls that wrote the summary.
			result, _ := rec["result"].(map[string]any)
			addUsage(r, result["usage"])
		}
		return r
	default:
		return &integration.Record{Kind: "event", Type: "other", Fields: map[string]any{"type": cut(typ)}}
	}
}

// decodeResponse returns pi's answer to one command. Its data goes back
// whole to whoever sent the command, so it is not cut.
func decodeResponse(rec map[string]any) *integration.Record {
	id, _ := rec["id"].(string)
	ok, _ := rec["success"].(bool)
	fields := map[string]any{}
	if data, has := rec["data"]; has && data != nil {
		fields["data"] = data
	}
	if text, isText := rec["error"].(string); isText {
		fields["error"] = text
	}
	return &integration.Record{Kind: "response", Type: "response", ID: id, OK: ok, Fields: fields}
}

// decodeMessageEnd returns a finished message as its role, how it ended and
// what it cost; the content stays in pi's session.
func decodeMessageEnd(rec map[string]any) *integration.Record {
	msg, _ := rec["message"].(map[string]any)
	fields := map[string]any{}
	for _, key := range []string{"role", "stopReason", "errorMessage"} {
		if text, ok := msg[key].(string); ok {
			fields[key] = cut(text)
		}
	}
	r := &integration.Record{Kind: "event", Type: "message_end", Fields: fields}
	addUsage(r, msg["usage"])
	return r
}

// decodeTool returns the start or end of one tool call with the tool's name
// and its arguments cut short; the result stays in pi's session.
func decodeTool(typ string, rec map[string]any) *integration.Record {
	fields := map[string]any{}
	for _, key := range []string{"toolCallId", "toolName"} {
		if text, ok := rec[key].(string); ok {
			fields[key] = cut(text)
		}
	}
	if isError, ok := rec["isError"].(bool); ok {
		fields["isError"] = isError
	}
	if ms, ok := rec["durationMs"].(float64); ok && ms >= 0 && !math.IsInf(ms, 0) {
		fields["durationMs"] = ms
	}
	if args, ok := rec["args"]; ok {
		text, _ := json.Marshal(args) // it came from JSON, so it goes back
		fields["args"] = cut(string(text))
	}
	return &integration.Record{Kind: "event", Type: typ, Fields: fields}
}

// plainFields returns the strings, numbers and booleans of a record except
// its type, leaving out nested messages and results. It keeps the first
// maxFields of them in key order and marks the record "truncated" when it
// left some out.
func plainFields(rec map[string]any) map[string]any {
	fields := map[string]any{}
	kept := 0
	for _, key := range sortedKeys(rec) {
		var value any
		switch v := rec[key].(type) {
		case string:
			if key == "type" {
				continue
			}
			value = cut(v)
		case float64, bool: // a JSON number is always finite
			value = v
		default:
			continue
		}
		if kept == maxFields {
			fields["truncated"] = true
			break
		}
		fields[cut(key)] = value
		kept++
	}
	return fields
}

// Bounds on the usage that corral accepts; a token count above 1<<53 cannot
// be held exactly in a JSON number.
const (
	maxTokens = 1 << 53
	maxCost   = 1e9
)

// addUsage puts pi's Usage object on r. The numbers come from the agent and
// feed corral's spend totals, so a usage is refused, and the record marked
// "usage_refused", unless every count is a whole number from 0 to maxTokens
// and the cost a number from 0 to maxCost. A missing number counts as 0.
func addUsage(r *integration.Record, value any) {
	if value == nil {
		return
	}
	u, refused := readUsage(value)
	if refused {
		r.Fields["usage_refused"] = true
		return
	}
	r.Usage = u
}

// readUsage reads a Usage object, or reports it refused.
func readUsage(value any) (u *integration.Usage, refused bool) {
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, true
	}
	counts := make([]int64, 4)
	for i, key := range []string{"input", "output", "cacheRead", "cacheWrite"} {
		n, ok := number(obj, key, maxTokens)
		if !ok || n != math.Trunc(n) {
			return nil, true
		}
		counts[i] = int64(n)
	}
	total := 0.0
	if c, has := obj["cost"]; has {
		costs, ok := c.(map[string]any)
		if !ok {
			return nil, true
		}
		if total, ok = number(costs, "total", maxCost); !ok {
			return nil, true
		}
	}
	return &integration.Usage{
		Input: counts[0], Output: counts[1], CacheRead: counts[2], CacheWrite: counts[3],
		Cost: total,
	}, false
}

// number returns obj[key] if it is a number from 0 to limit, and 0 if it is
// missing.
func number(obj map[string]any, key string, limit float64) (float64, bool) {
	value, has := obj[key]
	if !has {
		return 0, true
	}
	n, ok := value.(float64)
	if !ok || math.IsNaN(n) || n < 0 || n > limit {
		return 0, false
	}
	return n, true
}

// cut returns the first maxText characters of s, with every control
// character replaced by U+FFFD so that nothing printing the text can be
// steered by it. It looks at no more than the bytes maxText characters can
// take, and never splits a character.
func cut(s string) string {
	if limit := maxText * utf8.UTFMax; len(s) > limit {
		for limit > 0 && !utf8.RuneStart(s[limit]) {
			limit--
		}
		s = s[:limit]
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == maxText {
			break
		}
		if unicode.IsControl(r) {
			r = utf8.RuneError
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
