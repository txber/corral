package pi

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/txber/corral/integration"
)

const testBinary = "/opt/pi/bin/pi"

// newTestRuntime builds the runtime through the registry, as corral does.
func newTestRuntime(t *testing.T, options map[string]any) integration.Runtime {
	t.Helper()
	if options == nil {
		options = map[string]any{"binary": testBinary}
	}
	rt, err := integration.NewRuntime("pi", options)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	return rt
}

// testAgent is an agent in network mode "direct" with a stand-in token.
func testAgent(t *testing.T) integration.Agent {
	t.Helper()
	return integration.Agent{
		ID:           "a1",
		Role:         "worker",
		Network:      "direct",
		Model:        "example-model",
		Options:      map[string]any{},
		Cost:         integration.Cost{Input: 1.5, Output: 4.5, CacheRead: 0.3, CacheWrite: 0},
		Workdir:      "/home/you/work/a1",
		StateDir:     t.TempDir(),
		GatewayURL:   "http://198.18.7.1:18007/example",
		GatewayToken: "stand-in-token-7f3a",
	}
}

// readModels runs Prepare and returns models.json, raw and decoded.
func readModels(t *testing.T, rt integration.Runtime, a integration.Agent) ([]byte, map[string]any) {
	t.Helper()
	if err := rt.Prepare(a); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(a.StateDir, "pi", "models.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("models.json is not JSON: %v", err)
	}
	return data, doc
}

// gatewayProvider returns providers.gateway from a decoded models.json.
func gatewayProvider(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	providers, _ := doc["providers"].(map[string]any)
	p, ok := providers["gateway"].(map[string]any)
	if !ok || len(providers) != 1 {
		t.Fatalf("providers = %v, want exactly one provider \"gateway\"", doc["providers"])
	}
	return p
}

func TestRegisteredAsPi(t *testing.T) {
	newTestRuntime(t, map[string]any{"binary": testBinary})
}

func TestOptionsAreChecked(t *testing.T) {
	tests := []struct {
		name    string
		options map[string]any
		word    string // the error must name this
	}{
		{"missing binary", map[string]any{}, "binary"},
		{"relative binary", map[string]any{"binary": "bin/pi"}, "binary"},
		{"binary not a string", map[string]any{"binary": 7}, "binary"},
		{"unknown key", map[string]any{"binary": testBinary, "colour": "red"}, "colour"},
		{"headers not a table", map[string]any{"binary": testBinary, "headers": "x"}, "headers"},
		{"header value not a string", map[string]any{"binary": testBinary, "headers": map[string]any{"X-Team": 3}}, "X-Team"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := integration.NewRuntime("pi", tt.options)
			if err == nil {
				t.Fatal("NewRuntime accepted the options")
			}
			if !strings.Contains(err.Error(), tt.word) {
				t.Errorf("error %q does not name %q", err, tt.word)
			}
		})
	}
}

func TestModelsJSONPointsAtTheAgentsGateway(t *testing.T) {
	rt := newTestRuntime(t, nil)
	a := testAgent(t)
	_, doc := readModels(t, rt, a)
	p := gatewayProvider(t, doc)
	if p["baseUrl"] != a.GatewayURL {
		t.Errorf("baseUrl = %v, want %v", p["baseUrl"], a.GatewayURL)
	}
	if p["apiKey"] != "$"+integration.TokenEnv {
		t.Errorf("apiKey = %v, want $%s", p["apiKey"], integration.TokenEnv)
	}
	if p["api"] != "openai-completions" {
		t.Errorf("api = %v, want openai-completions", p["api"])
	}
	if _, ok := p["headers"]; ok {
		t.Errorf("headers = %v, want none without the option", p["headers"])
	}
	models, _ := p["models"].([]any)
	if len(models) != 1 {
		t.Fatalf("models = %v, want one", p["models"])
	}
	m, _ := models[0].(map[string]any)
	if m["id"] != "example-model" {
		t.Errorf("model id = %v, want example-model", m["id"])
	}
	if m["reasoning"] != false {
		t.Errorf("reasoning = %v, want false without a thinking option", m["reasoning"])
	}
	wantCost := map[string]any{"input": 1.5, "output": 4.5, "cacheRead": 0.3, "cacheWrite": 0.0}
	cost, _ := m["cost"].(map[string]any)
	for k, want := range wantCost {
		if cost[k] != want {
			t.Errorf("cost.%s = %v, want %v", k, cost[k], want)
		}
	}
}

func TestModelsJSONCarriesTheHeaders(t *testing.T) {
	rt := newTestRuntime(t, map[string]any{"binary": testBinary, "headers": map[string]any{"X-Team": "blue"}})
	_, doc := readModels(t, rt, testAgent(t))
	headers, _ := gatewayProvider(t, doc)["headers"].(map[string]any)
	if len(headers) != 1 || headers["X-Team"] != "blue" {
		t.Errorf("headers = %v, want X-Team: blue", headers)
	}
}

func TestModelsJSONMarksAThinkingModelAsReasoning(t *testing.T) {
	rt := newTestRuntime(t, nil)
	a := testAgent(t)
	a.Options = map[string]any{"thinking": "medium"}
	_, doc := readModels(t, rt, a)
	m := gatewayProvider(t, doc)["models"].([]any)[0].(map[string]any)
	if m["reasoning"] != true {
		t.Errorf("reasoning = %v, want true", m["reasoning"])
	}
}

func TestModelsJSONNeverHoldsTheToken(t *testing.T) {
	rt := newTestRuntime(t, nil)
	a := testAgent(t)
	data, _ := readModels(t, rt, a)
	if strings.Contains(string(data), a.GatewayToken) {
		t.Errorf("models.json holds the token:\n%s", data)
	}
}

func TestPrepareKeepsItsFilesPrivate(t *testing.T) {
	rt := newTestRuntime(t, nil)
	a := testAgent(t)
	if err := rt.Prepare(a); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	modes := map[string]os.FileMode{
		filepath.Join(a.StateDir, "pi"):                os.ModeDir | 0o700,
		filepath.Join(a.StateDir, "sessions"):          os.ModeDir | 0o700,
		filepath.Join(a.StateDir, "pi", "models.json"): 0o600,
	}
	for path, want := range modes {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode(); got != want {
			t.Errorf("%s: mode %v, want %v", path, got, want)
		}
	}
}

func TestPrepareRefusesBadRoleOptions(t *testing.T) {
	tests := []struct {
		name    string
		options map[string]any
		word    string
	}{
		{"thinking not a string", map[string]any{"thinking": true}, "thinking"},
		{"unknown thinking level", map[string]any{"thinking": "extreme"}, "thinking"},
		{"tools not a list", map[string]any{"tools": "read"}, "tools"},
		{"tool not a string", map[string]any{"tools": []any{"read", 2}}, "tools"},
		{"tool with a comma", map[string]any{"tools": []any{"read,bash"}}, "tools"},
		{"no tools", map[string]any{"tools": []any{}}, "tools"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := newTestRuntime(t, nil)
			a := testAgent(t)
			a.Options = tt.options
			err := rt.Prepare(a)
			if err == nil {
				t.Fatal("Prepare accepted the options")
			}
			if !strings.Contains(err.Error(), tt.word) {
				t.Errorf("error %q does not name %q", err, tt.word)
			}
		})
	}
}

func TestCommandHasEveryLockdownFlag(t *testing.T) {
	rt := newTestRuntime(t, nil)
	a := testAgent(t)
	got := rt.Command(a)
	want := []string{
		testBinary, "--mode", "rpc", "--offline", "-ne", "-ns", "-np", "-nc", "--no-mcp", "--no-approve",
		"--session-dir", filepath.Join(a.StateDir, "sessions"),
		"--provider", "gateway", "--model", "example-model",
	}
	if !slices.Equal(got, want) {
		t.Errorf("Command =\n%q\nwant\n%q", got, want)
	}
}

func TestCommandAddsThinkingAndToolsFromTheRoleOptions(t *testing.T) {
	rt := newTestRuntime(t, nil)
	a := testAgent(t)
	a.Options = map[string]any{"thinking": "high", "tools": []any{"read", "bash", "ls"}}
	got := rt.Command(a)
	tail := []string{"--thinking", "high", "--tools", "read,bash,ls"}
	if !slices.Equal(got[len(got)-4:], tail) {
		t.Errorf("Command = %q, want it to end with %q", got, tail)
	}
}

func TestEnvironment(t *testing.T) {
	rt := newTestRuntime(t, nil)
	a := testAgent(t)
	want := []string{
		"PI_CODING_AGENT_DIR=" + filepath.Join(a.StateDir, "pi"),
		"PI_OFFLINE=1",
		"HOME=/home/you/work/a1/.home",
		"TMPDIR=/home/you/work/a1/.tmp",
		"PATH=/usr/local/bin:/usr/bin",
		"CORRAL_GATEWAY_TOKEN=stand-in-token-7f3a",
	}
	if got := rt.Env(a); !slices.Equal(got, want) {
		t.Errorf("Env =\n%q\nwant\n%q", got, want)
	}
}

func TestTheTokenIsInTheEnvironmentAndNotInTheCommand(t *testing.T) {
	rt := newTestRuntime(t, nil)
	a := testAgent(t)
	a.Options = map[string]any{"thinking": "low", "tools": []any{"read"}}
	if !slices.Contains(rt.Env(a), integration.TokenEnv+"="+a.GatewayToken) {
		t.Errorf("Env does not hold the token")
	}
	for _, arg := range rt.Command(a) {
		if strings.Contains(arg, a.GatewayToken) {
			t.Errorf("Command holds the token in %q", arg)
		}
	}
}

func TestEnvLeavesTheTokenToTheSandboxWhenItIsEmpty(t *testing.T) {
	rt := newTestRuntime(t, nil)
	a := testAgent(t)
	a.Network = "none"
	a.GatewayToken = ""
	for _, kv := range rt.Env(a) {
		if strings.HasPrefix(kv, integration.TokenEnv+"=") {
			t.Errorf("Env sets %q, want the variable left to the sandbox", kv)
		}
	}
}

func TestReadPathsIsTheBinaryFolder(t *testing.T) {
	rt := newTestRuntime(t, nil)
	if got, want := rt.ReadPaths(), []string{"/opt/pi/bin"}; !slices.Equal(got, want) {
		t.Errorf("ReadPaths = %q, want %q", got, want)
	}
}

func TestEncode(t *testing.T) {
	tests := []struct {
		op   string
		args map[string]any
		want map[string]any
	}{
		{"prompt", map[string]any{"message": "Hello"}, map[string]any{"id": "r1", "type": "prompt", "message": "Hello"}},
		{"steer", map[string]any{"message": "Stop"}, map[string]any{"id": "r1", "type": "steer", "message": "Stop"}},
		{"follow_up", map[string]any{"message": "Then"}, map[string]any{"id": "r1", "type": "follow_up", "message": "Then"}},
		{"abort", nil, map[string]any{"id": "r1", "type": "abort"}},
		{"exec", map[string]any{"command": "ls -la"}, map[string]any{"id": "r1", "type": "bash", "command": "ls -la"}},
		{"stats", nil, map[string]any{"id": "r1", "type": "get_session_stats"}},
	}
	rt := newTestRuntime(t, nil)
	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			line, err := rt.Encode(tt.op, "r1", tt.args)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if !strings.HasSuffix(string(line), "\n") || strings.Count(string(line), "\n") != 1 {
				t.Fatalf("Encode = %q, want one line ending in LF", line)
			}
			var got map[string]any
			if err := json.Unmarshal(line, &got); err != nil {
				t.Fatalf("Encode = %q: %v", line, err)
			}
			if len(got) != len(tt.want) {
				t.Errorf("Encode = %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("%s = %v, want %v", k, got[k], v)
				}
			}
		})
	}
}

func TestEncodeKeepsALineSeparatorOnOneLine(t *testing.T) {
	rt := newTestRuntime(t, nil)
	line, err := rt.Encode("prompt", "r1", map[string]any{"message": "one\ntwo three"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(line), "\n") != 1 || strings.ContainsRune(string(line), ' ') {
		t.Errorf("Encode = %q, want the breaks escaped", line)
	}
}

func TestEncodeUnknownOperationIsUnsupported(t *testing.T) {
	rt := newTestRuntime(t, nil)
	_, err := rt.Encode("compact", "r1", nil)
	if !errors.Is(err, integration.ErrUnsupported) {
		t.Errorf("Encode(compact) error = %v, want ErrUnsupported", err)
	}
}

func TestEncodeRefusesWrongArguments(t *testing.T) {
	tests := []struct {
		name string
		op   string
		args map[string]any
	}{
		{"missing message", "prompt", nil},
		{"message not a string", "steer", map[string]any{"message": 3}},
		{"extra argument", "prompt", map[string]any{"message": "x", "images": "y"}},
		{"missing command", "exec", map[string]any{"message": "ls"}},
		{"argument to abort", "abort", map[string]any{"now": true}},
	}
	rt := newTestRuntime(t, nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if line, err := rt.Encode(tt.op, "r1", tt.args); err == nil {
				t.Errorf("Encode = %q, want an error", line)
			}
		})
	}
}

// decode builds a runtime and decodes one line.
func decode(t *testing.T, line string) *integration.Record {
	t.Helper()
	return newTestRuntime(t, nil).Decode([]byte(line))
}

// The fixtures below are the examples of pi's JSON event stream and RPC
// command references. The assistant message_end is put together from the
// documented AssistantMessage and Usage types, because the reference shows
// it only in shortened form.

func TestDecodeMessageEndKeepsUsageAndCost(t *testing.T) {
	line := `{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"Hello"}],"api":"openai-completions","provider":"gateway","model":"example-model","usage":{"input":100,"output":20,"cacheRead":40,"cacheWrite":5,"totalTokens":165,"cost":{"input":0.00015,"output":0.00009,"cacheRead":0.000012,"cacheWrite":0,"total":0.000252}},"stopReason":"error","errorMessage":"429 rate limited","timestamp":1733234401000}}`
	r := decode(t, line)
	if r == nil || r.Kind != "event" || r.Type != "message_end" {
		t.Fatalf("Decode = %+v, want event message_end", r)
	}
	want := map[string]any{"role": "assistant", "stopReason": "error", "errorMessage": "429 rate limited"}
	if len(r.Fields) != len(want) {
		t.Errorf("Fields = %v, want %v", r.Fields, want)
	}
	for k, v := range want {
		if r.Fields[k] != v {
			t.Errorf("%s = %v, want %v", k, r.Fields[k], v)
		}
	}
	wantUsage := integration.Usage{Input: 100, Output: 20, CacheRead: 40, CacheWrite: 5, Cost: 0.000252}
	if r.Usage == nil || *r.Usage != wantUsage {
		t.Errorf("Usage = %+v, want %+v", r.Usage, wantUsage)
	}
}

func TestDecodeUserMessageEndHasNoUsage(t *testing.T) {
	r := decode(t, `{"type":"message_end","message":{"role":"user","content":"Review this repository","timestamp":1733234401000}}`)
	if r == nil || r.Type != "message_end" || r.Fields["role"] != "user" || r.Usage != nil {
		t.Errorf("Decode = %+v, want message_end of role user without usage", r)
	}
}

func TestDecodeToolExecutionStart(t *testing.T) {
	r := decode(t, `{"type":"tool_execution_start","toolCallId":"call_abc123","toolName":"bash","args":{"command":"ls -la"}}`)
	if r == nil || r.Kind != "event" || r.Type != "tool_execution_start" {
		t.Fatalf("Decode = %+v, want event tool_execution_start", r)
	}
	want := map[string]any{"toolCallId": "call_abc123", "toolName": "bash", "args": `{"command":"ls -la"}`}
	if len(r.Fields) != len(want) {
		t.Errorf("Fields = %v, want %v", r.Fields, want)
	}
	for k, v := range want {
		if r.Fields[k] != v {
			t.Errorf("%s = %v, want %v", k, r.Fields[k], v)
		}
	}
}

func TestDecodeToolArgumentsAreCutTo200Characters(t *testing.T) {
	long := strings.Repeat("é", 500)
	r := decode(t, `{"type":"tool_execution_start","toolCallId":"c1","toolName":"write","args":{"content":"`+long+`"}}`)
	args, _ := r.Fields["args"].(string)
	if n := utf8.RuneCountInString(args); n != 200 || !utf8.ValidString(args) {
		t.Errorf("args has %d characters (valid UTF-8: %v), want 200", n, utf8.ValidString(args))
	}
}

func TestDecodeToolExecutionEnd(t *testing.T) {
	r := decode(t, `{"type":"tool_execution_end","toolCallId":"call_abc123","toolName":"bash","result":{"content":[{"type":"text","text":"complete output"}],"details":{}},"isError":false,"durationMs":42}`)
	if r == nil || r.Type != "tool_execution_end" {
		t.Fatalf("Decode = %+v, want event tool_execution_end", r)
	}
	want := map[string]any{"toolCallId": "call_abc123", "toolName": "bash", "isError": false, "durationMs": 42.0}
	if len(r.Fields) != len(want) {
		t.Errorf("Fields = %v, want %v (the result is left out)", r.Fields, want)
	}
	for k, v := range want {
		if r.Fields[k] != v {
			t.Errorf("%s = %v, want %v", k, r.Fields[k], v)
		}
	}
}

func TestDecodeStreamingUpdatesAreIgnored(t *testing.T) {
	lines := []string{
		`{"type":"message_update","usage":{"input":100,"output":1,"cacheRead":0,"cacheWrite":0,"totalTokens":101,"cost":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"total":0}},"assistantMessageEvent":{"type":"text_delta","contentIndex":0,"delta":"Hello "}}`,
		`{"type":"message_start","message":{"role":"user","content":"Review this repository","timestamp":1733234401000}}`,
		`{"type":"tool_execution_update","toolCallId":"call_abc123","toolName":"bash","args":{"command":"ls -la"},"partialResult":{"content":[{"type":"text","text":"partial output"}],"details":{}}}`,
		`{"type":"bash_execution_update","id":"req-1","delta":"total 48\n"}`,
	}
	for _, line := range lines {
		if r := decode(t, line); r != nil {
			t.Errorf("Decode(%s) = %+v, want nil", line, r)
		}
	}
}

func TestDecodeLifecycleEventsKeepTheirTypeAndScalarFields(t *testing.T) {
	tests := []struct {
		line   string
		typ    string
		fields map[string]any
	}{
		{`{"type":"agent_start"}`, "agent_start", map[string]any{}},
		{`{"type":"turn_start"}`, "turn_start", map[string]any{}},
		{`{"type":"turn_end","message":{"role":"assistant"},"toolResults":[]}`, "turn_end", map[string]any{}},
		{`{"type":"agent_end","messages":[{"role":"assistant"}],"willRetry":false}`, "agent_end", map[string]any{"willRetry": false}},
		{`{"type":"extension_error","extensionPath":"/path/to/extension.ts","event":"tool_call","error":"Error message"}`, "extension_error",
			map[string]any{"extensionPath": "/path/to/extension.ts", "event": "tool_call", "error": "Error message"}},
		{`{"type":"auto_retry_start","attempt":1,"maxAttempts":3,"delayMs":2000,"errorMessage":"529 overloaded"}`, "auto_retry_start",
			map[string]any{"attempt": 1.0, "maxAttempts": 3.0, "delayMs": 2000.0, "errorMessage": "529 overloaded"}},
		{`{"type":"auto_retry_end","success":true,"attempt":2}`, "auto_retry_end", map[string]any{"success": true, "attempt": 2.0}},
		{`{"type":"compaction_start","reason":"threshold"}`, "compaction_start", map[string]any{"reason": "threshold"}},
		{`{"type":"summarization_retry_scheduled","attempt":1,"maxAttempts":3,"delayMs":2000,"errorMessage":"terminated"}`, "summarization_retry_scheduled",
			map[string]any{"attempt": 1.0, "maxAttempts": 3.0, "delayMs": 2000.0, "errorMessage": "terminated"}},
		{`{"type":"summarization_retry_attempt_start","source":"compaction","reason":"threshold"}`, "summarization_retry_attempt_start",
			map[string]any{"source": "compaction", "reason": "threshold"}},
		{`{"type":"summarization_retry_finished"}`, "summarization_retry_finished", map[string]any{}},
	}
	for _, tt := range tests {
		t.Run(tt.typ, func(t *testing.T) {
			r := decode(t, tt.line)
			if r == nil || r.Kind != "event" || r.Type != tt.typ {
				t.Fatalf("Decode = %+v, want event %s", r, tt.typ)
			}
			if len(r.Fields) != len(tt.fields) {
				t.Errorf("Fields = %v, want %v", r.Fields, tt.fields)
			}
			for k, v := range tt.fields {
				if r.Fields[k] != v {
					t.Errorf("%s = %v, want %v", k, r.Fields[k], v)
				}
			}
		})
	}
}

func TestDecodeCompactionEndCountsItsUsage(t *testing.T) {
	line := `{"type":"compaction_end","reason":"threshold","result":{"summary":"Summary of conversation...","firstKeptEntryId":"abc123","tokensBefore":150000,"estimatedTokensAfter":32000,"usage":{"input":32000,"output":1200,"cacheRead":0,"cacheWrite":0,"totalTokens":33200,"cost":{"input":0.01,"output":0.02,"cacheRead":0,"cacheWrite":0,"total":0.03}},"details":{}},"aborted":false,"willRetry":false}`
	r := decode(t, line)
	if r == nil || r.Type != "compaction_end" {
		t.Fatalf("Decode = %+v, want event compaction_end", r)
	}
	if r.Fields["reason"] != "threshold" || r.Fields["aborted"] != false || r.Fields["willRetry"] != false {
		t.Errorf("Fields = %v", r.Fields)
	}
	want := integration.Usage{Input: 32000, Output: 1200, Cost: 0.03}
	if r.Usage == nil || *r.Usage != want {
		t.Errorf("Usage = %+v, want %+v", r.Usage, want)
	}
}

func TestDecodeUnknownTypeCarriesOnlyTheType(t *testing.T) {
	r := decode(t, `{"type":"queue_update","steering":["Change direction"],"followUp":[]}`)
	if r == nil || r.Kind != "event" || r.Type != "other" {
		t.Fatalf("Decode = %+v, want event other", r)
	}
	if len(r.Fields) != 1 || r.Fields["type"] != "queue_update" {
		t.Errorf("Fields = %v, want only type queue_update", r.Fields)
	}
}

func TestDecodeNonObjectIsGarbage(t *testing.T) {
	long := strings.Repeat("ü", 300)
	tests := []struct {
		line string
		text string
	}{
		{"Loading extensions...", "Loading extensions..."},
		{`[1,2]`, `[1,2]`},
		{`null`, `null`},
		{`"text"`, `"text"`},
		{`{"type":"agent_start"`, `{"type":"agent_start"`},
		{"", ""},
		{long, long[:400]}, // 200 two-byte characters
	}
	for _, tt := range tests {
		r := decode(t, tt.line)
		if r == nil || r.Kind != "garbage" {
			t.Errorf("Decode(%q) = %+v, want garbage", tt.line, r)
			continue
		}
		if r.Fields["text"] != tt.text {
			t.Errorf("Decode(%q) text = %q, want %q", tt.line, r.Fields["text"], tt.text)
		}
	}
}

func TestDecodeSettled(t *testing.T) {
	r := decode(t, `{"type":"agent_settled","aborted":false}`)
	if r == nil || r.Kind != "settled" || r.Fields["aborted"] != false {
		t.Errorf("Decode = %+v, want settled, not aborted", r)
	}
}

func TestDecodeResponseCarriesItsData(t *testing.T) {
	r := decode(t, `{"id":"req-1","type":"response","command":"bash","success":true,"data":{"output":"total 48\ndrwxr-xr-x ...","exitCode":0,"cancelled":false,"truncated":false}}`)
	if r == nil || r.Kind != "response" || r.ID != "req-1" || !r.OK {
		t.Fatalf("Decode = %+v, want a successful response to req-1", r)
	}
	want := map[string]any{"output": "total 48\ndrwxr-xr-x ...", "exitCode": 0.0, "cancelled": false, "truncated": false}
	if len(r.Fields) != len(want) {
		t.Errorf("Fields = %v, want %v", r.Fields, want)
	}
	for k, v := range want {
		if r.Fields[k] != v {
			t.Errorf("%s = %v, want %v", k, r.Fields[k], v)
		}
	}
}

func TestDecodeFailedResponseCarriesTheError(t *testing.T) {
	r := decode(t, `{"id":"req-3","type":"response","command":"set_model","success":false,"error":"Model not found: invalid/model"}`)
	if r == nil || r.Kind != "response" || r.ID != "req-3" || r.OK {
		t.Fatalf("Decode = %+v, want a failed response to req-3", r)
	}
	if r.Fields["error"] != "Model not found: invalid/model" {
		t.Errorf("Fields = %v, want the error", r.Fields)
	}
}

func TestDecodeStatsResponseKeepsTheTotals(t *testing.T) {
	r := decode(t, `{"type":"response","id":"s1","command":"get_session_stats","success":true,"data":{"sessionFile":"/path/to/session.jsonl","sessionId":"abc123","userMessages":5,"assistantMessages":5,"toolCalls":12,"toolResults":12,"totalMessages":22,"tokens":{"input":50000,"output":10000,"cacheRead":40000,"cacheWrite":5000,"total":105000},"cost":0.45,"contextUsage":{"tokens":60000,"contextWindow":200000,"percent":30}}}`)
	if r == nil || r.Kind != "response" || r.ID != "s1" {
		t.Fatalf("Decode = %+v, want a response to s1", r)
	}
	tokens, _ := r.Fields["tokens"].(map[string]any)
	if r.Fields["cost"] != 0.45 || tokens["total"] != 105000.0 {
		t.Errorf("Fields = %v, want cost and tokens", r.Fields)
	}
}

func TestDecodeKeepsALineSeparatorInsideAString(t *testing.T) {
	r := decode(t, "{\"type\":\"extension_error\",\"extensionPath\":\"/x.ts\",\"event\":\"tool_call\",\"error\":\"one two three\"}")
	if r == nil || r.Kind != "event" || r.Fields["error"] != "one two three" {
		t.Errorf("Decode = %+v, want the separators kept in the error", r)
	}
}

func TestDecodeAcceptsACarriageReturnBeforeTheLF(t *testing.T) {
	r := decode(t, "{\"type\":\"agent_settled\",\"aborted\":true}\r")
	if r == nil || r.Kind != "settled" || r.Fields["aborted"] != true {
		t.Errorf("Decode = %+v, want settled, aborted", r)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"type":"message_end","message":{"role":"assistant","usage":{"input":1,"cost":{"total":1}}}}`))
	f.Add([]byte(`{"type":"tool_execution_start","args":{"a":"b"}}`))
	f.Add([]byte(`{"type":"response","data":[1]}`))
	f.Add([]byte("\xff\xfe"))
	rt, err := integration.NewRuntime("pi", map[string]any{"binary": testBinary})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		r := rt.Decode(line)
		if r == nil || r.Kind != "garbage" {
			return
		}
		if text, _ := r.Fields["text"].(string); utf8.RuneCountInString(text) > 200 {
			t.Errorf("garbage text has %d characters", utf8.RuneCountInString(text))
		}
	})
}
