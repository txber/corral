package netns

import (
	"bytes"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestGoodAgentIDs(t *testing.T) {
	for _, text := range []string{"w1", "a", "recon12", "abcdefghijkl"} {
		got, err := parseAgentID(text)
		if err != nil || got != text {
			t.Errorf("parseAgentID(%q) = %q, %v; want %q, nil", text, got, err, text)
		}
	}
}

func TestBadAgentIDsAreRefused(t *testing.T) {
	for _, text := range []string{"", "1w", "W1", "w-1", "w_1", "../x", "a;b", "abcdefghijklm", "w1\n", "w 1", "wé"} {
		_, err := parseAgentID(text)
		if err == nil || !strings.Contains(err.Error(), "agent id") {
			t.Errorf("parseAgentID(%q) error = %v, want one naming the agent id", text, err)
		}
	}
}

func TestGoodSlots(t *testing.T) {
	for _, text := range []string{"1", "7", "99", "250"} {
		want, _ := strconv.Atoi(text)
		got, err := parseSlot(text)
		if err != nil || got != want {
			t.Errorf("parseSlot(%q) = %d, %v; want %d, nil", text, got, err, want)
		}
	}
}

func TestBadSlotsAreRefused(t *testing.T) {
	for _, text := range []string{"0", "251", "-1", "1.5", "x", "", "007x", "07", "+7", " 7", "1000", "٧"} {
		_, err := parseSlot(text)
		if err == nil || !strings.Contains(err.Error(), "slot") {
			t.Errorf("parseSlot(%q) error = %v, want one naming the slot", text, err)
		}
	}
}

// badTargets are refused by the target parser; see also the comparison with
// the scope parser in target_scope_test.go.
var badTargets = []string{
	"::1:tcp:80",
	"example.com:tcp:80",
	"0.0.0.0/0:tcp:80",
	"10.0.0.0/7:tcp:80",
	"10.10.4.7:tcp:0",
	"10.10.4.7:tcp:70000",
	"10.10.4.7:tcp:90-80",
	"10.10.4.7:icmp:1",
	"10.10.4.7/24:tcp:80",
	"10.10.4.7:tcp",
	"",
	"10.10.4.7:tcp:80;x",
	"10.10.4.0/255.255.255.0:tcp:80",
	"10.10.4.7:tcp:80 }",
	"10.10.4.7:tcp:80\n",
}

func TestBadTargetsAreRefused(t *testing.T) {
	for _, text := range badTargets {
		_, err := parseTarget(text)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Errorf("parseTarget(%q) error = %v, want one naming the target", text, err)
		}
	}
}

func TestNamesForSlot7(t *testing.T) {
	want := names{
		Netns:     "oc-w1",
		Veth:      "ocv7",
		RootIP:    "198.18.7.1",
		AgentIP:   "198.18.7.2",
		Chain:     "a_w1",
		InChain:   "i_w1",
		TCPSet:    "t_w1",
		UDPSet:    "u_w1",
		Limit:     "l_w1",
		ProxyPort: 18007,
	}
	if got := namesFor("w1", 7); got != want {
		t.Errorf("namesFor(w1, 7) = %+v, want %+v", got, want)
	}
}

func TestNamesForUncheckedValuesPanics(t *testing.T) {
	for _, c := range []struct {
		id   string
		slot int
	}{{"W1", 7}, {"w1", 0}, {"w1", 251}, {"w1;x", 7}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("namesFor(%q, %d) did not panic", c.id, c.slot)
				}
			}()
			namesFor(c.id, c.slot)
		}()
	}
}

func mustTarget(t *testing.T, text string) Target {
	t.Helper()
	target, err := parseTarget(text)
	if err != nil {
		t.Fatalf("parseTarget(%q): %v", text, err)
	}
	return target
}

func TestCommandsAreParsed(t *testing.T) {
	up, err := parseArgs([]string{"up", "w1", "7", "--target", "10.10.4.7:udp:53"})
	if err != nil {
		t.Fatal(err)
	}
	if up.name != "up" || up.agentID != "w1" || up.slot != 7 {
		t.Errorf("up = %+v", up)
	}
	if want := []Target{mustTarget(t, "10.10.4.7:udp:53")}; !slices.Equal(up.targets, want) {
		t.Errorf("up targets = %v, want %v", up.targets, want)
	}

	bare, err := parseArgs([]string{"up", "w1", "7"})
	if err != nil || len(bare.targets) != 0 {
		t.Errorf("up without targets = %+v, %v", bare, err)
	}

	allow, err := parseArgs([]string{"allow", "w1", "7", "--target", "10.10.4.7:udp:53", "--target", "10.10.4.0/24:tcp:1-1024"})
	if err != nil || len(allow.targets) != 2 {
		t.Errorf("allow = %+v, %v", allow, err)
	}

	run, err := parseArgs([]string{"exec", "w1", "--env-file", "/run/e", "--", "agent", "-x", "--"})
	if err != nil {
		t.Fatal(err)
	}
	if run.agentID != "w1" || run.envFile != "/run/e" || !slices.Equal(run.argv, []string{"agent", "-x", "--"}) {
		t.Errorf("exec = %+v", run)
	}

	down, err := parseArgs([]string{"down", "w1", "7"})
	if err != nil || down.slot != 7 {
		t.Errorf("down = %+v, %v", down, err)
	}

	list, err := parseArgs([]string{"list"})
	if err != nil || list.name != "list" {
		t.Errorf("list = %+v, %v", list, err)
	}
}

func TestBadCommandLinesAreRefused(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"nuke"},
		{"up", "w1"},
		{"up", "W1", "7"},
		{"up", "w1", "0"},
		{"up", "w1", "7", "--target"},
		{"up", "w1", "7", "--target=10.10.4.7:udp:53"},
		{"up", "w1", "7", "-target", "10.10.4.7:udp:53"},
		{"up", "w1", "7", "--target", "10.10.4.7:udp:53;x"},
		{"up", "w1", "7", "extra"},
		{"allow", "w1", "7"},
		{"exec", "w1", "--", "agent"},
		{"exec", "w1", "--env-file", "relative", "--", "agent"},
		{"exec", "w1", "--env-file", "/run/../etc/shadow", "--", "agent"},
		{"exec", "w1", "--env-file", "/run/e\x00", "--", "agent"},
		{"exec", "w1", "--env-file", "/run/e", "agent"},
		{"exec", "w1", "--env-file", "/run/e", "--"},
		{"exec", "w1", "--env-file", "/run/e", "--", "-agent"},
		{"exec", "w1", "--env-file", "/run/e", "--", ""},
		{"exec", "w1", "--env-file", "/run/e", "--", "agent", "a\x00b"},
		{"exec", "W1", "--env-file", "/run/e", "--", "agent"},
		{"down", "w1", "7", "8"},
		{"down", "w1", "7", "--target", "10.10.4.7:udp:53"},
		{"list", "x"},
	} {
		if c, err := parseArgs(args); err == nil {
			t.Errorf("parseArgs(%q) = %+v, want an error", args, c)
		}
	}
}

func TestTooManyTargetsAreRefused(t *testing.T) {
	args := []string{"up", "w1", "7"}
	for i := range maxTargets + 1 {
		args = append(args, "--target", "10.10.4.7:tcp:"+strconv.Itoa(i+1))
	}
	_, err := parseArgs(args)
	if err == nil || !strings.Contains(err.Error(), "targets") {
		t.Errorf("error = %v, want one about too many targets", err)
	}
	if _, err := parseArgs(args[:len(args)-2]); err != nil {
		t.Errorf("%d targets refused: %v", maxTargets, err)
	}
}

// TestTargetsWithTooManySetElementsAreRefused: 256 targets can split into
// hundreds of thousands of set elements; such a list is refused before
// anything is rendered.
func TestTargetsWithTooManySetElementsAreRefused(t *testing.T) {
	args := []string{"up", "w1", "7"}
	// 128 separate ports on a /8 ...
	for i := range 128 {
		args = append(args, "--target", "10.0.0.0/8:tcp:"+strconv.Itoa(1+2*i))
	}
	// ... and 128 hosts inside it that each add a port, so that each host
	// cuts the /8 into about 24 blocks that all carry the 128 ports.
	for i := range 128 {
		args = append(args, "--target", "10."+strconv.Itoa(i)+".0.1:tcp:"+strconv.Itoa(30001+2*i))
	}
	var stdout, stderr bytes.Buffer
	code := Main(args, &stdout, &stderr)
	firstLine, _, _ := strings.Cut(stderr.String(), "\n")
	if code != 2 || !strings.Contains(firstLine, "targets") || !strings.Contains(firstLine, "4096") {
		t.Errorf("Main = %d, %q; want 2 and an error naming the targets and the bound", code, firstLine)
	}
}

func TestBadArgumentsExitTwoAndNameTheArgument(t *testing.T) {
	tests := []struct {
		args []string
		name string // the word the error must contain
	}{
		{[]string{}, "command"},
		{[]string{"nuke"}, "command"},
		{[]string{"up", "W1", "7"}, "agent id"},
		{[]string{"down", "w1", "251"}, "slot"},
		{[]string{"up", "w1", "7", "--target", "10.10.4.7:tcp:0"}, "target"},
		{[]string{"up", "w1", "7", "--tagret", "10.10.4.7:tcp:80"}, "--tagret"},
		{[]string{"allow", "w1", "7"}, "--target"},
		{[]string{"exec", "w1", "--env-file", "env", "--", "agent"}, "env-file"},
		{[]string{"exec", "w1", "--env-file", "/run/e", "--", "-agent"}, "command"},
		{[]string{"list", "x"}, "list"},
	}
	for _, tt := range tests {
		var stdout, stderr bytes.Buffer
		code := Main(tt.args, &stdout, &stderr)
		if code != 2 {
			t.Errorf("Main(%q) = %d, want 2", tt.args, code)
		}
		if stdout.Len() != 0 {
			t.Errorf("Main(%q) wrote to stdout: %q", tt.args, stdout.String())
		}
		firstLine, _, _ := strings.Cut(stderr.String(), "\n")
		if !strings.HasPrefix(firstLine, "corral netns: ") || !strings.Contains(firstLine, tt.name) {
			t.Errorf("Main(%q) error line = %q, want one naming %q", tt.args, firstLine, tt.name)
		}
		if !strings.Contains(stderr.String(), "usage:") {
			t.Errorf("Main(%q) printed no usage", tt.args)
		}
	}
}

func TestExecWithoutSudoIsRefused(t *testing.T) {
	t.Setenv("SUDO_UID", "")
	var stdout, stderr bytes.Buffer
	code := Main([]string{"exec", "w1", "--env-file", "/run/e", "--", "agent"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "SUDO_UID") {
		t.Errorf("Main(exec) = %d, %q; want 1 and a word about SUDO_UID", code, stderr.String())
	}
}

// TestNetnsImportsOnlyTheStandardLibrary keeps the code that runs as root
// free of anything but the standard library.
func TestNetnsImportsOnlyTheStandardLibrary(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, imp := range parsed.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			// Standard library paths have no dot in their first element.
			first, _, _ := strings.Cut(path, "/")
			if strings.Contains(first, ".") {
				t.Errorf("%s imports %s", file, path)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no source files checked")
	}
}
