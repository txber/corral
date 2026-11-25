package netns

import (
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// agentIDPattern is the id rule of the usage text, written independently of
// validAgentID.
var agentIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]{0,11}$`)

// FuzzParseArgs feeds command lines, the arguments separated by NUL bytes,
// and checks that an accepted line has exactly a form of the usage text and
// that the command holds the values written in it.
func FuzzParseArgs(f *testing.F) {
	for _, args := range [][]string{
		{"up", "w1", "7", "--target", "10.10.4.7:udp:53"},
		{"up", "w1", "7"},
		{"allow", "w1", "7", "--target", "10.10.4.7:udp:53", "--target", "10.10.4.0/24:tcp:1-1024"},
		{"down", "w1", "7"},
		{"exec", "w1", "--env-file", "/run/e", "--", "/opt/agent", "-x", "--"},
		{"enter", "--env-file", "/run/e", "--", "/opt/agent", "-x"},
		{"list"},
		{"up", "abcdefghijkl", "250", "--target", "10.10.4.7/32:tcp:65535"},
		{"up", "abcdefghijklm", "1"},
		{"up", "w1", "07"},
		{"up", "w1", "251"},
		{"up", "w1", "7", "--target=10.10.4.7:udp:53"},
		{"up", "w1", "7", "-target", "10.10.4.7:udp:53"},
		{"up", "w1", "7", "--", "--target", "10.10.4.7:tcp:80"},
		{"up", "w1", "7", "--target", "::ffff:10.10.4.7:tcp:80"},
		{"up", "w1", "7", "--target", "10.10.4.7:tcp:80\n"},
		{"up", "w1", "7", "--target", "10.10.4.7:tcp:٨٠"},
		{"allow", "w1", "7"},
		{"down", "w1", "7", "--target", "10.10.4.7:udp:53"},
		{"exec", "w1", "--env-file", "--", "--", "/opt/agent"},
		{"exec", "w1", "--env-file", "/run/../e", "--", "/opt/agent"},
		{"exec", "w1", "--env-file", "/run/e", "--", "/opt/../agent"},
		{"exec", "w1", "--env-file=/run/e", "--", "/opt/agent"},
		{"enter", "w1", "--env-file", "/run/e", "--", "/opt/agent"},
		{"enter", "--env-file", "/run/e", "--", "-agent"},
		{"list", ""},
		{"nuke"},
	} {
		f.Add(strings.Join(args, "\x00"))
	}
	f.Fuzz(func(t *testing.T, line string) {
		var args []string
		if line != "" {
			args = strings.Split(line, "\x00")
		}
		c, err := parseArgs(args)
		if err != nil {
			return
		}
		if c.name != args[0] {
			t.Fatalf("parseArgs(%q): command %q", args, c.name)
		}
		switch c.name {
		case "list":
			if len(args) != 1 {
				t.Fatalf("parseArgs(%q): list accepted with arguments", args)
			}
		case "up", "allow", "down":
			if len(args) < 3 || c.agentID != args[1] || !agentIDPattern.MatchString(c.agentID) ||
				c.slot < 1 || c.slot > 250 || strconv.Itoa(c.slot) != args[2] {
				t.Fatalf("parseArgs(%q): agent id %q, slot %d", args, c.agentID, c.slot)
			}
			// The rest is "--target <target>" pairs, each read into the
			// target at its place.
			rest := args[3:]
			if len(rest) != 2*len(c.targets) {
				t.Fatalf("parseArgs(%q): %d targets from %d arguments", args, len(c.targets), len(rest))
			}
			for i, target := range c.targets {
				want, err := parseTarget(rest[2*i+1])
				if rest[2*i] != "--target" || err != nil || target != want {
					t.Fatalf("parseArgs(%q): target %d is %v", args, i, target)
				}
			}
			if len(c.targets) > 256 || c.name == "down" && len(c.targets) > 0 || c.name == "allow" && len(c.targets) == 0 {
				t.Fatalf("parseArgs(%q): %s with %d targets", args, c.name, len(c.targets))
			}
			if _, _, err := setContents(c.targets); err != nil {
				t.Fatalf("parseArgs(%q): accepted targets the renderer refuses: %v", args, err)
			}
		case "exec", "enter":
			rest := args[1:]
			if c.name == "exec" {
				if len(rest) == 0 || c.agentID != rest[0] || !agentIDPattern.MatchString(c.agentID) {
					t.Fatalf("parseArgs(%q): agent id %q", args, c.agentID)
				}
				rest = rest[1:]
			} else if c.agentID != "" {
				t.Fatalf("parseArgs(%q): enter with agent id %q", args, c.agentID)
			}
			if len(rest) < 4 || rest[0] != "--env-file" || rest[1] != c.envFile || rest[2] != "--" || !slices.Equal(c.argv, rest[3:]) {
				t.Fatalf("parseArgs(%q): env file %q, argv %q", args, c.envFile, c.argv)
			}
			if !absoluteWithoutDotDot(c.envFile) || !absoluteWithoutDotDot(c.argv[0]) {
				t.Fatalf("parseArgs(%q): env file %q, command %q", args, c.envFile, c.argv[0])
			}
		default:
			t.Fatalf("parseArgs(%q): accepted command %q", args, c.name)
		}
	})
}

func absoluteWithoutDotDot(path string) bool {
	return strings.HasPrefix(path, "/") && !slices.Contains(strings.Split(path, "/"), "..")
}

var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// FuzzParseEnv checks that an accepted env file becomes exactly its lines, as
// KEY=VALUE with a plain key set once, and that an error never depends on a
// value, so that no secret can show in it.
func FuzzParseEnv(f *testing.F) {
	for _, text := range []string{
		"PATH=/usr/bin:/bin\nGREETING=hello = world\nEMPTY=\n_x1=y",
		"KEY=value-with-=-signs==\n",
		"",
		"\n",
		"\n\n",
		"PATH\n",
		"=x\n",
		"1A=x\n",
		"A-B=x\n",
		"A B=x\n",
		"Ä=x\n",
		"export A=x\n",
		"A=x\n\nB=y\n",
		"A=x\x00y\n",
		"A=1\r\nB=2\r\n",
		"A=x\rB=y",
		"TOKEN=secret-one\nTOKEN=secret-two\n",
		"A=line\nnot a pair secret-value",
		strings.Repeat("A=x\n", 64) + "B=y\n",
		envLines(64),
		envLines(65),
	} {
		f.Add([]byte(text))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		env, err := parseEnv(data)
		if err != nil {
			if _, again := parseEnv(maskValues(data)); again == nil || again.Error() != err.Error() {
				t.Fatalf("parseEnv(%q): error %q changes when the values change: %v", data, err, again)
			}
			return
		}
		if env == nil || len(env) > 64 || strings.Join(env, "\n") != strings.TrimSuffix(string(data), "\n") {
			t.Fatalf("parseEnv(%q) = %q, not the lines of the file", data, env)
		}
		seen := map[string]bool{}
		for _, entry := range env {
			key, value, _ := strings.Cut(entry, "=")
			if !envKeyPattern.MatchString(key) || seen[key] || strings.ContainsAny(value, "\x00\n") {
				t.Fatalf("parseEnv(%q): entry %q", data, entry)
			}
			seen[key] = true
		}
	})
}

// maskValues overwrites every value in an env file, keeping its NUL bytes,
// which parseEnv refuses wherever they are.
func maskValues(data []byte) []byte {
	masked := slices.Clone(data)
	inValue := false
	for i, c := range masked {
		switch {
		case c == '\n':
			inValue = false
		case inValue && c != 0:
			masked[i] = 'x'
		case c == '=':
			inValue = true
		}
	}
	return masked
}

// FuzzStateRoundTrip checks that parseState reads every line of a state text,
// the slot and then one target per line, and that formatState writes what was
// read as a text that reads back the same. A target may be spelled in any
// form parseTarget accepts, such as "/32" or "80-80", which formatState
// writes in the short form.
func FuzzStateRoundTrip(f *testing.F) {
	for _, text := range []string{
		"slot 17\ntarget 192.0.2.7:udp:53\ntarget 10.10.4.0/24:tcp:1-1024\n",
		"slot 250\n",
		"slot 1\ntarget 10.10.4.7/32:tcp:80-80\n",
		"",
		"\n",
		"slot 7",
		"slot 7\n\n",
		"slot 7\r\n",
		"slot 07\n",
		"slot 251\n",
		"slot  3\n",
		"slot ٧\n",
		"slot 3\nslot 4\n",
		"slot 3\nflush ruleset\n",
		"target 192.0.2.7:udp:53\n",
		"slot 7\ntarget 10.10.4.7:tcp:80\r\n",
		"slot 7\ntarget  10.10.4.7:tcp:80\n",
		"slot 7\ntarget ::ffff:10.10.4.7:tcp:80\n",
		"slot 7\ntarget 0.0.0.0/0:tcp:80\n",
		"slot 7\ntarget 10.10.4.7:tcp:90-80\n",
	} {
		f.Add(text)
	}
	f.Fuzz(func(t *testing.T, text string) {
		slot, targets, err := parseState(text)
		if err != nil {
			return
		}
		if slot < 1 || slot > 250 || len(targets) > 256 {
			t.Fatalf("parseState(%q): slot %d, %d targets", text, slot, len(targets))
		}
		lines := strings.SplitAfter(text, "\n")
		if len(lines) != len(targets)+2 || lines[0] != "slot "+strconv.Itoa(slot)+"\n" || lines[len(lines)-1] != "" {
			t.Fatalf("parseState(%q) = %d, %v, which are not the lines of the text", text, slot, targets)
		}
		for i, target := range targets {
			targetText, ok := strings.CutPrefix(strings.TrimSuffix(lines[i+1], "\n"), "target ")
			if read, err := parseTarget(targetText); !ok || err != nil || read != target {
				t.Fatalf("parseState(%q): target %d is %v, read from line %q", text, i, target, lines[i+1])
			}
		}
		again := formatState(slot, targets)
		if slot2, targets2, err := parseState(again); err != nil || slot2 != slot || !slices.Equal(targets2, targets) {
			t.Fatalf("parseState(%q) = %d, %v, but formatState writes %q, which reads as %d, %v, %v", text, slot, targets, again, slot2, targets2, err)
		}
	})
}

// FuzzRenderAgent renders an agent's rules for a fuzzed id, slot and target
// list. An id or slot the parser refuses must make the renderers panic. For
// good ones the set elements must be canonical, must not overlap, since an
// interval set refuses that, and must grant exactly what the targets grant;
// and the targets may change nothing in the text but the element lines.
func FuzzRenderAgent(f *testing.F) {
	f.Add("w1", 7, []byte{})
	// 10.0.0.0/22 tcp 1-16 with 10.0.1.7 tcp 20 and udp 20 inside it.
	f.Add("w1", 7, []byte{112, 0, 0, 0, 15, 0, 192, 1, 7, 19, 0, 0, 192, 1, 7, 19, 0, 1})
	// 10.0.0.0/8 tcp 1-65535 with 10.0.0.9 tcp 16 and 10.0.0.1 tcp 65535
	// inside it.
	f.Add("abcdefghijkl", 250, []byte{2, 10, 0, 0, 0, 4, 195, 0, 9, 79, 0, 0, 192, 0, 1, 3, 15, 2})
	f.Add("a", 1, []byte{0, 1, 2, 3, 4, 5, 1, 1, 2, 3, 4, 4, 3, 0, 0, 0, 0, 24, 200, 0, 0, 5, 0, 0})
	f.Add("W1", 7, []byte{})
	f.Add("w1;x", 7, []byte{})
	f.Add("w1\n", 7, []byte{})
	f.Add("abcdefghijklm", 3, []byte{})
	f.Add("", 3, []byte{})
	f.Add("w1", 0, []byte{})
	f.Add("w1", 251, []byte{})
	f.Fuzz(func(t *testing.T, agentID string, slot int, data []byte) {
		goodID := agentIDPattern.MatchString(agentID)
		if !goodID || slot < 1 || slot > 250 {
			if !panics(func() { renderAgent(agentID, slot, nil) }) {
				t.Fatalf("renderAgent(%q, %d) rendered", agentID, slot)
			}
			if !goodID && (!panics(func() { renderTargets(agentID, nil) }) || !panics(func() { renderRemove(agentID, 1) })) {
				t.Fatalf("renderTargets or renderRemove rendered for agent id %q", agentID)
			}
			return
		}
		targets := targetsFrom(data)
		tcp, udp, err := setContents(targets)
		if err != nil {
			// Too many elements: refused whole, never cut short. Inputs this
			// large make fuzzing slow, so TestRenderPanicsOnTooManySetElements
			// checks such a list on every run.
			if !panics(func() { renderAgent(agentID, slot, targets) }) || !panics(func() { renderTargets(agentID, targets) }) {
				t.Fatalf("rendered targets setContents refuses: %v", err)
			}
			return
		}
		checkElements(t, targets, "tcp", tcp)
		checkElements(t, targets, "udp", udp)

		want := renderTargets(agentID, nil)
		if len(tcp) > 0 {
			want += "add element inet corral t_" + agentID + " { " + strings.Join(tcp, ", ") + " }\n"
		}
		if len(udp) > 0 {
			want += "add element inet corral u_" + agentID + " { " + strings.Join(udp, ", ") + " }\n"
		}
		if got := renderTargets(agentID, targets); got != want {
			t.Fatalf("renderTargets(%q, %v) =\n%s\nwant\n%s", agentID, targets, got, want)
		}

		text := renderAgent(agentID, slot, targets)
		for _, elements := range [][]string{tcp, udp} {
			if len(elements) > 0 {
				text = strings.Replace(text, "\t\telements = { "+strings.Join(elements, ", ")+" }\n", "", 1)
			}
		}
		if text != renderAgent(agentID, slot, nil) {
			t.Fatalf("renderAgent(%q, %d, %v) differs from the rules without targets beyond the elements:\n%s", agentID, slot, targets, text)
		}
	})
}

// targetsFrom turns fuzz data into up to 32 valid targets, six bytes each.
// Most addresses come from a few small ranges and many ports are low, so that
// networks nest and port ranges meet, which is where normalise does its work.
func targetsFrom(data []byte) []Target {
	var targets []Target
	for len(data) >= 6 && len(targets) < 32 {
		b := data[:6]
		data = data[6:]
		var a [4]byte
		switch b[0] % 4 {
		case 0:
			a = [4]byte{10, 0, b[1] & 3, b[2]}
		case 1:
			a = [4]byte{10, b[1] & 7, b[2] & 7, b[3]}
		case 2:
			a = [4]byte{b[1], b[2], b[3], b[4]}
		default:
			a = [4]byte{10, 0, 0, b[2] & 15}
		}
		bits := min(32, 8+int(b[0]>>3)) // a quarter are single hosts
		proto := "tcp"
		if b[5]&1 != 0 {
			proto = "udp"
		}
		first := 1 + int(b[3]&31)
		if b[5]&2 != 0 {
			first = 65532 + int(b[3]&3)
		}
		last := min(65535, first+int(b[4]&15))
		if b[5]&4 != 0 {
			first, last = 1, 65535
		}
		network := netip.PrefixFrom(netip.AddrFrom4(a), bits).Masked()
		targets = append(targets, Target{Network: network, Proto: proto, First: uint16(first), Last: uint16(last)})
	}
	return targets
}

// checkElements checks the set elements of one protocol against the targets.
func checkElements(t *testing.T, targets []Target, proto string, texts []string) {
	t.Helper()
	// An element "<addr[/prefix]> . <port[-port]>" is a target without its
	// protocol: it must read as one and be written as String writes it.
	var elements []Target
	for _, text := range texts {
		addr, ports, _ := strings.Cut(text, " . ")
		asTarget := addr + ":" + proto + ":" + ports
		e, err := parseTarget(asTarget)
		if err != nil || e.String() != asTarget {
			t.Fatalf("%s element %q is not in canonical form", proto, text)
		}
		elements = append(elements, e)
	}
	for i, a := range elements {
		for _, b := range elements[i+1:] {
			if a.Network.Overlaps(b.Network) && a.First <= b.Last && b.First <= a.Last {
				t.Fatalf("%s elements %v and %v overlap", proto, a, b)
			}
		}
	}

	// Probe the corners of every target and element and the points just
	// outside them, where a missing or extra block shows.
	var addrs []netip.Addr
	var ports []int
	for _, x := range append(slices.Clone(targets), elements...) {
		lo, hi := x.Network.Addr(), lastAddr(x.Network)
		addrs = append(addrs, lo, hi, lo.Prev(), hi.Next())
		ports = append(ports, int(x.First), int(x.Last), int(x.First)-1, int(x.Last)+1)
	}
	if len(addrs) == 0 {
		return
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for range 400 {
		addr, port := addrs[rng.IntN(len(addrs))], ports[rng.IntN(len(ports))]
		if grants(targets, proto, addr, port) != grants(elements, proto, addr, port) {
			t.Fatalf("%s %v port %d: targets %v grant %v, elements %q do not agree", proto, addr, port, targets, grants(targets, proto, addr, port), texts)
		}
	}
}

func grants(targets []Target, proto string, addr netip.Addr, port int) bool {
	return slices.ContainsFunc(targets, func(t Target) bool {
		return t.Proto == proto && t.Network.Contains(addr) && int(t.First) <= port && port <= int(t.Last)
	})
}

// lastAddr returns the highest address in an IPv4 network.
func lastAddr(network netip.Prefix) netip.Addr {
	a := network.Addr().As4()
	binary.BigEndian.PutUint32(a[:], binary.BigEndian.Uint32(a[:])|^uint32(0)>>network.Bits())
	return netip.AddrFrom4(a)
}

func panics(fn func()) (did bool) {
	defer func() { did = recover() != nil }()
	fn()
	return false
}
