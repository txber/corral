package netns

import (
	"math/rand/v2"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func someTargets(t *testing.T) []Target {
	return []Target{
		mustTarget(t, "10.10.4.0/24:tcp:1-1024"),
		mustTarget(t, "10.10.4.7:udp:53"),
	}
}

// chainBody returns the rules of the last block in text that fills chain,
// without its "type" line.
func chainBody(t *testing.T, text, chain string) []string {
	t.Helper()
	head := "\tchain " + chain + " {\n"
	start := strings.LastIndex(text, head)
	if start < 0 {
		t.Fatalf("no chain %s in:\n%s", chain, text)
	}
	body, _, found := strings.Cut(text[start+len(head):], "\t}\n")
	if !found {
		t.Fatalf("chain %s not closed", chain)
	}
	var rules []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "type ") {
			rules = append(rules, line)
		}
	}
	return rules
}

// element is one set element: addresses and a port range.
type element struct {
	network     netip.Prefix
	first, last int
}

// setElements returns the elements the last "elements = { ... }" of a set
// block, or the last "add element" for that set, puts into the set.
func setElements(t *testing.T, text, set string) []element {
	t.Helper()
	pattern := regexp.MustCompile(`(?:set ` + set + ` \{[^}]*elements = \{|add element inet corral ` + set + ` \{) ([^}]*) \}`)
	found := pattern.FindAllStringSubmatch(text, -1)
	if len(found) == 0 {
		return nil
	}
	var out []element
	for _, text := range strings.Split(found[len(found)-1][1], ", ") {
		addr, ports, ok := strings.Cut(text, " . ")
		if !ok {
			t.Fatalf("bad element %q", text)
		}
		network, err := netip.ParsePrefix(addr)
		if err != nil {
			a, err := netip.ParseAddr(addr)
			if err != nil {
				t.Fatalf("bad element address %q", addr)
			}
			network = netip.PrefixFrom(a, 32)
		}
		firstText, lastText, isRange := strings.Cut(ports, "-")
		first, err := strconv.Atoi(firstText)
		if err != nil {
			t.Fatalf("bad element ports %q", ports)
		}
		last := first
		if isRange {
			if last, err = strconv.Atoi(lastText); err != nil {
				t.Fatalf("bad element ports %q", ports)
			}
		}
		out = append(out, element{network, first, last})
	}
	return out
}

func TestAgentRulesNameOnlyThisAgent(t *testing.T) {
	text := renderAgent("w1", 7, someTargets(t))
	for _, name := range []string{"ocv7", "198.18.7.1", "198.18.7.2", "18007", "a_w1", "i_w1", "t_w1", "u_w1", `"corral-drop w1 "`} {
		if !strings.Contains(text, name) {
			t.Errorf("rules lack %s", name)
		}
	}
	for _, pattern := range []string{`ocv(?:[0-689]|7\d)`, `198\.18\.(?:[0-689]|7\d)`, `\b[aitu]_(?:[^w]|w[^1]|w1\w)`, `corral-drop (?:[^w]|w[^1]|w1\w)`} {
		if found := regexp.MustCompile(pattern).FindString(text); found != "" {
			t.Errorf("rules name %q, which is not this agent's", found)
		}
	}
}

func TestAgentRulesHoldTheTargets(t *testing.T) {
	text := renderAgent("w1", 7, someTargets(t))
	tcp := setElements(t, text, "t_w1")
	udp := setElements(t, text, "u_w1")
	if want := []element{{netip.MustParsePrefix("10.10.4.0/24"), 1, 1024}}; !slices.Equal(tcp, want) {
		t.Errorf("TCP set = %v, want %v", tcp, want)
	}
	if want := []element{{netip.MustParsePrefix("10.10.4.7/32"), 53, 53}}; !slices.Equal(udp, want) {
		t.Errorf("UDP set = %v, want %v", udp, want)
	}
}

func overlap(a, b element) bool {
	return a.network.Overlaps(b.network) && a.first <= b.last && b.first <= a.last
}

func TestOverlappingTargetsBecomeDisjointElements(t *testing.T) {
	var targets []Target
	for _, text := range []string{
		"10.10.4.0/24:tcp:1-1024",
		"10.10.4.7:tcp:445",
		"10.10.4.7:tcp:1000-2000",
		"10.10.4.0/30:tcp:3000",
		"10.10.4.0/25:tcp:2001-2999",
		"10.10.4.128/25:tcp:1-1024",
		"10.10.0.0/16:tcp:22",
		"10.10.4.0/24:tcp:1-1024",
		"10.10.4.9:tcp:1025",
	} {
		targets = append(targets, mustTarget(t, text))
	}
	elements := setElements(t, renderAgent("w1", 7, targets), "t_w1")
	for i, a := range elements {
		for _, b := range elements[i+1:] {
			if overlap(a, b) {
				t.Errorf("elements %v and %v overlap", a, b)
			}
		}
	}

	type probe struct {
		addr netip.Addr
		port int
	}
	var probes []probe
	for i := range 256 {
		for _, port := range []int{1, 22, 445, 1024, 1025, 1500, 2000, 2001, 2500, 3000, 3001} {
			probes = append(probes, probe{netip.AddrFrom4([4]byte{10, 10, 4, byte(i)}), port})
		}
	}
	rng := rand.New(rand.NewPCG(7, 7))
	for range 2000 {
		addr := netip.AddrFrom4([4]byte{10, 10, byte(rng.IntN(8)), byte(rng.IntN(256))})
		probes = append(probes, probe{addr, 1 + rng.IntN(65535)})
	}
	for _, p := range probes {
		wanted := slices.ContainsFunc(targets, func(t Target) bool {
			return t.Network.Contains(p.addr) && int(t.First) <= p.port && p.port <= int(t.Last)
		})
		got := slices.ContainsFunc(elements, func(e element) bool {
			return e.network.Contains(p.addr) && e.first <= p.port && p.port <= e.last
		})
		if got != wanted {
			t.Errorf("%v port %d: in set %v, want %v", p.addr, p.port, got, wanted)
		}
	}
}

func TestNestedTargetWithNoNewPortsAddsNoElement(t *testing.T) {
	targets := []Target{
		mustTarget(t, "10.10.4.0/24:tcp:1-1024"),
		mustTarget(t, "10.10.4.7:tcp:445"),
	}
	got := setElements(t, renderTargets("w1", targets), "t_w1")
	if want := []element{{netip.MustParsePrefix("10.10.4.0/24"), 1, 1024}}; !slices.Equal(got, want) {
		t.Errorf("elements = %v, want %v", got, want)
	}
}

func TestAgentRulesWithoutTargetsHaveEmptySets(t *testing.T) {
	text := renderAgent("w1", 7, nil)
	for _, set := range []string{"set t_w1 {", "set u_w1 {"} {
		if !strings.Contains(text, set) {
			t.Errorf("rules lack %q", set)
		}
	}
	if strings.Contains(text, "elements") {
		t.Errorf("rules without targets hold elements:\n%s", text)
	}
}

func TestAgentRulesLogAndDropTheRest(t *testing.T) {
	text := renderAgent("w1", 7, someTargets(t))
	for _, chain := range []string{"a_w1", "i_w1"} {
		rules := chainBody(t, text, chain)
		n := len(rules)
		if n < 3 || rules[n-1] != "drop" || rules[n-2] != `limit rate 10/second log prefix "corral-drop w1 "` {
			t.Fatalf("chain %s does not end in log and drop: %q", chain, rules)
		}
		// Only IPv4 from the agent's own address is accepted, so IPv6 and
		// packets with a forged source reach the drop.
		for _, rule := range rules[:n-2] {
			if !strings.HasPrefix(rule, "ip saddr 198.18.7.2 ") || !strings.HasSuffix(rule, " accept") {
				t.Errorf("chain %s rule %q is not an accept for the agent's address", chain, rule)
			}
		}
	}
}

func TestEstablishedAcceptForAgentTrafficCarriesTheAgentsSource(t *testing.T) {
	agent := renderAgent("w1", 7, someTargets(t))
	established := 0
	for _, rule := range chainBody(t, agent, "a_w1") {
		if strings.Contains(rule, "established") {
			established++
			if rule != "ip saddr 198.18.7.2 ct state established,related accept" {
				t.Errorf("agent rule %q", rule)
			}
		}
	}
	if established != 1 {
		t.Errorf("agent chain has %d established rules, want 1", established)
	}
	if rules := chainBody(t, agent, "i_w1"); slices.ContainsFunc(rules, func(r string) bool { return strings.Contains(r, "ct state") }) {
		t.Errorf("input chain uses the connection state: %q", rules)
	}
	base := renderBase()
	for _, chain := range []string{"forward", "input"} {
		for _, rule := range chainBody(t, base, chain) {
			if strings.Contains(rule, "established") && !strings.HasPrefix(rule, `oifname "ocv*" `) {
				t.Errorf("base %s rule %q accepts established traffic not bound for an agent", chain, rule)
			}
		}
	}
}

func TestTrafficTowardsAgentsIsOnlyEstablished(t *testing.T) {
	var towards []string
	for _, rule := range chainBody(t, renderBase(), "forward") {
		if strings.Contains(rule, `oifname "ocv*"`) {
			towards = append(towards, rule)
		}
	}
	want := []string{`oifname "ocv*" ct state established,related accept`, `oifname "ocv*" drop`}
	if !slices.Equal(towards, want) {
		t.Errorf("rules towards agents = %q, want %q", towards, want)
	}
}

func TestForwardedTargetsNeverLeaveThroughAnAgentInterface(t *testing.T) {
	rules := chainBody(t, renderAgent("w1", 7, someTargets(t)), "a_w1")
	want := []string{
		`ip saddr 198.18.7.2 oifname != "ocv*" ip daddr . tcp dport @t_w1 accept`,
		`ip saddr 198.18.7.2 oifname != "ocv*" ip daddr . udp dport @u_w1 accept`,
	}
	for _, rule := range want {
		if !slices.Contains(rules, rule) {
			t.Errorf("forward chain lacks %q: %q", rule, rules)
		}
	}
	for _, rule := range rules {
		if strings.Contains(rule, "@") && !slices.Contains(want, rule) {
			t.Errorf("unexpected set rule %q", rule)
		}
	}
}

func TestInputOpensOnlyTheProxyPort(t *testing.T) {
	text := renderAgent("w1", 7, someTargets(t))
	want := []string{
		"ip saddr 198.18.7.2 ip daddr 198.18.7.1 tcp dport 18007 accept",
		`limit rate 10/second log prefix "corral-drop w1 "`,
		"drop",
	}
	if got := chainBody(t, text, "i_w1"); !slices.Equal(got, want) {
		t.Errorf("input chain = %q, want %q", got, want)
	}
	for _, entry := range []string{
		`add element inet corral forward_agents { "ocv7" : jump a_w1 }`,
		`add element inet corral input_agents { "ocv7" : jump i_w1 }`,
	} {
		if !strings.Contains(text, entry) {
			t.Errorf("rules lack %q", entry)
		}
	}
	input := chainBody(t, renderBase(), "input")
	for _, rule := range input {
		if strings.Contains(rule, "accept") || strings.Contains(rule, "forward_agents") {
			t.Errorf("base input rule %q", rule)
		}
	}
}

func TestInputRulesDoNotUseTheTargetSets(t *testing.T) {
	for _, rule := range chainBody(t, renderAgent("w1", 7, someTargets(t)), "i_w1") {
		if strings.Contains(rule, "@") || strings.Contains(rule, "t_w1") || strings.Contains(rule, "u_w1") {
			t.Errorf("input rule %q uses a set", rule)
		}
	}
}

func TestUnmappedAgentInterfaceIsLoggedBeforeTheDrop(t *testing.T) {
	base := renderBase()
	for chain, agentMap := range map[string]string{"forward": "forward_agents", "input": "input_agents"} {
		rules := chainBody(t, base, chain)
		want := []string{
			`iifname "ocv*" iifname vmap @` + agentMap,
			`iifname "ocv*" limit rate 10/second log prefix "corral-drop ? "`,
			`iifname "ocv*" drop`,
		}
		if len(rules) < 3 || !slices.Equal(rules[:3], want) {
			t.Errorf("base %s chain starts %q, want %q", chain, rules, want)
		}
	}
}

func TestBaseChainsAcceptByDefaultAndTouchOnlyAgentInterfaces(t *testing.T) {
	text := renderBase()
	if hooks, accepts := strings.Count(text, " hook "), strings.Count(text, "policy accept;"); hooks == 0 || hooks != accepts {
		t.Errorf("%d hooks, %d accept policies", hooks, accepts)
	}
	for _, chain := range []string{"forward", "input", "postrouting"} {
		for _, rule := range chainBody(t, text, chain) {
			if !strings.HasPrefix(rule, `iifname "ocv*" `) && !strings.HasPrefix(rule, `oifname "ocv*" `) {
				t.Errorf("base %s rule %q does not start with an agent interface", chain, rule)
			}
		}
	}
	want := []string{`iifname "ocv*" oifname != "ocv*" ip saddr 198.18.0.0/16 masquerade`}
	if got := chainBody(t, text, "postrouting"); !slices.Equal(got, want) {
		t.Errorf("postrouting = %q, want %q", got, want)
	}
}

func TestRenderTargetsReplacesTheWholeSet(t *testing.T) {
	targets := []Target{
		mustTarget(t, "10.10.4.0/24:tcp:1-1024"),
		mustTarget(t, "10.10.4.0/24:tcp:445-2000"),
		mustTarget(t, "10.10.4.7:udp:53"),
	}
	text := renderTargets("w1", targets)
	want := "flush set inet corral t_w1\n" +
		"flush set inet corral u_w1\n" +
		"add element inet corral t_w1 { 10.10.4.0/24 . 1-2000 }\n" +
		"add element inet corral u_w1 { 10.10.4.7 . 53 }\n"
	if text != want {
		t.Errorf("renderTargets =\n%s\nwant\n%s", text, want)
	}
	if got := renderTargets("w1", targets[2:]); got != "flush set inet corral t_w1\nflush set inet corral u_w1\nadd element inet corral u_w1 { 10.10.4.7 . 53 }\n" {
		t.Errorf("renderTargets with UDP only =\n%s", got)
	}
}

func TestRemoveDeletesTheAgentRulesChainsAndSets(t *testing.T) {
	text := renderRemove("w1", 7)
	for _, line := range []string{
		`delete element inet corral forward_agents { "ocv7" }`,
		`delete element inet corral input_agents { "ocv7" }`,
		"delete chain inet corral a_w1",
		"delete chain inet corral i_w1",
		"delete set inet corral t_w1",
		"delete set inet corral u_w1",
	} {
		if !strings.Contains(text, line+"\n") {
			t.Errorf("remove lacks %q", line)
		}
	}
}

func TestRenderPanicsOnUncheckedTargets(t *testing.T) {
	good := mustTarget(t, "10.10.4.0/24:tcp:80")
	for _, bad := range []Target{
		{},
		{Network: netip.MustParsePrefix("2001:db8::/64"), Proto: "tcp", First: 80, Last: 80},
		{Network: netip.MustParsePrefix("10.0.0.0/7"), Proto: "tcp", First: 80, Last: 80},
		{Network: netip.PrefixFrom(netip.MustParseAddr("10.10.4.7"), 24), Proto: "tcp", First: 80, Last: 80},
		{Network: good.Network, Proto: "tcp } ; flush ruleset", First: 80, Last: 80},
		{Network: good.Network, Proto: "tcp", First: 0, Last: 80},
		{Network: good.Network, Proto: "tcp", First: 90, Last: 80},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("renderTargets accepted %+v", bad)
				}
			}()
			renderTargets("w1", []Target{good, bad})
		}()
	}
}

// safeText is every character the rendered rules may hold.
var safeText = regexp.MustCompile(`^[a-z0-9_ .,:;/{}"@=!?\-\n\t*]+$`)

func TestRenderedTextHasNoShellOrNftMetacharactersFromInput(t *testing.T) {
	rng := rand.New(rand.NewPCG(4, 4))
	const letters = "abcdefghijklmnopqrstuvwxyz"
	const digits = "0123456789"
	for range 200 {
		id := []byte{letters[rng.IntN(len(letters))]}
		for range rng.IntN(12) {
			chars := letters + digits
			id = append(id, chars[rng.IntN(len(chars))])
		}
		agentID := string(id)
		slot := 1 + rng.IntN(250)
		var targets []Target
		for range 1 + rng.IntN(8) {
			targets = append(targets, randomTarget(t, rng))
		}
		for _, text := range []string{
			renderBase(),
			renderAgent(agentID, slot, targets),
			renderTargets(agentID, targets),
			renderRemove(agentID, slot),
		} {
			if !safeText.MatchString(text) {
				t.Fatalf("unexpected character in:\n%s", text)
			}
		}
	}
}

func randomTarget(t *testing.T, rng *rand.Rand) Target {
	bits := 8 + rng.IntN(25)
	addr := netip.AddrFrom4([4]byte{byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256))})
	network := netip.PrefixFrom(addr, bits).Masked()
	first := 1 + rng.IntN(65535)
	last := first + rng.IntN(65536-first)
	proto := []string{"tcp", "udp"}[rng.IntN(2)]
	text := network.String() + ":" + proto + ":" + strconv.Itoa(first) + "-" + strconv.Itoa(last)
	return mustTarget(t, text)
}
