// This file renders the nftables rules, as text for one "nft -f -" run each,
// so that every change is one transaction that applies whole or not at all.
//
// All rules live in table inet corral. Its base chains accept by default and
// act only on traffic of the agents' veth interfaces (ocv*), and on traffic
// addressed to the agents' range that arrives on any other interface than
// loopback:
//
//	forward      from an agent: jump to that agent's forward chain a_<id>;
//	             towards an agent: established and related traffic only
//	input        from an agent: jump to that agent's input chain i_<id>;
//	             to the agents' range from elsewhere: dropped, so that no
//	             other host, container or VM can use a proxy port
//	postrouting  agent traffic leaving through another interface is masqueraded
//
// Connections this machine makes to its own 198.18.<n>.1 arrive on lo and
// pass.
//
// The jumps go through two maps from interface name to chain. Traffic from
// an ocv* interface that no map holds is logged and dropped, and each agent
// chain ends in a log and a drop, so nothing from an agent falls through.
// Every drop is logged at a limited rate; both chains of one agent share the
// named limit l_<id>, so one agent writes at most 10 lines a second.
//
// Every accept in an agent chain requires the agent's own IPv4 source
// address, so an agent cannot borrow another agent's address or connections,
// and IPv6 is dropped. The forward chain accepts the agent's established and
// related traffic and new traffic to its targets, held in the sets t_<id>
// (TCP) and u_<id> (UDP), when it does not leave through another agent's
// veth. The input chain is separate and opens one thing only: TCP to the
// agent's proxy port on the root end of its veth. So a target that covers
// this machine's own addresses opens nothing on it.
package netns

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

const (
	table       = "inet corral"
	agentIfaces = `"ocv*"` // an nftables name pattern
	forwardMap  = "forward_agents"
	inputMap    = "input_agents"
	logRate     = "10/second"
	logPrefix   = "corral-drop "
	// maxElements bounds the set elements one agent's targets may become,
	// and so the size of the text handed to the kernel.
	maxElements = 4096
)

// unknownDrop logs, at a limited rate, a packet that belongs to no agent's
// rules and is about to be dropped.
const unknownDrop = "limit rate " + logRate + ` log prefix "` + logPrefix + `? "`

// renderBase returns the text that creates table inet corral, its maps and
// its base chains where they are missing, and sets the base chains' rules.
// Loading it again gives the same result and keeps the agents' entries.
func renderBase() string {
	lines := []string{
		"table " + table + " {",
		"\tmap " + forwardMap + " {",
		"\t\ttype ifname : verdict;",
		"\t}",
		"\tmap " + inputMap + " {",
		"\t\ttype ifname : verdict;",
		"\t}",
		"\tchain forward {",
		"\t\ttype filter hook forward priority filter; policy accept;",
		"\t}",
		"\tchain input {",
		"\t\ttype filter hook input priority filter; policy accept;",
		"\t}",
		"\tchain postrouting {",
		"\t\ttype nat hook postrouting priority srcnat; policy accept;",
		"\t}",
		"}",
		"flush chain " + table + " forward",
		"flush chain " + table + " input",
		"flush chain " + table + " postrouting",
		"table " + table + " {",
		"\tchain forward {",
		"\t\ttype filter hook forward priority filter; policy accept;",
		"\t\tiifname " + agentIfaces + " iifname vmap @" + forwardMap,
		"\t\tiifname " + agentIfaces + " " + unknownDrop,
		"\t\tiifname " + agentIfaces + " drop",
		"\t\toifname " + agentIfaces + " ct state established,related accept",
		"\t\toifname " + agentIfaces + " " + unknownDrop,
		"\t\toifname " + agentIfaces + " drop",
		"\t}",
		"\tchain input {",
		"\t\ttype filter hook input priority filter; policy accept;",
		"\t\tiifname " + agentIfaces + " iifname vmap @" + inputMap,
		"\t\tiifname " + agentIfaces + " " + unknownDrop,
		"\t\tiifname " + agentIfaces + " drop",
		"\t\tiifname != \"lo\" ip daddr " + agentNetwork + " " + unknownDrop,
		"\t\tiifname != \"lo\" ip daddr " + agentNetwork + " drop",
		"\t}",
		"\tchain postrouting {",
		"\t\ttype nat hook postrouting priority srcnat; policy accept;",
		"\t\tiifname " + agentIfaces + " oifname != " + agentIfaces + " ip saddr " + agentNetwork + " masquerade",
		"\t}",
		"}",
	}
	return strings.Join(lines, "\n") + "\n"
}

// renderAgent returns the text that sets up one agent's sets and chains and
// enters its veth in both maps. Loading it again replaces the agent's rules
// and set contents. If the veth is already mapped to another agent's chain,
// the kernel refuses the map entry and with it the whole text.
//
// agentID and slot must have passed parseAgentID and parseSlot, and targets
// come from parseTarget; renderAgent panics otherwise.
func renderAgent(agentID string, slot int, targets []Target) string {
	n := namesFor(agentID, slot)
	tcp, udp, err := setContents(targets)
	if err != nil {
		panic("netns: unchecked targets: " + err.Error())
	}
	from := "ip saddr " + n.AgentIP
	drop := []string{
		"\t\tlimit name \"" + n.Limit + `" log prefix "` + logPrefix + agentID + ` "`,
		"\t\tdrop",
	}

	lines := declarations(n)
	lines = append(lines,
		"flush chain "+table+" "+n.Chain,
		"flush chain "+table+" "+n.InChain,
		"flush set "+table+" "+n.TCPSet,
		"flush set "+table+" "+n.UDPSet,
		"table "+table+" {",
	)
	lines = append(lines, setBlock(n.TCPSet, tcp)...)
	lines = append(lines, setBlock(n.UDPSet, udp)...)
	lines = append(lines,
		"\tchain "+n.Chain+" {",
		"\t\t"+from+" ct state established,related accept",
		"\t\t"+from+" oifname != "+agentIfaces+" ip daddr . tcp dport @"+n.TCPSet+" accept",
		"\t\t"+from+" oifname != "+agentIfaces+" ip daddr . udp dport @"+n.UDPSet+" accept",
	)
	lines = append(lines, drop...)
	lines = append(lines,
		"\t}",
		"\tchain "+n.InChain+" {",
		"\t\t"+from+" ip daddr "+n.RootIP+" tcp dport "+strconv.Itoa(n.ProxyPort)+" accept",
	)
	lines = append(lines, drop...)
	lines = append(lines,
		"\t}",
		"}",
		mapEntry(forwardMap, n.Veth, n.Chain),
		mapEntry(inputMap, n.Veth, n.InChain),
	)
	return strings.Join(lines, "\n") + "\n"
}

// renderTargets returns the text that replaces the contents of an agent's
// two sets with targets, which must be the agent's complete list. The sets
// are flushed and refilled in one transaction, because an interval set
// refuses an element that overlaps one it already holds.
func renderTargets(agentID string, targets []Target) string {
	n := setNames(agentID)
	tcp, udp, err := setContents(targets)
	if err != nil {
		panic("netns: unchecked targets: " + err.Error())
	}
	lines := []string{
		"flush set " + table + " " + n.TCPSet,
		"flush set " + table + " " + n.UDPSet,
	}
	if len(tcp) > 0 {
		lines = append(lines, "add element "+table+" "+n.TCPSet+" { "+strings.Join(tcp, ", ")+" }")
	}
	if len(udp) > 0 {
		lines = append(lines, "add element "+table+" "+n.UDPSet+" { "+strings.Join(udp, ", ")+" }")
	}
	return strings.Join(lines, "\n") + "\n"
}

// renderRemove returns the text that deletes an agent's map entries, chains
// and sets. It declares each of them first, so it also succeeds when some
// are already gone; if the veth is mapped to another agent's chain, the
// kernel refuses the whole text.
func renderRemove(agentID string, slot int) string {
	n := namesFor(agentID, slot)
	lines := declarations(n)
	lines = append(lines,
		mapEntry(forwardMap, n.Veth, n.Chain),
		mapEntry(inputMap, n.Veth, n.InChain),
		"delete element "+table+" "+forwardMap+` { "`+n.Veth+`" }`,
		"delete element "+table+" "+inputMap+` { "`+n.Veth+`" }`,
		"flush chain "+table+" "+n.Chain,
		"flush chain "+table+" "+n.InChain,
		"delete chain "+table+" "+n.Chain,
		"delete chain "+table+" "+n.InChain,
		"delete set "+table+" "+n.TCPSet,
		"delete set "+table+" "+n.UDPSet,
		"delete limit "+table+" "+n.Limit,
	)
	return strings.Join(lines, "\n") + "\n"
}

// setNames is namesFor for the set names alone, which need no slot.
func setNames(agentID string) names {
	if !validAgentID(agentID) {
		panic(fmt.Sprintf("netns: unchecked agent id %q", agentID))
	}
	return names{TCPSet: "t_" + agentID, UDPSet: "u_" + agentID}
}

// declarations declares the maps and an agent's empty sets and chains and
// its limit, so that the flush and delete commands after it find them.
func declarations(n names) []string {
	lines := []string{
		"table " + table + " {",
		"\tmap " + forwardMap + " {",
		"\t\ttype ifname : verdict;",
		"\t}",
		"\tmap " + inputMap + " {",
		"\t\ttype ifname : verdict;",
		"\t}",
	}
	lines = append(lines, setBlock(n.TCPSet, nil)...)
	lines = append(lines, setBlock(n.UDPSet, nil)...)
	return append(lines,
		"\tlimit "+n.Limit+" {",
		"\t\trate "+logRate,
		"\t}",
		"\tchain "+n.Chain+" {",
		"\t}",
		"\tchain "+n.InChain+" {",
		"\t}",
		"}",
	)
}

func setBlock(name string, elements []string) []string {
	lines := []string{
		"\tset " + name + " {",
		"\t\ttype ipv4_addr . inet_service;",
		"\t\tflags interval;",
	}
	if len(elements) > 0 {
		lines = append(lines, "\t\telements = { "+strings.Join(elements, ", ")+" }")
	}
	return append(lines, "\t}")
}

func mapEntry(mapName, veth, chain string) string {
	return "add element " + table + " " + mapName + ` { "` + veth + `" : jump ` + chain + " }"
}

// setContents returns the elements of an agent's TCP and UDP sets, or an
// error when together they would be more than maxElements.
func setContents(targets []Target) (tcp, udp []string, err error) {
	tcp, udp = normalise(targets, "tcp"), normalise(targets, "udp")
	if count := len(tcp) + len(udp); count > maxElements {
		return nil, nil, fmt.Errorf("targets make %d set elements, more than %d", count, maxElements)
	}
	return tcp, udp, nil
}

// portRange is an inclusive range of ports.
type portRange struct{ first, last int }

// normalise turns the targets of one protocol into set elements
// "<addr[/prefix]> . <port[-port]>" that cover the same addresses and ports
// and do not overlap one another, sorted.
//
// Networks are either nested or disjoint. Each network keeps the parts of it
// that no narrower target network covers, and gives them the ports of every
// target whose network holds it. A network whose ports the wider networks
// already grant is left out, so it does not split the wider one.
//
// It panics on a target parseTarget could not have returned.
func normalise(targets []Target, proto string) []string {
	ports := map[netip.Prefix][]portRange{}
	for _, t := range targets {
		if !t.valid() {
			panic(fmt.Sprintf("netns: unchecked target %+v", t))
		}
		if t.Proto == proto {
			ports[t.Network] = append(ports[t.Network], portRange{int(t.First), int(t.Last)})
		}
	}
	networks := make([]netip.Prefix, 0, len(ports))
	for network := range ports {
		networks = append(networks, network)
	}
	slices.SortFunc(networks, comparePrefixes)

	// Keep a network only if it adds ports to those of the wider networks.
	var kept []netip.Prefix
	for _, network := range networks {
		var wider []portRange
		for _, other := range networks {
			if other != network && within(network, other) {
				wider = append(wider, ports[other]...)
			}
		}
		if !coveredBy(mergePorts(ports[network]), mergePorts(wider)) {
			kept = append(kept, network)
		}
	}

	type element struct {
		block netip.Prefix
		ports portRange
	}
	var elements []element
	for _, network := range kept {
		// The parts of network outside the narrower kept networks get the
		// ports of every network that holds network, itself included.
		var inner []netip.Prefix
		for _, other := range kept {
			if other != network && within(other, network) {
				inner = append(inner, other)
			}
		}
		var holding []portRange
		for _, other := range networks {
			if within(network, other) {
				holding = append(holding, ports[other]...)
			}
		}
		portsHere := mergePorts(holding)
		for _, block := range exclude(network, inner) {
			for _, r := range portsHere {
				elements = append(elements, element{block, r})
			}
		}
	}
	slices.SortFunc(elements, func(a, b element) int {
		if c := comparePrefixes(a.block, b.block); c != 0 {
			return c
		}
		return a.ports.first - b.ports.first
	})

	texts := make([]string, 0, len(elements))
	for _, e := range elements {
		addr := e.block.String()
		if e.block.IsSingleIP() {
			addr = e.block.Addr().String()
		}
		ports := strconv.Itoa(e.ports.first)
		if e.ports.last != e.ports.first {
			ports += "-" + strconv.Itoa(e.ports.last)
		}
		texts = append(texts, addr+" . "+ports)
	}
	return texts
}

// within reports whether inner lies inside outer (or is outer).
func within(inner, outer netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

func comparePrefixes(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

// mergePorts sorts ranges and joins those that overlap or touch.
func mergePorts(ranges []portRange) []portRange {
	sorted := slices.Clone(ranges)
	slices.SortFunc(sorted, func(a, b portRange) int { return a.first - b.first })
	var merged []portRange
	for _, r := range sorted {
		if last := len(merged) - 1; last >= 0 && r.first <= merged[last].last+1 {
			merged[last].last = max(merged[last].last, r.last)
			continue
		}
		merged = append(merged, r)
	}
	return merged
}

// coveredBy reports whether every range in ranges lies inside one range of
// cover. Both must be merged.
func coveredBy(ranges, cover []portRange) bool {
	for _, r := range ranges {
		if !slices.ContainsFunc(cover, func(c portRange) bool { return c.first <= r.first && r.last <= c.last }) {
			return false
		}
	}
	return true
}

// exclude returns prefixes that cover network except the holes, each of
// which lies inside network.
func exclude(network netip.Prefix, holes []netip.Prefix) []netip.Prefix {
	blocks := []netip.Prefix{network}
	for _, hole := range holes {
		var rest []netip.Prefix
		for _, block := range blocks {
			switch {
			case within(block, hole):
				// The hole covers the whole block.
			case within(hole, block):
				rest = append(rest, cutOut(block, hole)...)
			default:
				rest = append(rest, block)
			}
		}
		blocks = rest
	}
	return blocks
}

// cutOut returns the prefixes that cover block except hole, which lies
// inside it: halve the block until the hole is reached, keeping the halves
// that do not hold it.
func cutOut(block, hole netip.Prefix) []netip.Prefix {
	var rest []netip.Prefix
	for block.Bits() < hole.Bits() {
		lower, upper := halves(block)
		if lower.Contains(hole.Addr()) {
			rest = append(rest, upper)
			block = lower
		} else {
			rest = append(rest, lower)
			block = upper
		}
	}
	return rest
}

// halves splits an IPv4 prefix into its two halves.
func halves(p netip.Prefix) (lower, upper netip.Prefix) {
	bits := p.Bits() + 1
	a := p.Addr().As4()
	value := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	value |= 1 << (32 - bits)
	high := netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
	return netip.PrefixFrom(p.Addr(), bits), netip.PrefixFrom(high, bits)
}
