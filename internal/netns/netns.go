// Package netns is the root helper behind "corral netns": it gives each agent
// its own network namespace, joined to the root namespace by a veth pair, and
// nftables rules that let the agent reach only its targets and one proxy port.
//
// The helper runs as root through sudo, on arguments an unprivileged caller
// chooses. Every argument is checked against a strict grammar before anything
// is rendered or run, and the rules are built only from checked values. The
// package uses the standard library only.
//
// This file holds the naming scheme and the command line; rules.go renders
// the nftables text, system.go runs the commands, state.go keeps a record
// of each agent and envfile.go reads the environment of a launched command.
package netns

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// The naming and address scheme. An agent with id <id> in slot <n> gets:
//
//	network namespace  oc-<id>
//	veth, root end     ocv<n>, address 198.18.<n>.1/30
//	veth, agent end    address 198.18.<n>.2/30
//	proxy port         18000+<n>, on 198.18.<n>.1
//	nftables           chains a_<id> (forward) and i_<id> (input),
//	                   sets t_<id> (TCP) and u_<id> (UDP), in table inet corral
const (
	netnsPrefix   = "oc-"
	vethPrefix    = "ocv"
	addressPrefix = "198.18."
	agentNetwork  = addressPrefix + "0.0/16" // every agent address lies in it
	proxyPortBase = 18000
)

// Limits on what a caller may ask for.
const (
	minSlot    = 1
	maxSlot    = 250
	maxTargets = 256
	minPrefix  = 8  // the widest network a target may name
	maxIDLen   = 12 // the id rule: a letter and up to 11 letters or digits
)

const usage = `usage:
  corral netns up    <agent_id> <slot> [--target <target>]...
  corral netns allow <agent_id> <slot> --target <target> [--target <target>]...
  corral netns exec  <agent_id> --env-file <path> -- <command> [<arg>...]
  corral netns down  <agent_id> <slot>
  corral netns list

<agent_id> is a lowercase letter and up to 11 lowercase letters or digits,
<slot> a number from 1 to 250, and <target> <ip[/prefix]>:<tcp|udp>:<port[-port]>,
for example 10.10.4.0/24:tcp:1-1024 or 192.0.2.7:udp:53.
`

// Main runs one "corral netns" command line (without "netns") and returns the
// exit code: 2 for a bad command line, 1 for a failed command.
func Main(args []string, stdout, stderr io.Writer) int {
	c, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "corral netns: %v\n\n%s", err, usage)
		return 2
	}
	if err := execute(c, stdout); err != nil {
		fmt.Fprintf(stderr, "corral netns: %s: %v\n", c.name, err)
		return 1
	}
	return 0
}

// Target is one network target: an IPv4 network, a protocol and a port range.
// It has the same meaning and text form as a target of the scope package.
type Target struct {
	Network     netip.Prefix // a single host is a /32
	Proto       string       // "tcp" or "udp"
	First, Last uint16
}

// String returns the text form parseTarget reads: the address alone for a
// single host, the port alone for a single port.
func (t Target) String() string {
	address := t.Network.String()
	if t.Network.IsSingleIP() {
		address = t.Network.Addr().String()
	}
	ports := strconv.Itoa(int(t.First))
	if t.Last != t.First {
		ports += "-" + strconv.Itoa(int(t.Last))
	}
	return address + ":" + t.Proto + ":" + ports
}

// valid reports whether t is a target parseTarget could have returned. The
// renderer checks it again, because only these values reach the rules.
func (t Target) valid() bool {
	return t.Network.IsValid() && t.Network.Addr().Is4() &&
		t.Network.Bits() >= minPrefix && t.Network.Masked() == t.Network &&
		(t.Proto == "tcp" || t.Proto == "udp") &&
		t.First >= 1 && t.First <= t.Last
}

// names is every name and address that belongs to one agent.
type names struct {
	Netns, Veth, RootIP, AgentIP, Chain, InChain, TCPSet, UDPSet, Limit string
	ProxyPort                                                           int
}

// namesFor derives an agent's names from a checked agent id and slot. It
// panics on values that did not pass parseAgentID and parseSlot: that is a
// bug in the caller, and no rule may be built from such values.
func namesFor(agentID string, slot int) names {
	if !validAgentID(agentID) || slot < minSlot || slot > maxSlot {
		panic(fmt.Sprintf("netns: unchecked agent id %q or slot %d", agentID, slot))
	}
	n := strconv.Itoa(slot)
	return names{
		Netns:     netnsPrefix + agentID,
		Veth:      vethPrefix + n,
		RootIP:    addressPrefix + n + ".1",
		AgentIP:   addressPrefix + n + ".2",
		Chain:     "a_" + agentID,
		InChain:   "i_" + agentID,
		TCPSet:    "t_" + agentID,
		UDPSet:    "u_" + agentID,
		Limit:     "l_" + agentID,
		ProxyPort: proxyPortBase + slot,
	}
}

// parseAgentID accepts a lowercase ASCII letter followed by up to eleven
// lowercase ASCII letters or digits.
func parseAgentID(text string) (string, error) {
	if !validAgentID(text) {
		return "", fmt.Errorf("bad agent id %.40q: want a lowercase letter and up to 11 lowercase letters or digits", text)
	}
	return text, nil
}

func validAgentID(text string) bool {
	if text == "" || len(text) > maxIDLen || text[0] < 'a' || text[0] > 'z' {
		return false
	}
	for _, c := range []byte(text) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// parseSlot accepts a number from 1 to 250 written without a leading zero.
func parseSlot(text string) (int, error) {
	n, ok := decimal(text, 3)
	if !ok || n < minSlot || n > maxSlot {
		return 0, fmt.Errorf("bad slot %.40q: want a number from %d to %d", text, minSlot, maxSlot)
	}
	return n, nil
}

// parseTarget reads <ip[/prefix]>:<tcp|udp>:<port[-port]> and accepts exactly
// what scope.ParseTarget accepts. The rules are built from the parsed values,
// never from the text.
func parseTarget(text string) (Target, error) {
	t, err := readTarget(text)
	if err != nil {
		return Target{}, fmt.Errorf("bad target %.80q: %w", text, err)
	}
	return t, nil
}

func readTarget(text string) (Target, error) {
	parts := strings.Split(text, ":")
	if len(parts) != 3 {
		return Target{}, errors.New("want <ip[/prefix]>:<tcp|udp>:<port[-port]>")
	}
	addrText, proto, portsText := parts[0], parts[1], parts[2]
	if proto != "tcp" && proto != "udp" {
		return Target{}, errors.New("protocol must be tcp or udp")
	}

	addrText, bitsText, hasBits := strings.Cut(addrText, "/")
	addr, err := netip.ParseAddr(addrText)
	if err != nil || !addr.Is4() {
		return Target{}, errors.New("want an IPv4 address")
	}
	bits := 32
	if hasBits {
		// Only /<digits>; the netmask form /255.255.255.0 is refused.
		n, ok := decimal(bitsText, 2)
		if !ok || n > 32 {
			return Target{}, errors.New("bad prefix length")
		}
		bits = n
	}
	if bits < minPrefix {
		return Target{}, fmt.Errorf("network is wider than /%d", minPrefix)
	}
	network := netip.PrefixFrom(addr, bits)
	if network.Masked() != network {
		return Target{}, errors.New("network has host bits set")
	}

	firstText, lastText, isRange := strings.Cut(portsText, "-")
	first, ok := port(firstText)
	if !ok {
		return Target{}, errors.New("bad port: want a number from 1 to 65535")
	}
	last := first
	if isRange {
		if last, ok = port(lastText); !ok {
			return Target{}, errors.New("bad port: want a number from 1 to 65535")
		}
	}
	if first > last {
		return Target{}, errors.New("port range runs backwards")
	}
	return Target{Network: network, Proto: proto, First: first, Last: last}, nil
}

// port parses a port number from 1 to 65535.
func port(text string) (uint16, bool) {
	n, ok := decimal(text, 5)
	if !ok || n < 1 || n > 65535 {
		return 0, false
	}
	return uint16(n), true
}

// decimal parses one to maxDigits ASCII digits without a leading zero (a lone
// "0" is allowed). It refuses signs, spaces and other Unicode digits.
func decimal(text string, maxDigits int) (int, bool) {
	if text == "" || len(text) > maxDigits || (len(text) > 1 && text[0] == '0') {
		return 0, false
	}
	n := 0
	for _, c := range []byte(text) {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// command is one checked command line.
type command struct {
	name    string // up, allow, exec, down or list
	agentID string
	slot    int
	targets []Target
	envFile string   // exec only
	argv    []string // exec only: the command to run and its arguments
}

// parseArgs checks a whole command line; nothing may run before it passes.
// It reads the arguments by hand rather than with package flag, so that only
// the exact forms in the usage text are accepted ("--target=x" or "-target x"
// are not).
func parseArgs(args []string) (command, error) {
	if len(args) == 0 {
		return command{}, errors.New("no command given")
	}
	name, rest := args[0], args[1:]
	switch name {
	case "list":
		if len(rest) != 0 {
			return command{}, errors.New("list takes no arguments")
		}
		return command{name: name}, nil
	case "exec":
		return parseExec(rest)
	case "up", "allow", "down":
	default:
		return command{}, fmt.Errorf("unknown command %.40q", name)
	}

	if len(rest) < 2 {
		return command{}, fmt.Errorf("%s needs <agent_id> <slot>", name)
	}
	agentID, err := parseAgentID(rest[0])
	if err != nil {
		return command{}, err
	}
	slot, err := parseSlot(rest[1])
	if err != nil {
		return command{}, err
	}
	if name == "down" && len(rest) > 2 {
		return command{}, fmt.Errorf("down takes only <agent_id> <slot>, not %.40q", rest[2])
	}
	targets, err := parseTargets(rest[2:])
	if err != nil {
		return command{}, err
	}
	// Refuse targets that would make an oversized ruleset now, before
	// anything is rendered.
	if _, _, err := setContents(targets); err != nil {
		return command{}, err
	}
	if name == "allow" && len(targets) == 0 {
		return command{}, errors.New("allow needs at least one --target")
	}
	return command{name: name, agentID: agentID, slot: slot, targets: targets}, nil
}

// parseTargets reads a list of "--target <target>" pairs.
func parseTargets(args []string) ([]Target, error) {
	var targets []Target
	for len(args) > 0 {
		if args[0] != "--target" {
			return nil, fmt.Errorf("unexpected argument %.40q", args[0])
		}
		if len(args) < 2 {
			return nil, errors.New("--target needs a value")
		}
		if len(targets) == maxTargets {
			return nil, fmt.Errorf("more than %d targets", maxTargets)
		}
		t, err := parseTarget(args[1])
		if err != nil {
			return nil, err
		}
		targets = append(targets, t)
		args = args[2:]
	}
	return targets, nil
}

// parseExec reads "<agent_id> --env-file <path> -- <command> [<arg>...]".
// The command's own arguments are passed on as they are; only NUL bytes,
// which no argument can carry, are refused.
func parseExec(args []string) (command, error) {
	if len(args) < 5 || args[1] != "--env-file" || args[3] != "--" {
		return command{}, errors.New("exec needs <agent_id> --env-file <path> -- <command> [<arg>...]")
	}
	agentID, err := parseAgentID(args[0])
	if err != nil {
		return command{}, err
	}
	envFile := args[2]
	if !strings.HasPrefix(envFile, "/") || strings.Contains(envFile, "\x00") || hasDotDot(envFile) {
		return command{}, fmt.Errorf("bad --env-file %.80q: want an absolute path without ..", envFile)
	}
	argv := args[4:]
	if argv[0] == "" || strings.HasPrefix(argv[0], "-") {
		return command{}, fmt.Errorf("bad command %.80q", argv[0])
	}
	for _, arg := range argv {
		if strings.Contains(arg, "\x00") {
			return command{}, errors.New("command argument holds a NUL byte")
		}
	}
	return command{name: "exec", agentID: agentID, envFile: envFile, argv: argv}, nil
}

// hasDotDot reports whether path has a ".." element.
func hasDotDot(path string) bool {
	for _, element := range strings.Split(path, "/") {
		if element == ".." {
			return true
		}
	}
	return false
}
