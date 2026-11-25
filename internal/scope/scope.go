// Package scope describes what one agent may reach: network targets and
// folders. The texts it parses come from configuration, the addresses and
// paths it matches may come from an agent, so both sides refuse anything
// that is not plainly well formed.
package scope

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
)

// MaxTargets is the largest number of targets one scope may hold.
const MaxTargets = 256

// minPrefix is the widest network a target may name: a /8.
const minPrefix = 8

// Target is one network target: an IPv4 network, a protocol and a port range.
type Target struct {
	Network     netip.Prefix // a single host is a /32
	Proto       string       // "tcp" or "udp"
	First, Last uint16
}

// ParseTarget parses a target of the form <ip[/prefix]>:<tcp|udp>:<port[-port]>,
// for example "10.10.4.7:tcp:445" or "10.10.4.0/24:tcp:1-1024".
func ParseTarget(text string) (Target, error) {
	parts := strings.Split(text, ":")
	if len(parts) != 3 {
		return Target{}, fmt.Errorf("target must be <ip[/prefix]>:<tcp|udp>:<port[-port]>: %.80q", text)
	}
	addrText, proto, portsText := parts[0], parts[1], parts[2]
	if proto != "tcp" && proto != "udp" {
		return Target{}, fmt.Errorf("protocol must be tcp or udp: %.80q", proto)
	}
	network, err := parseNetwork(addrText)
	if err != nil {
		return Target{}, err
	}
	firstText, lastText, isRange := strings.Cut(portsText, "-")
	first, err := parsePort(firstText)
	if err != nil {
		return Target{}, err
	}
	last := first
	if isRange {
		if last, err = parsePort(lastText); err != nil {
			return Target{}, err
		}
	}
	if first > last {
		return Target{}, fmt.Errorf("port range %q runs backwards", portsText)
	}
	return Target{Network: network, Proto: proto, First: first, Last: last}, nil
}

// parseNetwork parses an IPv4 address or an IPv4 network in /<bits> form.
// Host bits must be zero, so that the text says exactly what it covers.
func parseNetwork(text string) (netip.Prefix, error) {
	addrText, bitsText, hasBits := strings.Cut(text, "/")
	addr, err := netip.ParseAddr(addrText)
	if err != nil || !addr.Is4() {
		return netip.Prefix{}, fmt.Errorf("bad IPv4 address %.80q", addrText)
	}
	bits := 32
	if hasBits {
		// Only /<digits>; the netmask form 10.0.0.0/255.0.0.0 is refused here.
		n, ok := decimal(bitsText, 2)
		if !ok || n > 32 {
			return netip.Prefix{}, fmt.Errorf("bad prefix length in %.80q", text)
		}
		bits = n
	}
	if bits < minPrefix {
		return netip.Prefix{}, fmt.Errorf("network %q is wider than /%d", text, minPrefix)
	}
	network := netip.PrefixFrom(addr, bits)
	if network.Masked() != network {
		return netip.Prefix{}, fmt.Errorf("network %q has host bits set", text)
	}
	return network, nil
}

// parsePort parses a port number from 1 to 65535.
func parsePort(text string) (uint16, error) {
	n, ok := decimal(text, 5)
	if !ok || n < 1 || n > 65535 {
		return 0, fmt.Errorf("bad port %.20q: want a number from 1 to 65535", text)
	}
	return uint16(n), nil
}

// decimal parses one to maxDigits ASCII digits without a leading zero (a
// lone "0" is allowed). It refuses signs, spaces and other Unicode digits,
// which strconv.Atoi would partly accept.
func decimal(text string, maxDigits int) (int, bool) {
	if text == "" || len(text) > maxDigits || (len(text) > 1 && text[0] == '0') {
		return 0, false
	}
	for _, c := range []byte(text) {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(text)
	return n, err == nil
}

// String returns the target in the form ParseTarget reads, with a single
// host written without "/32" and a single port without a range.
func (t Target) String() string {
	addr := t.Network.String()
	if t.Network.IsSingleIP() {
		addr = t.Network.Addr().String()
	}
	ports := strconv.Itoa(int(t.First))
	if t.Last != t.First {
		ports += "-" + strconv.Itoa(int(t.Last))
	}
	return addr + ":" + t.Proto + ":" + ports
}

// allows reports whether the target covers addr, proto and port.
func (t Target) allows(addr netip.Addr, proto string, port int) bool {
	return proto == t.Proto && t.Network.Contains(addr) && int(t.First) <= port && port <= int(t.Last)
}

// Scope is what one agent may reach.
type Scope struct {
	Targets []Target
	Paths   []string // absolute, cleaned
}

// New builds a scope from target texts and folder paths. It refuses a bad
// target, more than MaxTargets targets, and a path that is not absolute or
// contains "..".
func New(targets, paths []string) (Scope, error) {
	if len(targets) > MaxTargets {
		return Scope{}, fmt.Errorf("more than %d targets", MaxTargets)
	}
	var s Scope
	for _, text := range targets {
		target, err := ParseTarget(text)
		if err != nil {
			return Scope{}, err
		}
		s.Targets = append(s.Targets, target)
	}
	for _, path := range paths {
		if !filepath.IsAbs(path) || hasDotDot(path) {
			return Scope{}, fmt.Errorf("path must be absolute and without '..': %q", path)
		}
		s.Paths = append(s.Paths, filepath.Clean(path))
	}
	return s, nil
}

// AllowsTarget reports whether some target covers the IPv4 address ip with
// proto and port. Anything that does not parse is not allowed.
func (s Scope) AllowsTarget(ip, proto string, port int) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return false
	}
	for _, t := range s.Targets {
		if t.allows(addr, proto, port) {
			return true
		}
	}
	return false
}

// AllowsPath reports whether resolved is one of the scope's folders or lies
// below one. The path must already be resolved: AllowsPath compares text and
// does not look at the file system. A relative path, a path with ".." and a
// path containing a NUL byte are never allowed.
func (s Scope) AllowsPath(resolved string) bool {
	if !filepath.IsAbs(resolved) || hasDotDot(resolved) || strings.ContainsRune(resolved, 0) {
		return false
	}
	path := filepath.Clean(resolved)
	for _, base := range s.Paths {
		// TrimSuffix keeps the root folder "/" from becoming the prefix "//".
		if path == base || strings.HasPrefix(path, strings.TrimSuffix(base, "/")+"/") {
			return true
		}
	}
	return false
}

// hasDotDot reports whether path has a ".." component.
func hasDotDot(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}
