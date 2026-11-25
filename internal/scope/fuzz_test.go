package scope

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// lines splits fuzzed text into a list, one item per line.
func lines(text string) []string {
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// FuzzAllowsTarget compares AllowsTarget with a plain reference: the address
// must be IPv4 in dotted-quad form, and a target covers it when the network
// bits match under the mask and the port lies in the range. It also checks
// what every target New keeps must be, so that no wider or malformed target
// can make the reference agree with a wrong answer.
func FuzzAllowsTarget(f *testing.F) {
	f.Add("10.10.4.0/24:tcp:1-1024", "10.10.4.9", "tcp", 80, uint32(0))
	f.Add("10.10.4.0/24:tcp:1-1024", "10.10.4.9", "tcp", 1024, uint32(255))
	f.Add("10.10.4.0/24:tcp:1-1024", "10.10.5.9", "udp", 2000, uint32(256))
	f.Add("10.10.4.7:udp:53\n10.10.4.7:tcp:445", "10.10.4.7", "udp", 53, uint32(0))
	f.Add("10.0.0.0/8:tcp:1-65535", "::ffff:10.0.0.1", "tcp", 1, uint32(1))
	f.Add("10.0.0.0/8:tcp:1-65535", "fe80::1%eth0", "tcp", 65535, uint32(0))
	f.Add("10.0.0.0/8:tcp:1-65535", "010.0.0.1", "tcp", 65536, uint32(0xffffff))
	f.Add("10.0.0.0/8:tcp:1-65535", "10.0.0.1%eth0", "tcp", 0, uint32(0x1000000))
	f.Add("192.168.1.255:tcp:65535", "192.168.1.255", "TCP", 65535, uint32(0))
	f.Add("192.0.2.4:tcp:1", "192.0.2.4", "tcp", -1, uint32(0))
	f.Add("192.0.2.4:tcp:1", " 192.0.2.4", "tcp", 1<<40+1, uint32(0))
	f.Add("255.255.255.255/32:udp:1-2", "255.255.255.255", "udp", 2, uint32(1))
	f.Add("0.0.0.0/0:tcp:80", "10.0.0.1", "tcp", 80, uint32(0))
	f.Add("", "10.0.0.1", "tcp", 80, uint32(0))
	f.Fuzz(func(t *testing.T, targetText, ip, proto string, port int, offset uint32) {
		s, err := New(lines(targetText), nil)
		if err != nil {
			return
		}
		for _, tg := range s.Targets {
			n := tg.Network
			if !n.Addr().Is4() || n.Bits() < 8 || n.Masked() != n ||
				(tg.Proto != "tcp" && tg.Proto != "udp") || tg.First < 1 || tg.First > tg.Last {
				t.Fatalf("New(%q) kept target %+v", targetText, tg)
			}
		}

		check := func(ip, proto string, port int) {
			got := s.AllowsTarget(ip, proto, port)
			if want := referenceAllowsTarget(s.Targets, ip, proto, port); got != want {
				t.Fatalf("AllowsTarget(%q, %q, %d) = %v, want %v; targets %q", ip, proto, port, got, want, targetText)
			}
			if got && netip.MustParseAddr(ip).String() != ip {
				t.Fatalf("AllowsTarget granted %q, which is not in dotted-quad form", ip)
			}
		}
		check(ip, proto, port)
		// Addresses at an offset from each network reach the allowed side,
		// and the same address in IPv6 or zoned form must still be refused.
		for _, tg := range s.Targets {
			a := tg.Network.Addr().As4()
			binary.BigEndian.PutUint32(a[:], binary.BigEndian.Uint32(a[:])+offset)
			near := netip.AddrFrom4(a).String()
			check(near, tg.Proto, port)
			check(near, tg.Proto, int(tg.First))
			check(near, tg.Proto, int(tg.Last)+1)
			check("::ffff:"+near, tg.Proto, int(tg.First))
			check(near+"%eth0", tg.Proto, int(tg.First))
		}
	})
}

// referenceAllowsTarget is AllowsTarget written with integer masks.
func referenceAllowsTarget(targets []Target, ip, proto string, port int) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return false
	}
	a := addr.As4()
	value := binary.BigEndian.Uint32(a[:])
	for _, tg := range targets {
		n := tg.Network.Addr().As4()
		mask := ^uint32(0) << (32 - tg.Network.Bits())
		if tg.Proto == proto && value&mask == binary.BigEndian.Uint32(n[:]) &&
			int(tg.First) <= port && port <= int(tg.Last) {
			return true
		}
	}
	return false
}

// FuzzAllowsPath compares AllowsPath with a reference that works on path
// elements, not on text: a resolved path is allowed when it is absolute, holds
// no NUL byte and no ".." element, and the elements of some scope folder
// begin its own. So "/data2" is not below "/data", while "//data/./x" is.
func FuzzAllowsPath(f *testing.F) {
	f.Add("/data", "/data/x")
	f.Add("/data", "/data2")
	f.Add("/data", "/data2/x")
	f.Add("/data", "/data/../etc")
	f.Add("/data", "/data/./x")
	f.Add("/data", "//data")
	f.Add("/data", "/data/")
	f.Add("/data", "/data\x00/x")
	f.Add("/data", "/data/...")
	f.Add("/data", "/data/..x")
	f.Add("/data/", "/data")
	f.Add("/w/./a/", "/w/a/b")
	f.Add("/w/a", "w/a")
	f.Add("/w/a\n/x", "/x/../w/a")
	f.Add("/a/b", "/a")
	f.Add("/", "/etc/passwd")
	f.Add("/", "")
	f.Add("/da\x00ta", "/da\x00ta")
	f.Fuzz(func(t *testing.T, pathText, resolved string) {
		s, err := New(nil, lines(pathText))
		if err != nil {
			return
		}
		for _, p := range s.Paths {
			names := strings.Split(p, "/")
			if !strings.HasPrefix(p, "/") || slices.Contains(names, ".") || slices.Contains(names, "..") {
				t.Fatalf("New(%q) kept %q, which is not an absolute path without . and ..", pathText, p)
			}
		}
		got := s.AllowsPath(resolved)
		if want := referenceAllowsPath(s.Paths, resolved); got != want {
			t.Fatalf("AllowsPath(%q) = %v, want %v; scope folders %q", resolved, got, want, s.Paths)
		}
	})
}

func referenceAllowsPath(folders []string, resolved string) bool {
	if !strings.HasPrefix(resolved, "/") || strings.Contains(resolved, "\x00") {
		return false
	}
	if slices.Contains(strings.Split(resolved, "/"), "..") {
		return false
	}
	path := elements(resolved)
	for _, folder := range folders {
		base := elements(folder)
		if len(base) <= len(path) && slices.Equal(base, path[:len(base)]) {
			return true
		}
	}
	return false
}

// elements returns the names in a path, without empty and "." elements.
func elements(path string) []string {
	var names []string
	for _, name := range strings.Split(path, "/") {
		if name != "" && name != "." {
			names = append(names, name)
		}
	}
	return names
}
