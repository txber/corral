package approval

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/txber/corral/integration"
	"github.com/txber/corral/internal/scope"
)

// split cuts text at sep into at most max items; an empty text is no item.
func split(text, sep string, max int) []string {
	if text == "" {
		return nil
	}
	items := strings.Split(text, sep)
	return items[:min(len(items), max)]
}

// FuzzDecide decides any request against any scope, with a resolver that
// answers resolvedTo, fails, or fails with an error that holds control
// characters, as failMode says.
func FuzzDecide(f *testing.F) {
	long := strings.Repeat("\U0010fffe", 300)
	f.Add("path", "/w/a/x", "/w/a/x", uint8(0), "", 0, "", "", "/w/a")
	f.Add("path", "/w/a/x", "/etc/x", uint8(0), "", 0, "", "", "/w/a")
	f.Add("path", "/data/../etc", "/data/../etc", uint8(0), "", 0, "", "", "/data")
	f.Add("path", "/data\x00/x", "/data/x", uint8(0), "", 0, "", "", "/data")
	f.Add("path", "/data2", "/data2", uint8(0), "", 0, "", "", "/data")
	f.Add("path", "data/x", "/data/x", uint8(0), "", 0, "", "", "/data")
	f.Add("path", "/data/\x1b[31m", "/data/x", uint8(2), "", 0, "", "", "/data")
	f.Add("path", "/"+long, "/"+long, uint8(1), "", 0, "", "", "/data")
	f.Add("PATH", "/data/x", "/data/x", uint8(0), "", 0, "", "", "/data")
	f.Add("network", "", "", uint8(0), "h", 445, "10.10.4.7,10.10.4.8", "10.10.4.0/24:tcp:1-1024", "")
	f.Add("network", "", "", uint8(0), "h", 445, "::ffff:10.10.4.7", "10.10.4.0/24:tcp:1-1024", "")
	f.Add("network", "", "", uint8(0), "h", 65536+445, "10.10.4.7", "10.10.4.0/24:tcp:1-1024", "")
	f.Add("network", "", "", uint8(0), "h", 53, "10.10.4.7", "10.10.4.7:udp:53", "")
	f.Add("network", "", "", uint8(0), long, 445, long, "10.10.4.0/24:tcp:1-1024", "")
	f.Add(long, "", "", uint8(0), "", 0, "", "", "")

	f.Fuzz(func(t *testing.T, kind, path, resolvedTo string, failMode uint8, host string, port int, addresses, targets, paths string) {
		s, err := scope.New(split(targets, "\n", 8), split(paths, "\n", 8))
		if err != nil {
			return
		}
		r := integration.Request{Kind: kind, ID: "r", Path: path, Access: "read", Host: host, Port: port, Addresses: split(addresses, ",", 16), Detail: host}
		var calls []string
		resolve := func(p string) (string, error) {
			calls = append(calls, p)
			switch failMode % 3 {
			case 1:
				return "", fmt.Errorf("resolve %s: failed", p)
			case 2:
				return "", &fs.PathError{Op: "lstat", Path: p, Err: errors.New("bad\x1b[0m\n" + p)}
			}
			return resolvedTo, nil
		}

		d := Decide(r, s, resolve)

		if !slices.Contains([]string{"granted", "denied", "grant_session", "deny_session"}, d.Decision) {
			t.Fatalf("decision %q", d.Decision)
		}
		if len(d.Reason) > 400 || !utf8.ValidString(d.Reason) {
			t.Fatalf("reason of %d bytes, valid UTF-8 %v", len(d.Reason), utf8.ValidString(d.Reason))
		}
		for _, c := range d.Reason {
			if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) || c == ' ' || c == ' ' {
				t.Fatalf("reason holds %U: %q", c, d.Reason)
			}
		}
		allowed := d.Decision == "granted" || d.Decision == "grant_session"

		switch kind {
		case "path":
			plain := strings.HasPrefix(path, "/") && !strings.ContainsRune(path, 0)
			if (!plain && len(calls) > 0) || slices.ContainsFunc(calls, func(c string) bool { return c != path }) {
				t.Fatalf("path %q: resolve called with %q", path, calls)
			}
			if d.Decision == "grant_session" {
				t.Fatalf("path %q answered for the session", path)
			}
			if allowed && (!plain || failMode%3 != 0 || !s.AllowsPath(resolvedTo) ||
				!strings.HasPrefix(resolvedTo, "/") || slices.Contains(strings.Split(resolvedTo, "/"), "..")) {
				t.Fatalf("path %q granted, resolved to %q, scope %q", path, resolvedTo, s.Paths)
			}
		case "network":
			if len(calls) > 0 {
				t.Fatal("resolve called for a network request")
			}
			if d.Decision == "granted" {
				t.Fatal("network request granted, not for the session")
			}
			if allowed && (len(r.Addresses) == 0 || port < 1 || port > 65535) {
				t.Fatalf("network request granted with addresses %q on port %d", r.Addresses, port)
			}
			for _, a := range r.Addresses {
				if allowed && !coveredOnTCP(s, a, port) {
					t.Fatalf("network request granted, %q on tcp port %d is outside the scope", a, port)
				}
			}
		default:
			if allowed || len(calls) > 0 {
				t.Fatalf("kind %q: decision %q, resolve called %d times", kind, d.Decision, len(calls))
			}
		}
	})
}

// coveredOnTCP reports whether address is a plain IPv4 address that a tcp
// target of s covers on port, checked without AllowsTarget.
func coveredOnTCP(s scope.Scope, address string, port int) bool {
	addr, err := netip.ParseAddr(address)
	if err != nil || !addr.Is4() || addr.String() != address {
		return false
	}
	for _, target := range s.Targets {
		if target.Proto == "tcp" && target.Network.Contains(addr) && int(target.First) <= port && port <= int(target.Last) {
			return true
		}
	}
	return false
}
