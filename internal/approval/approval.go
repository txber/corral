// Package approval answers one permission request against an agent's scope.
// The request may be shaped by an agent under hostile influence, so every
// answer that is not clearly inside the scope is a denial, and nothing here
// panics or returns an error.
package approval

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/txber/corral/integration"
	"github.com/txber/corral/internal/scope"
)

// Decide answers r against s. A path is granted if it is absolute and its
// resolved form is inside the scope; a network request is granted for the
// session if every address is in the scope for tcp on the requested port.
// Everything else is denied. resolve turns a path into its real location;
// nil means Realpath.
func Decide(r integration.Request, s scope.Scope, resolve func(string) (string, error)) integration.Decision {
	if resolve == nil {
		resolve = Realpath
	}
	switch r.Kind {
	case "path":
		return decidePath(r.Path, s, resolve)
	case "network":
		return decideNetwork(r, s)
	default:
		return deny("request kind %s is not decided automatically", quote(r.Kind, 200))
	}
}

// decidePath never answers for the session: each path is decided on its own.
func decidePath(path string, s scope.Scope, resolve func(string) (string, error)) integration.Decision {
	// A relative path is denied before it is resolved, so that it can never be
	// read against the supervisor's own working folder.
	if !filepath.IsAbs(path) {
		return deny("path %s is not absolute", quote(path, 200))
	}
	if strings.ContainsRune(path, 0) {
		return deny("path %s contains a NUL byte", quote(path, 200))
	}
	resolved, err := resolve(path)
	if err != nil {
		// A file system error repeats the path; name only its cause, so that the
		// path does not appear twice at full length.
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			err = pathErr.Err
		}
		return deny("cannot resolve path %s: %s", quote(path, 200), quote(err.Error(), 150))
	}
	if !s.AllowsPath(resolved) {
		return deny("%s is outside the scope", quote(resolved, 200))
	}
	return integration.Decision{Decision: "granted", Reason: fmt.Sprintf("%s is inside the scope", quote(resolved, 200))}
}

// decideNetwork checks every address as tcp, whatever protocol the agent
// meant: the scope's udp targets are not for agents to ask about.
func decideNetwork(r integration.Request, s scope.Scope) integration.Decision {
	if len(r.Addresses) == 0 {
		return deny("no resolved addresses for host %s", quote(r.Host, 200))
	}
	for _, addr := range r.Addresses {
		if !s.AllowsTarget(addr, "tcp", r.Port) {
			return deny("%s on tcp port %d is outside the scope", quote(addr, 200), r.Port)
		}
	}
	return integration.Decision{
		Decision: "grant_session",
		Reason:   fmt.Sprintf("all %d addresses of host %s are inside the scope on tcp port %d", len(r.Addresses), quote(r.Host, 200), r.Port),
	}
}

// deny builds a denial. Reasons go into the event log, so every
// request-supplied text in one is quoted and cut (quote): a reason is at
// most 400 bytes.
func deny(format string, args ...any) integration.Decision {
	return integration.Decision{Decision: "denied", Reason: fmt.Sprintf(format, args...)}
}

// quote is text quoted as %q does, cut so that the quoted form is at most
// limit bytes. A rune that is not printable is escaped to up to ten bytes,
// so cutting the text to limit characters alone would not bound it.
func quote(text string, limit int) string {
	end, size := 0, len(`""`)
	for end < len(text) {
		_, n := utf8.DecodeRuneInString(text[end:])
		escaped := len(strconv.Quote(text[end:end+n])) - len(`""`)
		if size+escaped > limit {
			break
		}
		size += escaped
		end += n
	}
	return strconv.Quote(text[:end])
}

// Realpath returns the location an absolute path names once every symbolic
// link on the way is followed. The part of the path that does not exist yet
// is kept as written, cleaned, after the longest existing ancestor. It
// refuses a relative path, a dangling symbolic link (its target could lie
// anywhere) and ".." after a folder that does not exist (the kernel would
// refuse that path, and dropping the pair could name an existing link).
func Realpath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path %q is not absolute", path)
	}
	// The components are walked in order, as the kernel does: a ".." applies
	// to where the components before it really lead, not to their text.
	parts := strings.Split(path, "/")
	current := "/"
	for i, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			current = filepath.Dir(current) // current is resolved, so its parent is real
			continue
		}
		next := filepath.Join(current, part)
		if _, err := os.Lstat(next); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return missingTail(current, parts[i:])
			}
			return "", fmt.Errorf("resolve %q: %w", path, err)
		}
		resolved, err := filepath.EvalSymlinks(next)
		if err != nil {
			return "", fmt.Errorf("resolve %q: %w", path, err)
		}
		current = resolved
	}
	return current, nil
}

// missingTail appends the components that do not exist yet to the resolved
// ancestor.
func missingTail(ancestor string, tail []string) (string, error) {
	for _, part := range tail {
		if part == ".." {
			return "", fmt.Errorf("path has '..' after %q, which does not exist", filepath.Join(ancestor, tail[0]))
		}
	}
	return filepath.Join(append([]string{ancestor}, tail...)...), nil
}
