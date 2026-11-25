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
	"strings"

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
		return deny("request kind %.200q is not decided automatically", r.Kind)
	}
}

// decidePath never answers for the session: each path is decided on its own.
func decidePath(path string, s scope.Scope, resolve func(string) (string, error)) integration.Decision {
	// A relative path is denied before it is resolved, so that it can never be
	// read against the supervisor's own working folder.
	if !filepath.IsAbs(path) {
		return deny("path %.200q is not absolute", path)
	}
	if strings.ContainsRune(path, 0) {
		return deny("path %.200q contains a NUL byte", path)
	}
	resolved, err := resolve(path)
	if err != nil {
		// A file system error repeats the path; name only its cause, so that the
		// path does not appear twice at full length.
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			err = pathErr.Err
		}
		return deny("cannot resolve path %.200q: %.150q", path, err)
	}
	if !s.AllowsPath(resolved) {
		return deny("%.200q is outside the scope", resolved)
	}
	return integration.Decision{Decision: "granted", Reason: fmt.Sprintf("%.200q is inside the scope", resolved)}
}

// decideNetwork checks every address as tcp, whatever protocol the agent
// meant: the scope's udp targets are not for agents to ask about.
func decideNetwork(r integration.Request, s scope.Scope) integration.Decision {
	if len(r.Addresses) == 0 {
		return deny("no resolved addresses for host %.200q", r.Host)
	}
	for _, addr := range r.Addresses {
		if !s.AllowsTarget(addr, "tcp", r.Port) {
			return deny("%.200q on tcp port %d is outside the scope", addr, r.Port)
		}
	}
	return integration.Decision{
		Decision: "grant_session",
		Reason:   fmt.Sprintf("all %d addresses of host %.200q are inside the scope on tcp port %d", len(r.Addresses), r.Host, r.Port),
	}
}

// deny builds a denial. Every request-supplied text in a reason is cut to
// 200 characters (%.200q), because reasons go into the event log.
func deny(format string, args ...any) integration.Decision {
	return integration.Decision{Decision: "denied", Reason: fmt.Sprintf(format, args...)}
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
