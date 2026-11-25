// This file reads the env file of "corral netns exec": the variables, and
// the only variables, the launched command gets. The helper reads it as
// root on behalf of an unprivileged caller, so it checks the opened file,
// not the path, and accepts only a small, plain file of the caller's own.
package netns

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"syscall"
)

// Limits on an env file.
const (
	maxEnvSize  = 64 << 10
	maxEnvLines = 64
)

// readEnvFile opens path for the user uid and returns its variables as
// "KEY=VALUE" strings. The file must be a regular file, not a symbolic
// link, owned by uid and of mode 600.
func readEnvFile(path string, uid int) ([]string, error) {
	// O_NOFOLLOW refuses a symbolic link as the last element, and
	// O_NONBLOCK keeps a FIFO from blocking the open; fstat below then
	// refuses everything that is not a regular file.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("env file %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("env file %s: %w", path, err)
	}
	switch {
	case st.Mode&syscall.S_IFMT != syscall.S_IFREG:
		return nil, fmt.Errorf("env file %s: not a regular file", path)
	case int(st.Uid) != uid:
		return nil, fmt.Errorf("env file %s: owned by uid %d, want %d", path, st.Uid, uid)
	case st.Mode&0o7777 != 0o600:
		return nil, fmt.Errorf("env file %s: mode %o, want 600", path, st.Mode&0o7777)
	case st.Size > maxEnvSize:
		return nil, fmt.Errorf("env file %s: larger than %d bytes", path, maxEnvSize)
	}
	// The size can still grow after fstat; read one byte more than allowed
	// to notice.
	data, err := io.ReadAll(io.LimitReader(file, maxEnvSize+1))
	if err != nil {
		return nil, fmt.Errorf("env file %s: %w", path, err)
	}
	if len(data) > maxEnvSize {
		return nil, fmt.Errorf("env file %s: larger than %d bytes", path, maxEnvSize)
	}
	env, err := parseEnv(data)
	if err != nil {
		return nil, fmt.Errorf("env file %s: %w", path, err)
	}
	return env, nil
}

// parseEnv reads lines of KEY=VALUE. A key is a letter or underscore and
// then letters, digits or underscores; a value is the rest of the line. Each
// key may appear once. Errors name the line, never a value.
func parseEnv(data []byte) ([]string, error) {
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, errors.New("holds a NUL byte")
	}
	text := strings.TrimSuffix(string(data), "\n")
	if text == "" {
		return []string{}, nil
	}
	lines := strings.Split(text, "\n")
	if len(lines) > maxEnvLines {
		return nil, fmt.Errorf("more than %d lines", maxEnvLines)
	}
	env := make([]string, 0, len(lines))
	var keys []string
	for i, line := range lines {
		key, value, ok := strings.Cut(line, "=")
		if !ok || !validEnvKey(key) {
			return nil, fmt.Errorf("line %d: want KEY=VALUE with a key of letters, digits and underscores", i+1)
		}
		if slices.Contains(keys, key) {
			return nil, fmt.Errorf("line %d: %s is set twice", i+1, key)
		}
		if unsafeForRoot(key, value) {
			return nil, fmt.Errorf("line %d: %s is not allowed, because the tools that launch the command run as root with it", i+1, key)
		}
		keys = append(keys, key)
		env = append(env, line)
	}
	return env, nil
}

func validEnvKey(key string) bool {
	if key == "" || key[0] >= '0' && key[0] <= '9' {
		return false
	}
	for _, c := range []byte(key) {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// unsafeForRoot reports whether a variable would change how nsenter and
// setpriv behave. Both run as root with the env file's environment until
// setpriv drops to the caller, and a root process gets none of the
// protection the C library gives a set-user-ID program. So the helper
// refuses what that library drops or distrusts in such a program: the
// dynamic loader's and the allocator's variables, the paths it loads code
// or data from, and locale names that are paths.
func unsafeForRoot(key, value string) bool {
	for _, prefix := range []string{"LD_", "MALLOC_", "GLIBC_"} {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	switch key {
	case "GCONV_PATH", "GETCONF_DIR", "HOSTALIASES", "LOCALDOMAIN", "LOCPATH",
		"NIS_PATH", "NLSPATH", "RESOLV_HOST_CONF", "RES_OPTIONS", "TMPDIR", "TZDIR":
		return true
	case "LANG", "LANGUAGE":
		return strings.Contains(value, "/")
	case "TZ":
		// A zone name such as Europe/Berlin is fine; a file is not.
		zone := strings.TrimPrefix(value, ":")
		return strings.HasPrefix(zone, "/") || strings.Contains(zone, "..")
	}
	return strings.HasPrefix(key, "LC_") && strings.Contains(value, "/")
}
