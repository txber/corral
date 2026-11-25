// This file launches a command inside an agent's namespace, in two halves:
// exec runs as root, enters the namespace and drops to the calling user;
// enter runs as that user, reads the env file and starts the command. So no
// root process ever holds the env file's variables.
package netns

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// execInside is the first, root half of exec. It enters the agent's
// namespace and drops to the user who called sudo, without capabilities,
// and there runs this program's enter command, which reads the env file and
// starts the command. The env file is not opened here, so no root process
// ever holds its variables: nsenter and setpriv get only a fixed PATH.
// Exec replaces the helper, so the command keeps sudo's place, the
// caller's cgroup and standard streams, and its exit status reaches the
// caller directly.
func execInside(agentID, envFile string, argv []string) error {
	uid, err := callerID("SUDO_UID", os.Getenv("SUDO_UID"))
	if err != nil {
		return err
	}
	gid, err := callerID("SUDO_GID", os.Getenv("SUDO_GID"))
	if err != nil {
		return err
	}
	if !exists(filepath.Join(netnsDir, netnsPrefix+agentID)) {
		return fmt.Errorf("agent %s does not exist", agentID)
	}
	nsenter, err := findTool("nsenter")
	if err != nil {
		return err
	}
	setpriv, err := findTool("setpriv")
	if err != nil {
		return err
	}
	// The running binary itself, by the kernel's account, never by PATH.
	self, err := os.Executable()
	if err != nil {
		return err
	}
	line := execCommandLine(nsenter, setpriv, self, agentID, uid, gid, envFile, argv)
	return fmt.Errorf("starting nsenter: %w", syscall.Exec(nsenter, line, []string{"PATH=/usr/bin:/bin"}))
}

// execCommandLine returns the nsenter command line that enters the agent's
// namespace and has setpriv drop to uid and gid, with the user's groups and
// no inheritable capabilities, before self runs "netns enter".
func execCommandLine(nsenter, setpriv, self, agentID string, uid, gid int, envFile string, argv []string) []string {
	line := []string{
		nsenter, "--net=" + filepath.Join(netnsDir, netnsPrefix+agentID), "--",
		setpriv, "--reuid=" + strconv.Itoa(uid), "--regid=" + strconv.Itoa(gid),
		"--init-groups", "--inh-caps=-all", "--",
		self, "netns", "enter", "--env-file", envFile, "--",
	}
	return append(line, argv...)
}

// callerID reads the user or group id sudo leaves in SUDO_UID or SUDO_GID.
// It refuses root, whose commands must not run in an agent's namespace.
func callerID(name, text string) (int, error) {
	// ParseUint takes no sign; a leading zero, and so root, is refused
	// here. The kernel reserves the largest value as "no id".
	id, err := strconv.ParseUint(text, 10, 32)
	if err != nil || text[0] == '0' || id == math.MaxUint32 {
		return 0, fmt.Errorf("%s is %.20q, want the id of the user who called sudo, other than root", name, text)
	}
	return int(id), nil
}

// enter is the second, unprivileged half of exec: it reads the env file as
// the user it runs as and replaces itself with the command, whose whole
// environment is the file's variables. It refuses to run as root or with
// any capability, so that it never reads an env file with privileges.
// Called directly, it only runs a command as oneself.
func enter(envFile string, argv []string) error {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return errors.New("refusing to run as root")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	if hasEffectiveCapabilities(string(status)) {
		return errors.New("refusing to run with capabilities")
	}
	env, err := readEnvFile(envFile, os.Getuid())
	if err != nil {
		return err
	}
	path, err := commandPath(argv[0], env)
	if err != nil {
		return err
	}
	return fmt.Errorf("starting %s: %w", argv[0], syscall.Exec(path, argv, env))
}

// hasEffectiveCapabilities reports whether the CapEff line of a
// /proc/<pid>/status text shows any capability. Without the line it
// answers yes.
func hasEffectiveCapabilities(status string) bool {
	for _, line := range strings.Split(status, "\n") {
		if mask, ok := strings.CutPrefix(line, "CapEff:"); ok {
			return strings.Trim(strings.TrimSpace(mask), "0") != ""
		}
	}
	return true
}

// commandPath finds a command the way a shell would, in the PATH of env, or
// /usr/bin:/bin when env sets none. A name with a slash is taken as it is.
func commandPath(name string, env []string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	searchPath := "/usr/bin:/bin"
	for _, variable := range env {
		if value, ok := strings.CutPrefix(variable, "PATH="); ok {
			searchPath = value
		}
	}
	for _, dir := range filepath.SplitList(searchPath) {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); dir != "" && err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s not found in PATH", name)
}
