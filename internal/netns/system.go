// This file carries out the five commands with the system's tools: ip for
// namespaces, links and addresses, nft for the rules, nsenter and setpriv to
// launch a command. Each tool is found in fixed folders, gets an explicit
// argument list and environment and never runs through a shell, and every
// value on its command line has passed the checks in netns.go.
package netns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	netnsDir    = "/run/netns" // where ip keeps named namespaces
	toolTimeout = 30 * time.Second
	stopTimeout = 2 * time.Second // how long down waits after SIGTERM
)

// toolDirs are the folders the tools are looked up in, in this order. PATH
// is never used: the caller of sudo may have a say in it.
var toolDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// execute runs a checked command.
func execute(c command, stdout io.Writer) error {
	switch c.name {
	case "up":
		return up(c.agentID, c.slot, c.targets)
	case "allow":
		return allow(c.agentID, c.slot, c.targets)
	case "down":
		return down(c.agentID, c.slot)
	case "exec":
		return execInside(c.agentID, c.envFile, c.argv)
	case "enter":
		return enter(c.envFile, c.argv)
	case "list":
		return list(stdout)
	}
	return fmt.Errorf("unknown command %q", c.name)
}

// up creates an agent's namespace, veth pair and rules. It refuses an agent
// id or a slot already in use, and removes what it created when a later
// step fails.
func up(agentID string, slot int, targets []Target) (err error) {
	forwarding, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(forwarding)) != "1" {
		return errors.New("IPv4 forwarding is off; agents need net.ipv4.ip_forward = 1")
	}

	lock, err := lockState()
	if err != nil {
		return err
	}
	defer lock.Close()
	states, err := readStates()
	if err != nil {
		return err
	}
	if state, ok := states[agentID]; ok {
		return fmt.Errorf("agent %s already exists, in slot %d", agentID, state.slot)
	}
	for other, state := range states {
		if state.slot == slot {
			return fmt.Errorf("slot %d is in use by agent %s", slot, other)
		}
	}

	n := namesFor(agentID, slot)
	if err := nft(renderBase()); err != nil {
		return err
	}
	// ip refuses a namespace or a link that exists already, so each undo
	// below removes only what this run created.
	if err := ip("netns", "add", n.Netns); err != nil {
		return err
	}
	defer onFailure(&err, func() error { return ip("netns", "delete", n.Netns) })
	if err := ip("link", "add", n.Veth, "type", "veth", "peer", "name", "eth0", "netns", n.Netns); err != nil {
		return err
	}
	defer onFailure(&err, func() error { return ip("link", "delete", n.Veth) })

	// With IPv6 on, the agent's router solicitations reach the rules on a
	// host that forwards IPv6, which drop and log them. Off on the root end,
	// the kernel discards them first.
	if err := disableIPv6(n.Veth); err != nil {
		return err
	}
	if err := ip("addr", "add", n.RootIP+"/30", "dev", n.Veth); err != nil {
		return err
	}
	if err := ip("-n", n.Netns, "addr", "add", n.AgentIP+"/30", "dev", "eth0"); err != nil {
		return err
	}

	// The rules are in place before the links come up.
	if err := nft(renderAgent(agentID, slot, targets)); err != nil {
		return err
	}
	defer onFailure(&err, func() error { return nft(renderRemove(agentID, slot)) })
	for _, args := range [][]string{
		{"link", "set", n.Veth, "up"},
		{"-n", n.Netns, "link", "set", "lo", "up"},
		{"-n", n.Netns, "link", "set", "eth0", "up"},
		{"-n", n.Netns, "route", "add", "default", "via", n.RootIP},
	} {
		if err := ip(args...); err != nil {
			return err
		}
	}
	return writeState(agentID, agentState{slot: slot, targets: targets})
}

// onFailure runs undo if *err is set when the calling function returns,
// and adds undo's own error to it. It is meant to be deferred.
func onFailure(err *error, undo func() error) {
	if *err == nil {
		return
	}
	if undoErr := undo(); undoErr != nil {
		*err = errors.Join(*err, fmt.Errorf("undoing: %w", undoErr))
	}
}

// allow adds targets to a running agent. The sets get the agent's complete
// list, its earlier targets and the new ones, in one transaction.
func allow(agentID string, slot int, targets []Target) error {
	lock, err := lockState()
	if err != nil {
		return err
	}
	defer lock.Close()
	states, err := readStates()
	if err != nil {
		return err
	}
	state, ok := states[agentID]
	if !ok {
		return fmt.Errorf("agent %s does not exist", agentID)
	}
	if state.slot != slot {
		return fmt.Errorf("agent %s is in slot %d, not %d", agentID, state.slot, slot)
	}
	all := slices.Clone(state.targets)
	for _, t := range targets {
		if !slices.Contains(all, t) {
			all = append(all, t)
		}
	}
	if len(all) > maxTargets {
		return fmt.Errorf("agent %s would have more than %d targets", agentID, maxTargets)
	}
	if _, _, err := setContents(all); err != nil {
		return err
	}
	if err := nft(renderTargets(agentID, all)); err != nil {
		return err
	}
	return writeState(agentID, agentState{slot: slot, targets: all})
}

// down stops what runs in an agent's namespace and removes the namespace,
// the veth pair, the rules and the state file. Each step passes over what
// is already gone, so down also clears what a failed up or a lost state
// file left behind. It refuses a slot that belongs to another agent.
func down(agentID string, slot int) error {
	lock, err := lockState()
	if err != nil {
		return err
	}
	defer lock.Close()
	states, err := readStates()
	if err != nil {
		return err
	}
	for other, state := range states {
		switch {
		case other == agentID && state.slot != slot:
			return fmt.Errorf("agent %s is in slot %d, not %d", agentID, state.slot, slot)
		case other != agentID && state.slot == slot:
			return fmt.Errorf("slot %d belongs to agent %s", slot, other)
		}
	}

	n := namesFor(agentID, slot)
	netnsPath := filepath.Join(netnsDir, n.Netns)
	if exists(netnsPath) {
		if err := stopProcesses(n.Netns); err != nil {
			return err
		}
	}
	// Deleting the root end removes both ends at once; the kernel removes
	// a namespace's links only some time after the namespace is deleted.
	if exists(filepath.Join("/sys/class/net", n.Veth)) {
		if err := ip("link", "delete", n.Veth); err != nil {
			return err
		}
	}
	if exists(netnsPath) {
		if err := ip("netns", "delete", n.Netns); err != nil {
			return err
		}
	}
	if err := nft(renderRemove(agentID, slot)); err != nil {
		return err
	}
	return removeState(agentID)
}

// stopProcesses ends what runs in a namespace: SIGTERM, up to two seconds
// to exit, then SIGKILL for what is left.
func stopProcesses(netns string) error {
	pids, err := namespacePIDs(netns)
	if err != nil {
		return err
	}
	signal(pids, syscall.SIGTERM)
	for deadline := time.Now().Add(stopTimeout); len(pids) > 0 && time.Now().Before(deadline); {
		time.Sleep(100 * time.Millisecond)
		if pids, err = namespacePIDs(netns); err != nil {
			return err
		}
	}
	signal(pids, syscall.SIGKILL)
	return nil
}

// signal sends sig to each process. A process that is already gone is
// fine.
func signal(pids []int, sig syscall.Signal) {
	for _, pid := range pids {
		_ = syscall.Kill(pid, sig)
	}
}

// namespacePIDs returns the processes in a namespace.
func namespacePIDs(netns string) ([]int, error) {
	output, err := runTool("", "ip", "netns", "pids", netns)
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, field := range strings.Fields(output) {
		// Never 0, 1 or negative: kill would take those as a group or all.
		pid, err := strconv.Atoi(field)
		if err != nil || pid <= 1 {
			return nil, fmt.Errorf("ip netns pids %s: unexpected output %.40q", netns, field)
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// list prints "<agent_id> <slot>" for every agent that has a namespace or a
// state file, sorted by id; the slot is "-" for a namespace without one.
func list(stdout io.Writer) error {
	states, err := readStates()
	if err != nil {
		return err
	}
	slots := map[string]string{}
	for agentID, state := range states {
		slots[agentID] = strconv.Itoa(state.slot)
	}
	entries, err := os.ReadDir(netnsDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, entry := range entries {
		agentID, ok := strings.CutPrefix(entry.Name(), netnsPrefix)
		if _, known := slots[agentID]; ok && validAgentID(agentID) && !known {
			slots[agentID] = "-"
		}
	}
	agentIDs := make([]string, 0, len(slots))
	for agentID := range slots {
		agentIDs = append(agentIDs, agentID)
	}
	slices.Sort(agentIDs)
	for _, agentID := range agentIDs {
		if _, err := fmt.Fprintf(stdout, "%s %s\n", agentID, slots[agentID]); err != nil {
			return err
		}
	}
	return nil
}

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

// disableIPv6 switches IPv6 off for an interface of the root namespace. It
// does nothing on a kernel without IPv6.
func disableIPv6(iface string) error {
	if !exists("/proc/sys/net/ipv6") {
		return nil
	}
	path := filepath.Join("/proc/sys/net/ipv6/conf", iface, "disable_ipv6")
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("switching IPv6 off: %w", err)
	}
	_, err = file.WriteString("1\n")
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("switching IPv6 off: %w", err)
	}
	return nil
}

// exists reports whether path exists, without following a final symbolic
// link.
func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// ip runs ip with args.
func ip(args ...string) error {
	_, err := runTool("", "ip", args...)
	return err
}

// nft loads rules text as one transaction: all of it applies or none.
func nft(rules string) error {
	_, err := runTool(rules, "nft", "-f", "-")
	return err
}

// runTool runs a tool with input on its standard input and returns its
// standard output. The tool gets no variable from the helper's
// environment, which the caller of sudo partly chooses.
func runTool(input, name string, args ...string) (string, error) {
	path, err := findTool(name)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"LC_ALL=C"}
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// findTool returns the path of a tool in the first of toolDirs that holds
// it as an executable file.
func findTool(name string) (string, error) {
	for _, dir := range toolDirs {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s not found in %s", name, strings.Join(toolDirs, ", "))
}
