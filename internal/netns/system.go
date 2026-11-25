// This file carries out the commands that change the network with the
// system's tools: ip for namespaces, links and addresses, nft for the rules;
// launch.go starts commands inside a namespace. Each tool is found in fixed
// folders, gets an explicit argument list and environment and never runs
// through a shell, and every value on its command line has passed the
// checks in netns.go.
package netns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

	// maxKillPasses bounds how often down lists and kills what is left in a
	// namespace.
	maxKillPasses = 5
)

// toolDirs are the folders the tools are looked up in, in this order. PATH
// is never used: the caller of sudo may have a say in it.
var toolDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// execute runs a checked command. All but enter run as root and act on
// the machine's own network, so they refuse to run in any other network
// namespace, such as an agent's.
func execute(c command, stdout io.Writer) error {
	if c.name != "enter" {
		if os.Geteuid() != 0 {
			return errors.New("must be run as root, for example through sudo")
		}
		if err := checkInitialNamespace(); err != nil {
			return err
		}
	}
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

// checkInitialNamespace returns an error unless the helper runs in the
// network namespace of process 1.
func checkInitialNamespace() error {
	self, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return err
	}
	first, err := os.Stat("/proc/1/ns/net")
	if err != nil {
		return err
	}
	if !os.SameFile(self, first) {
		return errors.New("refusing to run outside the machine's own network namespace")
	}
	return nil
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
		return fmt.Errorf("agent %s already exists, in slot %d; corral netns down %s %d removes it",
			agentID, state.slot, agentID, state.slot)
	}
	for other, state := range states {
		if state.slot == slot {
			return fmt.Errorf("slot %d is in use by agent %s; corral netns down %s %d removes it",
				slot, other, other, slot)
		}
	}

	// The record comes first, so that whatever a killed up leaves behind
	// carries its slot and down can remove it. Its removal is the last
	// step of the undo.
	if err := writeState(agentID, agentState{slot: slot, targets: targets}); err != nil {
		return err
	}
	// undoFailed is set by a failed undo step; the state file then stays.
	var undoFailed bool
	defer func() { undoState(&err, undoFailed, agentID, slot, removeState) }()

	n := namesFor(agentID, slot)
	if err := nft(renderBase()); err != nil {
		return err
	}
	// ip refuses a namespace or a link that exists already, so each undo
	// below removes only what this run created.
	if err := ip("netns", "add", n.Netns); err != nil {
		return err
	}
	defer onFailure(&err, &undoFailed, func() error { return deleteNetns(n.Netns) })
	if err := ip("link", "add", n.Veth, "type", "veth", "peer", "name", "eth0", "netns", n.Netns); err != nil {
		return err
	}
	defer onFailure(&err, &undoFailed, func() error { return deleteLink(n.Veth) })

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
	defer onFailure(&err, &undoFailed, func() error { return nft(renderRemove(agentID, slot)) })
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
	return nil
}

// onFailure runs undo if *err is set when the calling function returns,
// and adds undo's own error to it and sets *failed when undo fails. It is
// meant to be deferred.
func onFailure(err *error, failed *bool, undo func() error) {
	if *err == nil {
		return
	}
	if undoErr := undo(); undoErr != nil {
		*failed = true
		*err = errors.Join(*err, fmt.Errorf("undoing: %w", undoErr))
	}
}

// undoState is the last undo step of a failed up: it removes the agent's
// state file with remove, unless an earlier undo step failed. Then the file
// stays, so that what is left keeps its slot on record, and the error says
// how to remove it.
func undoState(err *error, undoFailed bool, agentID string, slot int, remove func(agentID string) error) {
	switch {
	case *err == nil:
	case undoFailed:
		*err = errors.Join(*err, fmt.Errorf("kept the record of agent %s; corral netns down %s %d removes what is left",
			agentID, agentID, slot))
	default:
		if removeErr := remove(agentID); removeErr != nil {
			*err = errors.Join(*err, fmt.Errorf("undoing: %w", removeErr))
		}
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

	// Processes that will not stop do not stop the teardown; down then
	// reports them at the end.
	n := namesFor(agentID, slot)
	var stopErr error
	if exists(filepath.Join(netnsDir, n.Netns)) {
		stopErr = stopProcesses(n.Netns)
	}
	// Deleting the root end removes both ends at once; the kernel removes
	// a namespace's links only some time after the namespace is deleted.
	if err := deleteLink(n.Veth); err != nil {
		return errors.Join(stopErr, err)
	}
	if err := deleteNetns(n.Netns); err != nil {
		return errors.Join(stopErr, err)
	}
	if err := nft(renderRemove(agentID, slot)); err != nil {
		return errors.Join(stopErr, err)
	}
	return errors.Join(stopErr, removeState(agentID))
}

// deleteLink deletes a link of the root namespace if it exists.
func deleteLink(name string) error {
	if !exists(filepath.Join("/sys/class/net", name)) {
		return nil
	}
	return ip("link", "delete", name)
}

// deleteNetns deletes a named namespace if it exists.
func deleteNetns(name string) error {
	if !exists(filepath.Join(netnsDir, name)) {
		return nil
	}
	return ip("netns", "delete", name)
}

// stopProcesses ends what runs in a namespace: SIGTERM, up to two seconds
// to exit, then SIGKILL, repeated for what is still listed, at most
// maxKillPasses times, so that a process that keeps forking is caught.
func stopProcesses(netns string) error {
	ns, err := os.Stat(filepath.Join(netnsDir, netns))
	if err != nil {
		return err
	}
	pids, err := namespacePIDs(netns)
	if err != nil {
		return err
	}
	signalInNamespace(pids, ns, syscall.SIGTERM)
	for deadline := time.Now().Add(stopTimeout); len(pids) > 0 && time.Now().Before(deadline); {
		time.Sleep(100 * time.Millisecond)
		if pids, err = namespacePIDs(netns); err != nil {
			return err
		}
	}
	for pass := 0; pass < maxKillPasses && len(pids) > 0; pass++ {
		signalInNamespace(pids, ns, syscall.SIGKILL)
		time.Sleep(100 * time.Millisecond)
		if pids, err = namespacePIDs(netns); err != nil {
			return err
		}
	}
	if len(pids) > 0 {
		return fmt.Errorf("%d processes still run in %s", len(pids), netns)
	}
	return nil
}

// signalInNamespace sends sig to each listed process that is in the
// namespace ns. A pid is only a number the kernel may have given to another
// process since it was listed, so each process is first taken by a handle
// (on Linux, os.FindProcess holds a pidfd, which names the process itself),
// then checked to be in the namespace, and signalled through the handle.
func signalInNamespace(pids []int, ns os.FileInfo, sig syscall.Signal) {
	for _, pid := range pids {
		process, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		member, err := os.Stat(fmt.Sprintf("/proc/%d/ns/net", pid))
		if err == nil && os.SameFile(member, ns) {
			_ = process.Signal(sig) // a process that is gone by now is fine
		}
		process.Release()
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
