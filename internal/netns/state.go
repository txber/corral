// This file keeps the helper's record of the agents: one root-owned file
// per agent, /run/corral/<agent_id>, holding its slot and its complete
// target list. up writes it, allow rewrites it, down removes it and list
// reads the folder. It is how up finds an agent id or a slot in use and how
// allow knows the targets an agent already has. /run is a tmpfs, like
// /run/netns, so the records vanish at boot together with the namespaces.
package netns

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const stateDir = "/run/corral"

// agentState is what the state file of one agent holds.
type agentState struct {
	slot    int
	targets []Target
}

// formatState returns the text of a state file: a line "slot <n>", then
// one line "target <target>" per target.
func formatState(slot int, targets []Target) string {
	var b strings.Builder
	fmt.Fprintf(&b, "slot %d\n", slot)
	for _, t := range targets {
		fmt.Fprintf(&b, "target %s\n", t)
	}
	return b.String()
}

// parseState reads the text formatState writes, checking every value again.
func parseState(text string) (int, []Target, error) {
	if !strings.HasSuffix(text, "\n") {
		return 0, nil, errors.New("does not end in a newline")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	slotText, ok := strings.CutPrefix(lines[0], "slot ")
	if !ok {
		return 0, nil, errors.New("does not start with the slot")
	}
	slot, err := parseSlot(slotText)
	if err != nil {
		return 0, nil, err
	}
	if len(lines)-1 > maxTargets {
		return 0, nil, fmt.Errorf("more than %d targets", maxTargets)
	}
	var targets []Target
	for _, line := range lines[1:] {
		targetText, ok := strings.CutPrefix(line, "target ")
		if !ok {
			return 0, nil, fmt.Errorf("unexpected line %.40q", line)
		}
		t, err := parseTarget(targetText)
		if err != nil {
			return 0, nil, err
		}
		targets = append(targets, t)
	}
	return slot, targets, nil
}

// lockState creates the state folder if it is missing and locks it, so that
// one up, allow or down at a time reads and changes the agents. The lock
// holds until the returned file is closed or the helper ends.
func lockState() (*os.File, error) {
	if err := os.Mkdir(stateDir, 0o755); err == nil {
		// Mkdir applies the umask, which sudo may have made stricter.
		if err := os.Chmod(stateDir, 0o755); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	dir, err := os.Open(stateDir)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(dir.Fd()), syscall.LOCK_EX); err != nil {
		dir.Close()
		return nil, fmt.Errorf("locking %s: %w", stateDir, err)
	}
	return dir, nil
}

// readStates returns the state of every agent that has a state file, by
// agent id. Other files in the folder, such as a half-written one, are
// skipped.
func readStates() (map[string]agentState, error) {
	states := map[string]agentState{}
	entries, err := os.ReadDir(stateDir)
	if errors.Is(err, fs.ErrNotExist) {
		return states, nil
	}
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		agentID := entry.Name()
		if !validAgentID(agentID) {
			continue
		}
		path := filepath.Join(stateDir, agentID)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		slot, targets, err := parseState(string(data))
		if err != nil {
			return nil, fmt.Errorf("state file %s: %w", path, err)
		}
		states[agentID] = agentState{slot: slot, targets: targets}
	}
	return states, nil
}

// writeState writes an agent's state file. It writes a new file and renames
// it over the old one, so that a reader finds the old or the new state,
// never a part of one.
func writeState(agentID string, state agentState) error {
	file, err := os.CreateTemp(stateDir, "."+agentID+".*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name()) // fails harmlessly once renamed
	_, err = file.WriteString(formatState(state.slot, state.targets))
	if err == nil {
		err = file.Chmod(0o644)
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("writing the state of %s: %w", agentID, err)
	}
	return os.Rename(file.Name(), filepath.Join(stateDir, agentID))
}

// removeState removes an agent's state file if there is one.
func removeState(agentID string) error {
	err := os.Remove(filepath.Join(stateDir, agentID))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
