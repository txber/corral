package netns

import (
	"errors"
	"strings"
	"testing"
)

func TestFailedUndoKeepsTheStateFile(t *testing.T) {
	err := errors.New("adding the default route failed")
	removed := false
	undoState(&err, true, "w1", 7, func(string) error { removed = true; return nil })
	if removed {
		t.Error("undoState removed the state file after an undo step failed")
	}
	if !strings.Contains(err.Error(), "corral netns down w1 7") {
		t.Errorf("error %q does not say how to clear what is left", err)
	}
}

func TestUndoRemovesTheStateFile(t *testing.T) {
	err := errors.New("adding the default route failed")
	removed := ""
	undoState(&err, false, "w1", 7, func(agentID string) error { removed = agentID; return nil })
	if removed != "w1" {
		t.Errorf("undoState removed %q, want w1", removed)
	}
}

func TestSuccessfulUpKeepsTheStateFile(t *testing.T) {
	var err error
	removed := false
	undoState(&err, false, "w1", 7, func(string) error { removed = true; return nil })
	if removed || err != nil {
		t.Errorf("after a successful up: removed %v, error %v; want neither", removed, err)
	}
}
