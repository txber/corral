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

// failingUp fails the way up does after it created something: its undo
// steps are deferred as in up, an undo step through onFailure and, first
// deferred and so run last, the state step, which reads the flag only when
// it runs. undoErr is what the undo step returns.
func failingUp(undoErr error, removed *bool) (err error) {
	var undoFailed bool
	defer func() {
		undoState(&err, undoFailed, "w1", 7, func(string) error { *removed = true; return nil })
	}()
	defer onFailure(&err, &undoFailed, func() error { return undoErr })
	return errors.New("adding the default route failed")
}

func TestAFailedUndoStepKeepsTheStateFile(t *testing.T) {
	removed := false
	err := failingUp(errors.New("deleting the link failed"), &removed)
	if removed {
		t.Error("the state file was removed although an undo step failed")
	}
	if err == nil || !strings.Contains(err.Error(), "deleting the link failed") ||
		!strings.Contains(err.Error(), "corral netns down w1 7") {
		t.Errorf("error %v; want the undo failure and the down command", err)
	}
}

func TestSuccessfulUndoStepsRemoveTheStateFile(t *testing.T) {
	removed := false
	if err := failingUp(nil, &removed); err == nil {
		t.Error("failingUp returned no error")
	}
	if !removed {
		t.Error("the state file was kept although every undo step succeeded")
	}
}
