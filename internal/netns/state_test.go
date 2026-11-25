package netns

import (
	"slices"
	"strings"
	"testing"
)

func TestTargetStringIsTheTextForm(t *testing.T) {
	for _, text := range []string{"192.0.2.7:udp:53", "10.10.4.0/24:tcp:1-1024", "198.51.100.0/31:tcp:443"} {
		target, err := parseTarget(text)
		if err != nil {
			t.Fatal(err)
		}
		if got := target.String(); got != text {
			t.Errorf("String() = %q, want %q", got, text)
		}
	}
}

func TestStateHoldsTheSlotAndTargetsOnePerLine(t *testing.T) {
	targets := []Target{mustTarget(t, "192.0.2.7:udp:53"), mustTarget(t, "10.10.4.0/24:tcp:1-1024")}
	want := "slot 17\ntarget 192.0.2.7:udp:53\ntarget 10.10.4.0/24:tcp:1-1024\n"
	if got := formatState(17, targets); got != want {
		t.Errorf("formatState = %q, want %q", got, want)
	}
}

func TestStateReadsBackWhatWasWritten(t *testing.T) {
	targets := []Target{mustTarget(t, "192.0.2.7:udp:53"), mustTarget(t, "10.10.4.0/24:tcp:1-1024")}
	slot, got, err := parseState(formatState(17, targets))
	if err != nil {
		t.Fatal(err)
	}
	if slot != 17 || !slices.Equal(got, targets) {
		t.Errorf("parseState = %d, %v; want 17, %v", slot, got, targets)
	}
}

func TestStateWithoutTargetsReadsBack(t *testing.T) {
	slot, targets, err := parseState(formatState(250, nil))
	if err != nil || slot != 250 || len(targets) != 0 {
		t.Errorf("parseState = %d, %v, %v; want 250 and no targets", slot, targets, err)
	}
}

func TestParseStateRefuses(t *testing.T) {
	tests := map[string]string{
		"an empty file":       "",
		"no slot line":        "target 192.0.2.7:udp:53\n",
		"a bad slot":          "slot 251\n",
		"a bad target":        "slot 3\ntarget 192.0.2.7:icmp:1\n",
		"an unknown line":     "slot 3\nflush ruleset\n",
		"a second slot":       "slot 3\nslot 4\n",
		"no final newline":    "slot 3",
		"too many targets":    "slot 3\n" + strings.Repeat("target 192.0.2.7:udp:53\n", maxTargets+1),
		"a slot with a space": "slot  3\n",
	}
	for name, text := range tests {
		if slot, targets, err := parseState(text); err == nil {
			t.Errorf("%s: parseState(%q) = %d, %v; want an error", name, text, slot, targets)
		}
	}
}
