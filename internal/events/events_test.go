package events

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func openLog(t *testing.T) (*Log, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	l, err := Open(path, "j")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, path
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func TestSeqStartsAtOneAndCountsUp(t *testing.T) {
	l, _ := openLog(t)
	for want := 1; want <= 3; want++ {
		rec, err := l.Write("x", "", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if rec["seq"] != want {
			t.Errorf("seq = %v, want %d", rec["seq"], want)
		}
	}
}

func TestRecordStartsWithTheFixedFieldsInOrder(t *testing.T) {
	l, path := openLog(t)
	if _, err := l.Write("x", "", "", nil); err != nil {
		t.Fatal(err)
	}
	line := readLines(t, path)[0]
	prefix := `{"seq":1,"ts":"`
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("line = %s", line)
	}
	rest := line[len(prefix):]
	// ts is 2026-11-25T08:10:29.898Z, 24 characters.
	if len(rest) < 25 || rest[23] != 'Z' || rest[10] != 'T' || rest[19] != '.' {
		t.Fatalf("ts is not UTC with milliseconds: %s", line)
	}
	if got, want := rest[24:], `","job":"j","agent_id":null,"role":null,"type":"x"}`; got != want {
		t.Errorf("rest of line = %s, want %s", got, want)
	}
}

func TestCallerFieldsFollowSortedByName(t *testing.T) {
	l, path := openLog(t)
	fields := map[string]any{"zeta": 1, "alpha": "a", "mid": true}
	if _, err := l.Write("x", "a1", "worker", fields); err != nil {
		t.Fatal(err)
	}
	line := readLines(t, path)[0]
	want := `"agent_id":"a1","role":"worker","type":"x","alpha":"a","mid":true,"zeta":1}`
	if !strings.HasSuffix(line, want) {
		t.Errorf("line = %s, want suffix %s", line, want)
	}
}

func TestReopeningContinuesTheSequence(t *testing.T) {
	l, path := openLog(t)
	l.Write("x", "", "", nil)
	l.Write("x", "", "", nil)
	l.Close()

	l2, err := Open(path, "j")
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	rec, err := l2.Write("x", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec["seq"] != 3 {
		t.Errorf("seq = %v, want 3", rec["seq"])
	}
}

func TestTornLastLineIsIgnoredAndNotExtended(t *testing.T) {
	l, path := openLog(t)
	l.Write("x", "", "", nil)
	l.Close()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"seq":2,"ts":"2026`)
	f.Close()

	l2, err := Open(path, "j")
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	rec, err := l2.Write("y", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec["seq"] != 2 {
		t.Errorf("seq = %v, want 2", rec["seq"])
	}
	lines := readLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3: %q", len(lines), lines)
	}
	if lines[1] != `{"seq":2,"ts":"2026` {
		t.Errorf("torn line was changed: %q", lines[1])
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(lines[2]), &got); err != nil {
		t.Errorf("new record is not whole JSON: %v", err)
	}
}

func TestReservedFieldNamesAreRefused(t *testing.T) {
	l, path := openLog(t)
	for _, name := range []string{"seq", "ts", "job", "agent_id", "role", "type"} {
		if _, err := l.Write("x", "", "", map[string]any{name: 1}); err == nil {
			t.Errorf("field %q was accepted", name)
		}
	}
	if data, _ := os.ReadFile(path); len(data) != 0 {
		t.Errorf("refused writes left data in the file: %q", data)
	}
	if rec, _ := l.Write("x", "", "", nil); rec["seq"] != 1 {
		t.Errorf("a refused write used a seq: %v", rec["seq"])
	}
}

func TestNewFileModeIs600(t *testing.T) {
	_, path := openLog(t)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 600", mode)
	}
}

func TestExistingFileIsTightenedTo600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := Open(path, "j")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 600", mode)
	}
}

func TestSubscriberGetsLaterRecordsOnly(t *testing.T) {
	l, _ := openLog(t)
	l.Write("before", "", "", nil)
	records, cancel := l.Subscribe()
	defer cancel()
	l.Write("after", "", "", nil)
	rec := <-records
	if rec["type"] != "after" || rec["seq"] != 2 {
		t.Errorf("got %v, want the record of type after", rec)
	}
	select {
	case rec := <-records:
		t.Errorf("unexpected extra record %v", rec)
	default:
	}
}

func TestSlowSubscriberDoesNotBlockWriters(t *testing.T) {
	l, _ := openLog(t)
	records, cancel := l.Subscribe()
	defer cancel()
	// Nobody reads; more writes than the channel holds must still finish.
	for i := 0; i < 1000; i++ {
		if _, err := l.Write("x", "", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(records); got != 256 {
		t.Errorf("subscriber holds %d records, want 256", got)
	}
}

func TestNonASCIITextIsKept(t *testing.T) {
	l, path := openLog(t)
	if _, err := l.Write("x", "", "", map[string]any{"text": "Grüße <ok> 日本"}); err != nil {
		t.Fatal(err)
	}
	if line := readLines(t, path)[0]; !strings.Contains(line, `"text":"Grüße <ok> 日本"`) {
		t.Errorf("text was escaped: %s", line)
	}
}

func TestConcurrentWritesKeepSeqUniqueAndLinesWhole(t *testing.T) {
	l, path := openLog(t)
	var wg sync.WaitGroup
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if _, err := l.Write("x", "", "", map[string]any{"pad": strings.Repeat("p", 200)}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	seen := make(map[int]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var rec struct{ Seq int }
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			t.Fatalf("broken line %q: %v", scanner.Text(), err)
		}
		if seen[rec.Seq] {
			t.Fatalf("seq %d appears twice", rec.Seq)
		}
		seen[rec.Seq] = true
	}
	if len(seen) != 1000 {
		t.Errorf("got %d records, want 1000", len(seen))
	}
	for seq := 1; seq <= 1000; seq++ {
		if !seen[seq] {
			t.Fatalf("seq %d is missing", seq)
		}
	}
}

func TestWriteAfterCloseFailsAndCloseTwiceIsFine(t *testing.T) {
	l, _ := openLog(t)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Write("x", "", "", nil); err == nil {
		t.Error("write after close succeeded")
	}
	if err := l.Close(); err != nil {
		t.Errorf("second close = %v, want nil", err)
	}
}
