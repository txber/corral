package events

import (
	"bufio"
	"encoding/json"
	"errors"
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

func TestRecordAfterFailedPartialWriteSitsOnItsOwnLine(t *testing.T) {
	l, path := openLog(t)
	l.Write("x", "", "", nil)
	// Simulate a full disk: half of the next line reaches the file, then the write fails.
	l.write = func(line []byte) (int, error) {
		n, _ := l.file.Write(line[:len(line)/2])
		return n, errors.New("no space left on device")
	}
	if _, err := l.Write("lost", "", "", nil); err == nil {
		t.Fatal("write succeeded, want an error")
	}
	l.write = l.file.Write
	rec, err := l.Write("y", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3: %q", len(lines), lines)
	}
	var got struct{ Seq int }
	if err := json.Unmarshal([]byte(lines[2]), &got); err != nil {
		t.Fatalf("new record is not whole JSON: %v", err)
	}
	if got.Seq != rec["seq"] {
		t.Errorf("seq on disk = %d, returned %v", got.Seq, rec["seq"])
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
	prev := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var rec struct{ Seq int }
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			t.Fatalf("broken line %q: %v", scanner.Text(), err)
		}
		if rec.Seq != prev+1 {
			t.Fatalf("seq %d follows seq %d in the file", rec.Seq, prev)
		}
		prev = rec.Seq
	}
	if prev != 1000 {
		t.Errorf("last seq = %d, want 1000", prev)
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

func TestFieldNamedLikeAFixedFieldInAnotherCaseIsRefused(t *testing.T) {
	l, path := openLog(t)
	// "ſeq" starts with the long s, which folds to s.
	for _, name := range []string{"SEQ", "Seq", "ſeq", "Agent_ID", "TYPE"} {
		if _, err := l.Write("x", "", "", map[string]any{name: 1}); err == nil {
			t.Errorf("field %q was accepted", name)
		}
	}
	if data, _ := os.ReadFile(path); len(data) != 0 {
		t.Errorf("refused writes left data in the file: %q", data)
	}
}

func TestReopeningReadsOnlyTheExactSeqKey(t *testing.T) {
	// A file written before such names were refused can still hold them.
	path := filepath.Join(t.TempDir(), "events.jsonl")
	old := `{"seq":1,"ts":"2026-11-25T08:10:29.898Z","job":"j","agent_id":null,"role":null,"type":"x","Seq":1000000}` + "\n" +
		`{"seq":2,"ts":"2026-11-25T08:10:29.899Z","job":"j","agent_id":null,"role":null,"type":"x","SEQ":-5}` + "\n"
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := Open(path, "j")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	rec, err := l.Write("x", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec["seq"] != 3 {
		t.Errorf("seq = %v, want 3", rec["seq"])
	}
}

// nested wraps v in n levels, alternating slices and maps that hold it
// under key.
func nested(v any, key string, n int) any {
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			v = []any{v}
		} else {
			v = map[string]any{key: v}
		}
	}
	return v
}

func TestValueNestedDeeperThan32LevelsIsRefused(t *testing.T) {
	l, path := openLog(t)
	_, err := l.Write("x", "", "", map[string]any{"deep": nested("s", "k", 33)})
	if err == nil {
		t.Fatal("33 levels were accepted")
	}
	if !strings.Contains(err.Error(), `"deep"`) {
		t.Errorf("error does not name the field: %v", err)
	}
	if data, _ := os.ReadFile(path); len(data) != 0 {
		t.Errorf("refused write left data in the file: %q", data)
	}
	if _, err := l.Write("x", "", "", map[string]any{"deep": nested("s", "k", 32)}); err != nil {
		t.Errorf("32 levels were refused: %v", err)
	}
}

func TestValueTenThousandLevelsDeepIsRefused(t *testing.T) {
	// The JSON encoder alone accepts this depth, but the line around it
	// would be one level too deep to read back.
	l, path := openLog(t)
	if _, err := l.Write("x", "", "", map[string]any{"deep": nested("s", "k", 10000)}); err == nil {
		t.Error("nested value was accepted")
	}
	raw := json.RawMessage(strings.Repeat("[", 10000) + strings.Repeat("]", 10000))
	if _, err := l.Write("x", "", "", map[string]any{"raw": raw}); err == nil {
		t.Error("raw JSON value was accepted")
	}
	if data, _ := os.ReadFile(path); len(data) != 0 {
		t.Errorf("refused writes left data in the file: %q", data)
	}
}

func TestNamesWithInvalidTextAreRefused(t *testing.T) {
	for _, bad := range []string{"a\xff", "a\nb", "a\x00", "a\u0085"} {
		writes := map[string]func(l *Log) error{
			"type":       func(l *Log) error { _, err := l.Write(bad, "", "", nil); return err },
			"agent id":   func(l *Log) error { _, err := l.Write("x", bad, "", nil); return err },
			"role":       func(l *Log) error { _, err := l.Write("x", "", bad, nil); return err },
			"field name": func(l *Log) error { _, err := l.Write("x", "", "", map[string]any{bad: 1}); return err },
			"nested key": func(l *Log) error {
				_, err := l.Write("x", "", "", map[string]any{"f": []any{map[string]any{bad: 1}}})
				return err
			},
		}
		for where, write := range writes {
			l, path := openLog(t)
			if err := write(l); err == nil {
				t.Errorf("%s %q was accepted", where, bad)
			}
			if data, _ := os.ReadFile(path); len(data) != 0 {
				t.Errorf("refused %s %q left data in the file: %q", where, bad, data)
			}
		}
	}
}

func TestFieldNamesThatDifferOnlyInInvalidBytesAreRefused(t *testing.T) {
	// Written as they are, both names would turn into the same key.
	l, path := openLog(t)
	_, err := l.Write("x", "", "", map[string]any{"a\xff": "s", "a\xfe": "t"})
	if err == nil {
		t.Fatal("write was accepted")
	}
	if data, _ := os.ReadFile(path); len(data) != 0 {
		t.Errorf("refused write left data in the file: %q", data)
	}
}

func TestStringValuesWithInvalidUTF8AreRefused(t *testing.T) {
	l, path := openLog(t)
	for _, value := range []any{"a\xff", []any{"ok", "a\xfe"}, map[string]any{"k": "a\xc0"}} {
		_, err := l.Write("x", "", "", map[string]any{"text": value})
		if err == nil {
			t.Errorf("value %q was accepted", value)
		} else if !strings.Contains(err.Error(), `"text"`) {
			t.Errorf("error does not name the field: %v", err)
		}
	}
	if data, _ := os.ReadFile(path); len(data) != 0 {
		t.Errorf("refused writes left data in the file: %q", data)
	}
}

func TestStringValuesKeepLineBreaksAndControlCharacters(t *testing.T) {
	l, path := openLog(t)
	text := "one\ntwo\r\x00 "
	if _, err := l.Write("x", "", "", map[string]any{"text": text}); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(readLines(t, path)[0]), &got); err != nil {
		t.Fatal(err)
	}
	if got["text"] != text {
		t.Errorf("text = %q, want %q", got["text"], text)
	}
}

func TestOpenRefusesAJobNameWithInvalidText(t *testing.T) {
	for _, job := range []string{"j\xff", "j\n", "j\x7f"} {
		path := filepath.Join(t.TempDir(), "events.jsonl")
		if l, err := Open(path, job); err == nil {
			l.Close()
			t.Errorf("job %q was accepted", job)
		}
		if _, err := os.Stat(path); err == nil {
			t.Errorf("job %q: the file was created", job)
		}
	}
}
