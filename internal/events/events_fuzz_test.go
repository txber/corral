// Checks that hold for any input: every line in the file reads back as
// exactly the record Write returned, numbered without gaps or repeats, also
// after the log is opened again.
package events

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode"
	"unicode/utf8"
)

var tsPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)

// checkLines checks every line of a log file and returns the records decoded
// from it, in file order.
func checkLines(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	if len(data) == 0 {
		return nil
	}
	if data[len(data)-1] != '\n' {
		t.Fatalf("file does not end in a newline: %q", data)
	}
	var records []map[string]any
	for n, line := range bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'}) {
		if !json.Valid(line) || bytes.IndexByte(line, '\r') >= 0 {
			t.Fatalf("line %d is not one clean JSON value: %q", n+1, line)
		}
		keys := topKeys(t, line)
		if !slices.Equal(keys[:min(len(keys), len(reserved))], reserved) {
			t.Fatalf("line %d: fixed fields are not first in order: %q", n+1, keys)
		}
		extra := keys[len(reserved):]
		if !slices.IsSorted(extra) || len(slices.Compact(slices.Clone(extra))) != len(extra) {
			t.Fatalf("line %d: caller fields are not sorted and distinct: %q", n+1, extra)
		}
		rec := decode(t, line)
		if rec["seq"] != json.Number(fmt.Sprint(n+1)) {
			t.Fatalf("line %d: seq = %v", n+1, rec["seq"])
		}
		if ts, _ := rec["ts"].(string); !tsPattern.MatchString(ts) {
			t.Fatalf("line %d: ts = %v", n+1, rec["ts"])
		}
		records = append(records, rec)
	}
	return records
}

// topKeys returns the keys of the JSON object in line, in order, with repeats.
func topKeys(t *testing.T, line []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(line))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("line is not an object: %q", line)
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, tok.(string))
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

// decode decodes one JSON object, keeping numbers as they are written.
func decode(t *testing.T, data []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var rec map[string]any
	if err := dec.Decode(&rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// badName reports whether Write or Open must refuse name.
func badName(name string) bool {
	return !utf8.ValidString(name) || strings.ContainsFunc(name, unicode.IsControl)
}

func FuzzWrite(f *testing.F) {
	// job, type, agent id, role, field name, nested key, text, number, kind of value, depth
	f.Add("j", "start", "a1", "worker", "alpha", "k", "text", 1.5, byte(0), byte(0))
	f.Add("", "", "", "", "", "", "", 0.0, byte(3), byte(0))
	f.Add("j", "x", "", "", "seq", "k", "s", 1.0, byte(0), byte(0))
	f.Add("j", "x", "", "", "SEQ", "k", "s", -5.0, byte(1), byte(0))
	f.Add("j", "x", "", "", "ſeq", "k", "s", 1e300, byte(1), byte(0))
	f.Add("j", "x", "", "", "Agent_ID", "k", "s", 1.0, byte(1), byte(0))
	f.Add("j", "x", "a", "r", "a\xff", "k", "s", 1.0, byte(0), byte(0))
	f.Add("j\xff", "x", "a", "r", "n", "k", "s", 1.0, byte(0), byte(0))
	f.Add("j", "x\xfe", "a\xc0", "r\xed\xa0\x80", "n", "k", "s", 1.0, byte(0), byte(0))
	f.Add("j", "x", "a", "r", "text", "k", "a\xff", 1.0, byte(2), byte(5))
	f.Add("j", "x", "a", "r", "deep", "k", "s", 1.0, byte(2), byte(32))
	f.Add("j", "x", "a", "r", "deep", "k", "s", 1.0, byte(2), byte(33))
	f.Add("j", "x", "a", "r", "deep", "k\n", "s", 1.0, byte(2), byte(4))
	f.Add("j", "x", "", "", "pad", "k", "s", math.NaN(), byte(1), byte(0))
	f.Add("j", "x", "", "", "pad", "k", "s", math.Inf(-1), byte(1), byte(0))
	f.Add("Grüße", "日本", "<ok>", "&", "k\"\\", " ", "v\n\r\t\x00</script>", -0.0, byte(2), byte(9))

	f.Fuzz(func(t *testing.T, job, typ, agentID, role, name, key, s string, num float64, kind, depth byte) {
		path := filepath.Join(t.TempDir(), "events.jsonl")
		l, err := Open(path, job)
		if badName(job) {
			if err == nil {
				t.Fatalf("job %q was accepted", job)
			}
			if _, err := os.Stat(path); err == nil {
				t.Fatalf("refused job %q created the file", job)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		if _, err := l.Write("start", "", "", nil); err != nil {
			t.Fatal(err)
		}

		var value any
		valueBad := false
		switch kind % 4 {
		case 0:
			value, valueBad = s, !utf8.ValidString(s)
		case 1:
			value, valueBad = num, math.IsNaN(num) || math.IsInf(num, 0)
		case 2:
			// From two levels on, the value holds a map with key.
			value = nested(s, key, int(depth))
			valueBad = !utf8.ValidString(s) || depth > maxDepth || depth >= 2 && badName(key)
		default:
			value = nil
		}
		fields := map[string]any{"n": 1}
		fields[name] = value
		reservedName := slices.ContainsFunc(reserved, func(fixed string) bool { return strings.EqualFold(name, fixed) })
		wantRefused := badName(typ) || badName(agentID) || badName(role) || badName(name) || reservedName || valueBad

		before, _ := os.ReadFile(path)
		rec, err := l.Write(typ, agentID, role, fields)
		after, _ := os.ReadFile(path)
		if wantRefused != (err != nil) {
			t.Fatalf("refused = %v, want %v (error: %v)", err != nil, wantRefused, err)
		}
		if err != nil && !bytes.Equal(before, after) {
			t.Fatalf("refused write changed the file: %q", after)
		}
		if err == nil && (!bytes.HasPrefix(after, before) || bytes.Count(after[len(before):], []byte{'\n'}) != 1) {
			t.Fatalf("write did not append exactly one line: %q", after[len(before):])
		}

		records := checkLines(t, after)
		if err == nil {
			// The line must hold exactly the record returned.
			if rec["seq"] != 2 {
				t.Fatalf("returned seq = %v, want 2", rec["seq"])
			}
			returned, err := json.Marshal(rec)
			if err != nil {
				t.Fatal(err)
			}
			line := records[1]
			if !reflect.DeepEqual(line, decode(t, returned)) {
				t.Fatalf("line %v differs from the record returned %v", line, rec)
			}
			if line["job"] != job || line["type"] != typ || line["agent_id"] != nullIfEmpty(agentID) || line["role"] != nullIfEmpty(role) {
				t.Fatalf("fixed fields were changed: %v", line)
			}
			if _, ok := line[name]; !ok {
				t.Fatalf("field %q is missing: %v", name, line)
			}
		}

		// Opened again, the log continues with the next seq.
		l.Close()
		l2, err := Open(path, job)
		if err != nil {
			t.Fatal(err)
		}
		defer l2.Close()
		next, err := l2.Write("again", "", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if next["seq"] != len(records)+1 {
			t.Fatalf("after reopening seq = %v, want %d", next["seq"], len(records)+1)
		}
		final, _ := os.ReadFile(path)
		checkLines(t, final)
	})
}

func TestConcurrentWritesWithRefusalsKeepTheLogWhole(t *testing.T) {
	l, path := openLog(t)
	const writers, each = 16, 40
	var mu sync.Mutex
	returned := map[any]bool{}
	refused := 0
	var wg sync.WaitGroup
	for g := 0; g < writers; g++ {
		wg.Go(func() {
			for i := 0; i < each; i++ {
				fields := map[string]any{
					"text": strings.Repeat("\n\r x", g+1),
					"n":    float64(i) / 3,
					"m":    map[string]any{"k": []any{g, i, true, nil}},
				}
				switch i % 5 {
				case 3:
					fields["v"] = math.NaN()
				case 4:
					fields["Seq"] = 1
				}
				rec, err := l.Write(fmt.Sprintf("t%d", g), fmt.Sprintf("a%d", g), "", fields)
				mu.Lock()
				if err != nil {
					refused++
				} else if returned[rec["seq"]] {
					t.Errorf("seq %v returned twice", rec["seq"])
				} else {
					returned[rec["seq"]] = true
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	l.Close()

	written := writers * each * 3 / 5
	if refused != writers*each-written {
		t.Errorf("refused %d writes, want %d", refused, writers*each-written)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	records := checkLines(t, data)
	if len(records) != written {
		t.Fatalf("%d lines, want %d", len(records), written)
	}
	for _, rec := range records {
		typ, _ := rec["type"].(string)
		if rec["agent_id"] != "a"+strings.TrimPrefix(typ, "t") {
			t.Fatalf("agent_id %v does not belong to type %v", rec["agent_id"], typ)
		}
	}

	l2, err := Open(path, "j")
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	rec, err := l2.Write("again", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec["seq"] != written+1 {
		t.Errorf("after reopening seq = %v, want %d", rec["seq"], written+1)
	}
}
