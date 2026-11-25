// Package events writes the append-only JSONL event log that every part of
// corral reports to: one JSON object per line, numbered in order.
package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// subscriberBuffer is how many records a subscriber may fall behind before it
// starts losing records.
const subscriberBuffer = 256

// reserved are the names of the fixed fields of every record.
var reserved = []string{"seq", "ts", "job", "agent_id", "role", "type"}

// maxDepth is how many levels of maps and slices a field value may nest. It
// keeps every line far below the depth that encoding/json reads back.
const maxDepth = 32

// Log is an open event log. It is safe for concurrent use.
type Log struct {
	mu           sync.Mutex
	file         *os.File
	write        func([]byte) (int, error) // file.Write; tests replace it to fail a write
	job          string
	seq          int
	needsNewline bool // the file ends in a torn line
	closed       bool
	subscribers  map[chan map[string]any]bool
}

// Open opens the event log at path for the given job. It creates the file
// with mode 600, or tightens an existing file to 600, and continues the
// sequence after the last complete line. The job name is checked like the
// names in a record (see Write).
func Open(path, job string) (*Log, error) {
	if err := checkName(job); err != nil {
		return nil, fmt.Errorf("event log job %q: %w", job, err)
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open event log: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, fmt.Errorf("restrict event log: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("read event log: %w", err)
	}
	l := &Log{
		file: file,
		job:  job,
		seq:  lastSeq(data),
		// A torn last line stays as it is; the next record starts on a new line.
		needsNewline: len(data) > 0 && data[len(data)-1] != '\n',
		subscribers:  make(map[chan map[string]any]bool),
	}
	l.write = file.Write
	return l, nil
}

// lastSeq returns the seq of the last complete line of data that has one, or
// 0 if there is none. Text after the last newline is a torn line and is
// ignored.
func lastSeq(data []byte) int {
	end := bytes.LastIndexByte(data, '\n')
	if end < 0 {
		return 0
	}
	lines := bytes.Split(data[:end], []byte{'\n'})
	for i := len(lines) - 1; i >= 0; i-- {
		// Decoding into a struct would match "SEQ" or "Seq" too; a map keeps
		// the key "seq" apart from caller fields named like it.
		var rec map[string]json.RawMessage
		var seq int
		if json.Unmarshal(lines[i], &rec) == nil && json.Unmarshal(rec["seq"], &seq) == nil && seq > 0 {
			return seq
		}
	}
	return 0
}

// Write appends one record and returns it. An empty agentID or role is
// written as null. The record's fixed fields come first, in a fixed order,
// followed by the caller's fields sorted by name.
//
// A field value is made of what decoded JSON is made of: nil, a bool, an int,
// int64 or float64, a string, a []any or a map[string]any. Other types, such
// as []string or map[string]string, are refused; convert them first.
//
// Write refuses a record rather than change it, so that the line in the file
// always reads back as the record returned; the caller decides what to write
// instead. It refuses a field named like a fixed field in any case; a value of
// another type; a name (type, agent id, role, field name or key of a nested
// map) that is not valid UTF-8 or holds a control character; a string value
// that is not valid UTF-8; a number that is NaN or infinite; and a value
// nested deeper than 32 levels of maps and slices. A refused record writes
// nothing and uses no seq.
func (l *Log) Write(typ, agentID, role string, fields map[string]any) (map[string]any, error) {
	for _, fixed := range []struct{ what, value string }{{"type", typ}, {"agent id", agentID}, {"role", role}} {
		if err := checkName(fixed.value); err != nil {
			return nil, fmt.Errorf("event %s %q: %w", fixed.what, fixed.value, err)
		}
	}
	extra := slices.Sorted(maps.Keys(fields))
	for _, name := range extra {
		if err := checkField(name, fields[name]); err != nil {
			return nil, fmt.Errorf("event field %q: %w", name, err)
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, errors.New("write to closed event log")
	}

	record := map[string]any{
		"seq":      l.seq + 1,
		"ts":       time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"job":      l.job,
		"agent_id": nullIfEmpty(agentID),
		"role":     nullIfEmpty(role),
		"type":     typ,
	}
	for name, value := range fields {
		record[name] = value
	}
	names := append(slices.Clone(reserved), extra...)

	line, err := encode(record, names)
	if err != nil {
		return nil, fmt.Errorf("encode event: %w", err)
	}
	if l.needsNewline {
		line = append([]byte{'\n'}, line...)
	}
	// One write call on an O_APPEND file keeps the line whole.
	if _, err := l.write(line); err != nil {
		// Part of the line may be in the file; the next record starts on a new line.
		l.needsNewline = true
		return nil, fmt.Errorf("write event: %w", err)
	}
	l.needsNewline = false
	l.seq++

	for ch := range l.subscribers {
		select {
		case ch <- record:
		default: // a subscriber that does not keep up loses the record
		}
	}
	return record, nil
}

// checkName returns why name cannot be written as it is, or nil.
func checkName(name string) error {
	if !utf8.ValidString(name) {
		return errors.New("not valid UTF-8")
	}
	if strings.ContainsFunc(name, unicode.IsControl) {
		return errors.New("holds a control character")
	}
	return nil
}

// checkField returns why a caller's field cannot be written as it is, or nil.
func checkField(name string, value any) error {
	for _, fixed := range reserved {
		// encoding/json matches names without regard to case when it reads
		// a line back, so "SEQ" could stand for "seq".
		if strings.EqualFold(name, fixed) {
			return errors.New("name is reserved")
		}
	}
	if err := checkName(name); err != nil {
		return err
	}
	return checkValue(value, 0)
}

// checkValue returns why value, depth levels down in a field, cannot be
// written as it is, or nil. Numbers that JSON cannot hold are left to the
// encoder.
func checkValue(value any, depth int) error {
	switch v := value.(type) {
	case nil, bool, int, int64, float64:
	case string:
		if !utf8.ValidString(v) {
			return errors.New("a string value is not valid UTF-8")
		}
	case []any:
		if depth == maxDepth {
			return fmt.Errorf("nested deeper than %d levels", maxDepth)
		}
		for _, elem := range v {
			if err := checkValue(elem, depth+1); err != nil {
				return err
			}
		}
	case map[string]any:
		if depth == maxDepth {
			return fmt.Errorf("nested deeper than %d levels", maxDepth)
		}
		for key, elem := range v {
			if err := checkName(key); err != nil {
				return fmt.Errorf("key %q of a nested map: %w", key, err)
			}
			if err := checkValue(elem, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("a value of type %T is not supported", value)
	}
	return nil
}

// nullIfEmpty turns an empty string into nil so that it is written as null.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// encode renders record as one JSON line with its keys in the order of names.
// Text is kept as it is: no \u escapes for non-ASCII or for < > &.
func encode(record map[string]any, names []string) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, name := range names {
		if i > 0 {
			buf.WriteByte(',')
		}
		key, err := encodeValue(name)
		if err != nil {
			return nil, err
		}
		value, err := encodeValue(record[name])
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", name, err)
		}
		buf.Write(key)
		buf.WriteByte(':')
		buf.Write(value)
	}
	buf.WriteString("}\n")
	return buf.Bytes(), nil
}

// encodeValue renders one JSON value without a trailing newline.
func encodeValue(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

// Subscribe returns a channel of the records written from now on, and a
// function that ends the subscription and closes the channel. A subscriber
// that falls more than 256 records behind loses records.
func (l *Log) Subscribe() (records <-chan map[string]any, cancel func()) {
	ch := make(chan map[string]any, subscriberBuffer)
	l.mu.Lock()
	l.subscribers[ch] = true
	l.mu.Unlock()
	return ch, func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.subscribers[ch] {
			delete(l.subscribers, ch)
			close(ch)
		}
	}
}

// Close closes the file. Writes after Close fail. It is safe to call twice.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.file.Close()
}
