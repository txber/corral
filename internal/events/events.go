// Package events writes the append-only JSONL event log that every part of
// corral reports to: one JSON object per line, numbered in order.
package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"
)

// subscriberBuffer is how many records a subscriber may fall behind before it
// starts losing records.
const subscriberBuffer = 256

// reserved are the names of the fixed fields of every record.
var reserved = []string{"seq", "ts", "job", "agent_id", "role", "type"}

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
// sequence after the last complete line.
func Open(path, job string) (*Log, error) {
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
		var rec struct {
			Seq int `json:"seq"`
		}
		if json.Unmarshal(lines[i], &rec) == nil && rec.Seq > 0 {
			return rec.Seq
		}
	}
	return 0
}

// Write appends one record and returns it. An empty agentID or role is
// written as null. The record's fixed fields come first, in a fixed order,
// followed by the caller's fields sorted by name. Fields may not use the name
// of a fixed field.
func (l *Log) Write(typ, agentID, role string, fields map[string]any) (map[string]any, error) {
	for _, name := range reserved {
		if _, clash := fields[name]; clash {
			return nil, fmt.Errorf("event field %q is reserved", name)
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
	names := slices.Clone(reserved)
	for name, value := range fields {
		record[name] = value
	}
	extra := make([]string, 0, len(fields))
	for name := range fields {
		extra = append(extra, name)
	}
	slices.Sort(extra)
	names = append(names, extra...)

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
			return nil, err
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
