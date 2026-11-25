// The command `corral approvald`: the approval endpoint on its own, for
// anyone who runs nono with a webhook approval backend. It answers from a
// fixed scope file and prints every decision as one JSON line.

package nono

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/txber/corral/integration"
	"github.com/txber/corral/internal/approval"
	"github.com/txber/corral/internal/scope"
)

// Approvald runs `corral approvald --socket PATH --scope FILE` until it
// receives SIGINT or SIGTERM, and returns the exit code: 2 for a bad
// command line or scope file, 1 if the socket cannot be served.
func Approvald(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("corral approvald", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socket := flags.String("socket", "", "the Unix socket to listen on, in a folder only you can write")
	scopeFile := flags.String("scope", "", "a TOML file with the lists targets and paths")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *socket == "" || *scopeFile == "" || flags.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: corral approvald --socket PATH --scope FILE")
		return 2
	}
	s, err := loadScope(*scopeFile)
	if err != nil {
		fmt.Fprintf(stderr, "corral approvald: %v\n", err)
		return 2
	}

	out := &printer{w: stdout}
	decide := func(r integration.Request) integration.Decision {
		d := approval.Decide(r, s, nil)
		out.decision(r, d)
		return d
	}
	srv, err := serve(*socket, decide, out.denial)
	if err != nil {
		fmt.Fprintf(stderr, "corral approvald: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(stderr, "corral approvald: listening on %s\n", *socket)
	<-ctx.Done()
	if err := srv.Close(); err != nil {
		fmt.Fprintf(stderr, "corral approvald: %v\n", err)
		return 1
	}
	return 0
}

// loadScope reads a scope file: the lists targets and paths, nothing else.
func loadScope(path string) (scope.Scope, error) {
	var file struct {
		Targets []string
		Paths   []string
	}
	meta, err := toml.DecodeFile(path, &file)
	if err != nil {
		return scope.Scope{}, err
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return scope.Scope{}, fmt.Errorf("%s: unknown key %q", path, undecoded[0].String())
	}
	s, err := scope.New(file.Targets, file.Paths)
	if err != nil {
		return scope.Scope{}, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// printer writes one JSON line per decision and per denial. The server
// calls it from several goroutines.
type printer struct {
	mu sync.Mutex
	w  io.Writer
}

func (p *printer) decision(r integration.Request, d integration.Decision) {
	record := map[string]any{
		"kind":       r.Kind,
		"decision":   d.Decision,
		"reason":     d.Reason,
		"request_id": r.ID,
	}
	switch r.Kind {
	case "path":
		record["path"] = r.Path
	case "network":
		record["host"], record["port"] = r.Host, r.Port
	default:
		record["detail"] = r.Detail
	}
	p.print(record)
}

// denial prints a denial the server made itself; denial holds its status
// and reason, and kind and request_id when they are known.
func (p *printer) denial(denial map[string]any) {
	record := map[string]any{"decision": "denied"}
	for k, v := range denial {
		record[k] = v
	}
	p.print(record)
}

func (p *printer) print(record map[string]any) {
	record["ts"] = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	line, _ := json.Marshal(record) // strings and numbers only: it cannot fail
	p.mu.Lock()
	defer p.mu.Unlock()
	_, _ = p.w.Write(append(line, '\n'))
}
