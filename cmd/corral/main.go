// Command corral supervises sandboxed AI agents. This file holds the
// subcommand dispatcher; each subcommand is one case in run.
package main

import (
	"fmt"
	"io"
	"os"
)

const version = "0.1.0"

const usage = `usage: corral <command>

commands:
  version   print the version
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes one corral command line and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "corral %s\n", version)
		return 0
	default:
		fmt.Fprintf(stderr, "corral: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
