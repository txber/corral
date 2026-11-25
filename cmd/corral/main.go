// Command corral supervises sandboxed AI agents. This file holds the
// subcommand dispatcher; each subcommand is one case in run.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/txber/corral/integration/nono"
	_ "github.com/txber/corral/integration/pi"
	"github.com/txber/corral/internal/netns"
)

const version = "0.1.0"

const usage = `usage: corral <command>

commands:
  version   print the version
  netns     set up an agent's network namespace (run as root)
  approvald answer a nono sandbox's permission requests from a scope file
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes one corral command line and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	// The namespace helper runs as root through sudo, so it is handed its
	// arguments before anything else is read or set up.
	if len(args) > 0 && args[0] == "netns" {
		return netns.Main(args[1:], stdout, stderr)
	}
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "corral %s\n", version)
		return 0
	case "approvald":
		return nono.Approvald(args[1:], stdout, stderr)
	case "debug-profiles": // not in the usage: writes the generated profiles for checking
		return nono.DebugProfiles(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "corral: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
