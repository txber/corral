// The hidden command `corral debug-profiles`: it writes the profiles this
// integration generates for a sample agent, so that they can be checked
// with `nono profile validate`.

package nono

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/txber/corral/integration"
	"github.com/txber/corral/internal/config"
)

// DebugProfiles runs `corral debug-profiles --config FILE --dir DIR`. It
// writes sandbox-none.json and sandbox-direct.json, the sandbox profile in
// each network mode, and proxy.json into DIR, for the gateway that FILE
// names, and prints their paths.
func DebugProfiles(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("corral debug-profiles", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configFile := flags.String("config", "", "corral.toml")
	dir := flags.String("dir", "", "the folder to write the profiles into")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *configFile == "" || *dir == "" || flags.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: corral debug-profiles --config FILE --dir DIR")
		return 2
	}
	if err := debugProfiles(*configFile, *dir, stdout); err != nil {
		fmt.Fprintf(stderr, "corral debug-profiles: %v\n", err)
		return 1
	}
	return 0
}

func debugProfiles(configFile, dir string, stdout io.Writer) error {
	cfg, err := config.Load(configFile)
	if err != nil {
		return err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// A sample agent with every field the profiles use. Its approval socket
	// would be in dir.
	a := integration.Agent{
		ID:        "sample",
		Workdir:   filepath.Join(cfg.Paths.Work, "sample"),
		StateDir:  dir,
		Deny:      []string{filepath.Dir(cfg.Gateway.KeyFile)},
		Gateway:   cfg.Gateway,
		ProxyPort: 18000,
	}
	readPaths := []string{filepath.Join(cfg.Paths.Work, "shared")}
	for _, network := range []string{"none", "direct"} {
		a.Network = network
		p, err := sandboxProfile(a, readPaths)
		if err != nil {
			return err
		}
		if err := writeProfile(filepath.Join(dir, "sandbox-"+network+".json"), p, stdout); err != nil {
			return err
		}
	}
	p, err := proxyProfile(cfg.Gateway)
	if err != nil {
		return err
	}
	return writeProfile(filepath.Join(dir, "proxy.json"), p, stdout)
}

func writeProfile(path string, p profile, stdout io.Writer) error {
	if err := writeJSON(path, p); err != nil {
		return err
	}
	fmt.Fprintln(stdout, path)
	return nil
}
