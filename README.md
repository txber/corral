<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/corral-lockup-on-dark.svg">
    <img src=".github/corral-lockup-on-light.svg" alt="corral: a fence for autonomous agents" width="460">
  </picture>
</h1>

corral runs AI agents inside a fence. You say what each agent may reach,
corral holds it to that, asks you before anything else happens, and keeps a
record of everything.

> **Status: under construction.** The supervisor that ties the parts together
> is not finished yet. See [What works today](#what-works-today).

## What corral is for

Agents that run commands and read the web are useful, and they read things
you did not write. corral is for running them without having to trust them.

- **A fence.** Each agent gets a list of hosts, ports and folders. It reaches
  nothing else, and that is enforced from outside the agent, by a sandbox and
  a firewall.
- **A gate.** When an agent wants something that is not on its list, the
  request comes to you. No answer means no.
- **A record.** Every start, stop, grant and refusal goes into one log.

corral is neither an agent nor a sandbox. It is the supervisor between them:
it starts the agent program inside the sandbox tool you chose and does the
bookkeeping. It is made for one person on one machine.

## What works today

| Command | State |
|---|---|
| `corral version` | works |
| `corral netns`, the network fence for one agent | checks its arguments; the commands are being built |
| `corral run` and the client commands | not yet |

## Setup

corral is a single static binary for Linux. To build it you need Go 1.27 or
newer.

```sh
git clone https://github.com/txber/corral
cd corral
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o corral ./cmd/corral
sudo install -m 755 corral /usr/local/bin/corral
```

Run the tests with `go test ./...`.

## Use

```sh
corral version
```

This section grows as the commands above arrive.

## Configuration

corral reads two TOML files; `examples/` has a complete copy of each.

- `corral.toml` says where the model gateway is (`[gateway]`), which paths
  corral uses (`[paths]`), how many agents may run at once (`max_agents`) and
  which integration serves as sandbox, runtime and key proxy (`[sandbox]`,
  `[runtime]`, `[key_proxy]`, each with a `use` key and that integration's own
  options). See `examples/corral.toml`.
- `roles.toml` has one table per kind of agent a job may start: its network
  mode, model, limits, prices and options for the runtime. See
  `examples/roles.toml`.

A key that corral does not know is an error, and the message names it. A `~`
at the start of a path is the home folder.

## Integrations

corral does not confine or run anything itself. It drives three kinds of
tool, each behind a small interface in the package `integration`:

- a **sandbox** that confines one agent process,
- a **runtime**, the agent program and its control protocol,
- a **key proxy** that lets an agent use the model gateway without holding
  its key.

A tool is added by a Go package that implements one of the interfaces and
registers itself under a name; the configuration then picks it by that name.

## License

Apache-2.0, see [LICENSE](LICENSE).
