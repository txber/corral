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
| `corral netns`, the network fence for one agent | works, on its own too; needs root through sudo |
| `corral approvald`, the gate for a nono sandbox's permission requests | works, on its own |
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

The supervisor is not finished, but the network fence and the gate for nono
can be used on their own.

### `corral netns`: a network fence for one agent

`corral netns` gives an agent a network namespace of its own, with firewall
rules that let it reach only its targets and one proxy port on this machine.
It runs as root through sudo.

```sh
sudo corral netns up    <agent_id> <slot> [--target <target>]...
sudo corral netns allow <agent_id> <slot> --target <target> [--target <target>]...
sudo corral netns exec  <agent_id> --env-file <path> -- <command> [<arg>...]
sudo corral netns down  <agent_id> <slot>
sudo corral netns list
```

- `up` creates the namespace, a veth pair joining it to this machine, and the
  agent's rules. It refuses an agent id or a slot that is in use. It records
  the agent first, so `down` can also clear what an interrupted `up` left.
- `allow` adds targets to a running agent; open connections stay open.
- `exec` runs a command, given by its absolute path, inside the namespace as
  the user who called sudo: without capabilities, with `no_new_privs` set so
  that nothing it starts can gain privileges again, and with exactly the
  variables of the env file as its environment. The env file must belong to
  that user, have mode 600, and hold at most 64 lines of `KEY=VALUE` in at
  most 64 KiB. No root process ever holds its variables: the file is read
  only after the drop to the user, by `corral netns enter`, which `exec`
  starts itself and which is not meant to be called directly.
- `down` stops what runs in the namespace and removes the namespace, the veth
  pair and the rules. It succeeds when there is nothing left to remove, and
  fails, after removing the rest, if a process would not stop.
- `list` prints one `<agent_id> <slot>` line per agent.

An agent id is a lowercase letter followed by up to 11 lowercase letters or
digits. A slot is a number from 1 to 250. A target is
`<ip[/prefix]>:<tcp|udp>:<port[-port]>`, for example `192.0.2.7:udp:53` or
`10.10.4.0/24:tcp:1-1024`. Agent `<id>` in slot `<n>` gets:

| What | Name or address |
|---|---|
| namespace | `oc-<id>` |
| veth, this machine's end | `ocv<n>`, `198.18.<n>.1/30` |
| veth, the agent's end | `eth0`, `198.18.<n>.2/30` |
| proxy port | `198.18.<n>.1`, TCP `18000+<n>` |
| rules | chains, sets and a log limit named `*_<id>` in table `inet corral` |
| record | `/run/corral/<id>` |

Dropped traffic goes to the kernel log with the prefix `corral-drop <id> `,
at most 10 lines a second per agent. The table `inet corral` stays in place
once created, also after the last `down`: its base rules keep any leftover
`ocv*` interface closed.

What it needs:

- `ip`, `nft`, `nsenter` and `setpriv` in `/usr/sbin`, `/usr/bin`, `/sbin` or
  `/bin`;
- IPv4 forwarding (`net.ipv4.ip_forward = 1`), which it does not switch on
  itself;
- a sudoers file, if a supervisor is to call it without a password. With the
  binary installed root-owned as `/opt/corral/bin/corral`:

  ```
  Cmnd_Alias CORRAL_NETNS = /opt/corral/bin/corral netns *
  Defaults!CORRAL_NETNS !pam_session
  you ALL=(root) NOPASSWD: CORRAL_NETNS
  ```

  `!pam_session` keeps the launched command in the calling user's cgroup.
  Whoever holds this grant controls every agent's namespace: the helper
  records no owners and is made for one operator.

What it does not do: it starts no sandbox and no proxy, resolves no host
names, passes no IPv6 (off on this machine's end of each pair, and dropped by
the rules), changes no system setting, keeps nothing across a reboot, and
refuses to run inside any network namespace but the machine's own.

### `corral approvald`: answers a nono sandbox's permission requests

`corral approvald` answers the run-time permission requests of a
[nono](https://nono.sh) sandbox from a scope file such as
`examples/scope.toml`. It grants the folders listed in `paths`. It denies
every network request and logs it, because nono does not yet send the
addresses a host resolved to; `targets` take effect once it does.

Put its socket in a folder that only you can write and the sandboxed program
cannot, not below `/run` or `/tmp`, and keep the path under 108 bytes:

```sh
mkdir -p -m 700 ~/.local/state/corral
corral approvald --socket ~/.local/state/corral/approval.sock --scope scope.toml
```

Then point your nono profile at it:

```json
{
  "extends": "default",
  "linux": { "af_unix_mediation": "pathname" },
  "security": {
    "capability_elevation": true,
    "approval_backends": {
      "corral": { "type": "webhook", "url": "unix:///home/you/.local/state/corral/approval.sock", "timeout_secs": 30 }
    },
    "approval_defaults": { "backend": "corral" }
  }
}
```

It prints one JSON line per answer it sent and per request it refused itself
(malformed, too large, too slow), and stops on Ctrl-C.

## Configuration

The supervisor (`corral run`, not finished yet) reads two TOML files;
`examples/` has a complete copy of each.

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

Built in: a sandbox and a key proxy for [nono](https://nono.sh), registered
as `nono`, and a runtime for the coding agent pi, registered as `pi`.

## License

Apache-2.0, see [LICENSE](LICENSE).
