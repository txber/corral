<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/corral-lockup-on-dark.svg">
    <img src=".github/corral-lockup-on-light.svg" alt="corral: a fence for autonomous agents" width="460">
  </picture>
</h1>

corral is being built to run AI agents inside a fence. A supervisor that is
not an agent will start each agent in a sandbox, and three things will hold
for every one of them:

- **Scope** is the fence: the hosts, ports and folders the agent may reach.
- **Approval** is the gate: what lies beyond the scope is asked for, and a
  human decides.
- **Events** are the record: what an agent does, and every decision made
  about it, is written down.

## What corral is for

corral keeps agents inside a boundary and keeps a human at the gate. That is
the whole job:

- start and stop agent programs, each inside a sandbox;
- confine each agent to the hosts, ports and folders it was given, enforced
  below the agent;
- answer an agent's permission requests from what it was given, and pass
  everything else to a human;
- keep model keys out of an agent's reach;
- apply limits, and write every start, stop, grant and denial to one log.

What it is not:

- not an agent: it holds no model and no prompt, and it does not plan work or
  split it up;
- not a sandbox or a firewall of its own: it drives existing tools through
  small interfaces, so each can be replaced;
- not tied to a kind of work, a model provider, an agent program or a user
  interface;
- not a platform: one operator, one machine.

A change belongs in corral if it makes the fence, the gate or the record
better for any agent and any kind of work. What helps only one setup belongs
in that setup's configuration or in an integration.

## Status

Early. So far `corral version` and `corral netns` run; the parts are added
one by one.

## Build and test

    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o corral ./cmd/corral
    go test ./...

## Network namespaces: `corral netns`

`corral netns` gives each agent a network namespace of its own and firewall
rules that let it reach only its targets and one proxy port on this machine.
It runs as root through sudo and can be used on its own:

    corral netns up    <agent_id> <slot> [--target <target>]...
    corral netns allow <agent_id> <slot> --target <target> [--target <target>]...
    corral netns exec  <agent_id> --env-file <path> -- <command> [<arg>...]
    corral netns down  <agent_id> <slot>
    corral netns list

- `up` creates the namespace, a veth pair joining it to this machine and the
  agent's rules. It refuses an agent id or a slot that is in use, and removes
  what it created when a step fails.
- `allow` adds targets to a running agent; open connections stay open.
- `exec` runs a command inside the namespace as the user who called sudo,
  without capabilities, and with exactly the variables of the env file as its
  environment. The env file must belong to that user, have mode 600, hold at
  most 64 lines of `KEY=VALUE` and be no larger than 64 KiB; variables that
  would change how the launching tools run as root, such as `LD_PRELOAD`,
  are refused.
- `down` stops what runs in the namespace and removes the namespace, the veth
  pair and the rules. It succeeds when there is nothing left to remove.
- `list` prints one `<agent_id> <slot>` line per agent.

An agent id is a lowercase letter and up to 11 lowercase letters or digits, a
slot a number from 1 to 250, and a target `<ip[/prefix]>:<tcp|udp>:<port[-port]>`,
for example `192.0.2.7:udp:53` or `10.10.4.0/24:tcp:1-1024`. Agent `<id>` in
slot `<n>` gets:

| what | name or address |
|---|---|
| namespace | `oc-<id>` |
| veth, this machine's end | `ocv<n>`, `198.18.<n>.1/30` |
| veth, the agent's end | `eth0`, `198.18.<n>.2/30` |
| proxy port | `198.18.<n>.1`, TCP `18000+<n>` |
| rules | chains, sets and a log limit named `*_<id>` in table `inet corral` |
| record | `/run/corral/<id>` |

Dropped traffic is logged to the kernel log with the prefix `corral-drop <id> `,
at most 10 lines a second per agent.

It needs `ip`, `nft`, `nsenter` and `setpriv` in `/usr/sbin`, `/usr/bin`,
`/sbin` or `/bin`, and IPv4 forwarding (`net.ipv4.ip_forward = 1`), which it
does not switch on itself. Installed as `/opt/corral/bin/corral`, a sudoers
file lets the supervisor's user call it without a password; `!pam_session`
keeps the launched command in that user's cgroup:

    Cmnd_Alias CORRAL_NETNS = /opt/corral/bin/corral netns *
    Defaults!CORRAL_NETNS !pam_session

together with a line such as `you ALL=(root) NOPASSWD: CORRAL_NETNS`.

What it does not do: it starts no sandbox and no proxy, resolves no host
names, handles no IPv6 (an agent has none), changes no system setting, and
keeps nothing across a reboot.

## Integrations

corral drives other tools through three small interfaces, defined in the
package `integration` (`integration/integration.go`):

- `Sandbox` confines one agent process,
- `KeyProxy` lets an agent use the model gateway without holding its key,
- `Runtime` runs one agent program and speaks its control protocol.

A tool is added by a Go package that implements one of them and registers a
factory under a name from its `init` function; corral links the package in
and builds the tool by the name its configuration gives.

## License

Apache-2.0, see `LICENSE`.
