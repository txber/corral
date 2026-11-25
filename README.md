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

Early. So far only `corral version` runs; the parts are added one by one.

## Build and test

    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o corral ./cmd/corral
    go test ./...

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
