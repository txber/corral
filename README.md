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
