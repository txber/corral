# corral

corral is being built to run AI agents inside a fence: a supervisor that is
not an agent will start each agent in a sandbox, limit what it may reach, and
ask a human about everything beyond that.

corral is at an early stage. So far only `corral version` runs.

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
