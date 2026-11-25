# corral

corral is being built to run AI agents inside a fence: a supervisor that is
not an agent will start each agent in a sandbox, limit what it may reach, and
ask a human about everything beyond that.

corral is at an early stage. So far only `corral version` runs.

## Build and test

    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o corral ./cmd/corral
    go test ./...

## License

Apache-2.0, see `LICENSE`.
