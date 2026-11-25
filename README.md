# corral

corral runs AI agents inside a fence. A supervisor that is not an agent starts
each agent in a sandbox, limits what it may reach, and asks a human about
everything beyond that.

corral is at an early stage. So far only `corral version` runs.

## Build and test

    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o corral ./cmd/corral
    go test ./...

## License

Apache-2.0, see `LICENSE`.
