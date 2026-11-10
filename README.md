# hcdn-connector

Go module that connects a machine to Hostinger CDN tunnels. It powers
`hostinger preview` in the [Hostinger CLI](https://github.com/hostinger/api-cli),
which shares a local dev server at a temporary public HTTPS URL.

The connector opens outbound TLS sessions to nearby CDN PoPs (port 7844),
and the edge sends visitor requests back over them.
The machine needs no public IP and no open inbound port.

Status: `v0.x`. Until `v1`, a minor version can break the Go API.

## Share a local server

Use the Hostinger CLI:

```sh
brew install hostinger/tap/hostinger
hostinger preview 5173
```

Report problems with the `hostinger` command in
[hostinger/api-cli](https://github.com/hostinger/api-cli/issues), and bugs
in the connector here.

## Use the library

```sh
go get github.com/hostinger/hcdn-connector@latest
```

`connector.RunQuick` runs a whole quick tunnel in one call and prints nothing:

```go
expired, err := connector.RunQuick(ctx, connector.QuickOptions{
	URL:        "http://localhost:5173",
	HostHeader: "localhost",
	OnReady:    func(q connector.QuickTunnel) { fmt.Println(q.URL) },
})
```

`err` is nil when `ctx` ends or the tunnel expires (`expired` is true).
A named tunnel with its own client certificate uses `connector.New`; see
[`examples/embed`](examples/embed). The API reference is on
[pkg.go.dev](https://pkg.go.dev/github.com/hostinger/hcdn-connector/pkg/connector).

The library opens no listener, installs no signal handler and never calls
`os.Exit`. It builds with `CGO_ENABLED=0` for Linux, macOS and Windows on
amd64 and arm64. It never shares sensitive ports on this machine (SSH,
databases, debuggers and similar; see `pkg/localguard`).

### Compatibility

- `pkg/connector`, `pkg/config`, `pkg/creds` and `pkg/localguard` are the
  public API and follow semver from `v0.2.0`. While the module is `v0`, a
  breaking change bumps the minor version. Type aliases of `internal/...`
  types in `pkg/connector` are public API too.
- `internal/...` has no compatibility promise.
- Error text can hold text from the edge as received. Escape it before you
  print it to a terminal.
- `connector.Metrics` exposes Prometheus types; a smaller interface may
  replace it in a minor version.
- The wire protocol follows [`docs/protocol.md`](docs/protocol.md), not the
  module version.

## Standalone binary

`cmd/hcdn-connector` wraps the library for development and testing. It is
not a supported product. Its reference (install, config, commands, metrics)
is in [`docs/standalone.md`](docs/standalone.md).

## Development

```sh
make lint test
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Report security issues as
described in [`SECURITY.md`](SECURITY.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
