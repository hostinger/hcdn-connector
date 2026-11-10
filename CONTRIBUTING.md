# Contributing

External pull requests are welcome.

## Before you open an issue

- For a problem with your tunnel, your hPanel settings or your account,
  contact Hostinger support. GitHub issues are for bugs in this code.
- For a security problem, read [`SECURITY.md`](SECURITY.md). Do not open a
  public issue.

## Pull requests

1. Keep one change per pull request.
2. Run `make lint test` before you push.
3. Add a test for a bug fix or a new behavior.
4. Do not change the file formats (`config.yml`, `credentials.json`)
   without an issue that the maintainers accepted first.

A review from a code owner (`.github/CODEOWNERS`) is necessary before a
merge.

## Wire protocol

[`docs/protocol.md`](docs/protocol.md) is the contract with the CDN edge
(tunneld). A change to it needs a review from the tunneld owners. The edge
and the connector release on different schedules, so a change must stay
compatible in both directions.

## Public API

`pkg/connector`, `pkg/config`, `pkg/creds` and `pkg/localguard` are the
public Go API. The README section "Compatibility" describes the compatibility
promise. A change that breaks the API needs a minor version bump while the
module is `v0`.

## License

By contributing, you agree that your contribution is licensed under the
Apache License 2.0 ([`LICENSE`](LICENSE)).
