# Security policy

Do not report a vulnerability in a public issue, a pull request or a
discussion.

Report it through GitHub private vulnerability reporting: open the
**Security** tab of this repository and click **Report a vulnerability**.
The Hostinger security team receives the report.

Include:

- the version (`hcdn-connector version`) or the commit,
- the steps that reproduce the problem,
- the impact that you expect.

We answer within 5 working days. We publish a fix and a GitHub security
advisory before we disclose the details.

## Scope

- The `hcdn-connector` binary and the Go packages in this repository.
- The wire contract in [`docs/protocol.md`](docs/protocol.md).

The CDN edge, hPanel and the Hostinger API are out of scope for this
repository. Report problems with them through the same channel. The team
forwards them.
