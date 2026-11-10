# hCDN Tunnel wire protocol, version 1

This document is the contract between the connector (this repository) and
the CDN edge (tunneld). `internal/proto/proto.go` holds the constants. This
file is the public reference.

The protocol version is independent of the module version. A change to
this file needs a review from the tunneld owners (see `CONTRIBUTING.md`).

## 1. Transport

| Port | Peer | TLS ALPN | Use |
|------|------|----------|-----|
| 7844 | tunneld | `hcdn-tunnel/1` (sessions), `hcdn-tunnel-api/1` (discovery) | Primary |
| 443 | nginx on the PoP | `http/1.1` | Fallback for networks that allow 80/443 only |

- TLS 1.3 only. The connector presents a client certificate.
- The client certificate has exactly one URI SAN `hcdn-tunnel:<tunnel-uuid>`.
  The edge maps the certificate serial to the tunnel.
- On 443 the connector sends `GET /_tunnel/v1/connect` with
  `Upgrade: hcdn-tunnel` and `Connection: Upgrade`. After the
  `101 Switching Protocols` the connection carries the same session as on
  7844. On 443 the discovery API is plain HTTPS on the same host.
- After the TLS handshake the roles swap: the edge is the HTTP/2 client
  and the connector is the HTTP/2 server. The connector never sends the
  HTTP/2 client preface.

## 2. Discovery API

The connector calls the API on a bootstrap endpoint from
`credentials.json` (`bootstrap_endpoints`). Every call uses the client
certificate.

`GET /_hcdn/v1/pops`:

```json
{
  "gen": 41,
  "pops": [
    {"code": "fra", "endpoint": "fra.tunnel.hostinger.io", "ports": [7844, 443], "region": "eu-central", "allowed": true}
  ],
  "pinned_pops": ["fra"]
}
```

- `gen` is the list generation (below 2^53). The hello carries the same
  value in `hcdn-pops-gen`. The connector refreshes the list when the two
  differ.
- A PoP code is unique (case-insensitive). An endpoint is a host name in
  the registrable domain (eTLD+1, per the public suffix list) of a
  bootstrap endpoint: `fra.tunnel.hostinger.io` for the bootstrap
  `tunnel.hostinger.io`. The connector rejects a reply with any other
  endpoint, unless it trusts a private CA (`server_ca_file`).

`GET /_hcdn/v1/ping`: `2xx`, empty body. The connector measures the RTT
of three TLS handshakes, each followed by a ping.

`GET /_hcdn/v1/whoami`:

```json
{"tunnel_id": "<uuid>", "cert_serial": "<hex>", "days_left": 214, "pop": "fra", "node": "<edge node>",
 "class": "named", "expires_at": "2027-05-09T10:00:00Z"}
```

- `class` is `named` or `quick` (section 8). `hostname` is present for the
  quick class only. `expires_at` is the certificate `NotAfter` (RFC 3339).
  tunneld before 0.3.0 omits all three. A connector ignores unknown fields.
- For a quick id, `pops` sets `allowed: true` only for the PoPs that accept
  quick tunnels.
- From tunneld 0.5.0 a quick reply carries an `owner` object when the edge
  asks for an owner ticket (section 9):

  ```json
  "owner": {"mode": "log", "issuer": "wh-api", "status": "ok", "reason": "ok", "client_id": "123456"}
  ```

  `mode` (`log` or `require`) and `issuer` are always set. `status` (`ok`,
  `missing` or `invalid`), `reason` (the label of section 9) and `client_id`
  (when `status` is `ok`) answer only a whoami that carried
  `hcdn-owner-ticket: <ticket>`. Mode `off` and tunneld before 0.5.0 omit the
  object: the edge did not ask. A connector treats a mode it does not know
  the same way.
- A quick connector calls whoami twice at most. The first call has no owner
  header. Only when that reply has `owner` with mode `log` or `require`, and
  the connector got a ticket, does a second whoami carry the ticket and
  return the verdict.

## 3. Hello

The first stream on every session. The edge sends:

```
POST /_hcdn/v1/hello
hcdn-protocol: 1
hcdn-edge-node: <edge node name>
hcdn-edge-pop: fra
hcdn-cert-days-left: 214
hcdn-max-inflight: 512        # per-session cap the connector enforces
hcdn-max-streams: 128         # informational
hcdn-pops-gen: 41
hcdn-edge-features: visible   # optional, comma-separated
```

The connector answers:

```
200
hcdn-connector-version: <version>
hcdn-connector-id: <random per process>
hcdn-features: ws,owner,visible
hcdn-connected-pops: fra,phx  # informational
hcdn-transport: 7844 | 443-fallback
hcdn-owner-ticket: <ticket>   # or, without a ticket:
hcdn-owner-absent: no_token | opted_out | fetch_failed | not_requested | unsupported
```

- `hcdn-features` is a comma-separated list. `owner` means the connector
  sends one of the two owner headers on every hello and knows the goaway
  `owner_required`. `visible` means the connector reads the edge's
  `visible` request (section 10). Connectors before it send `ws` only, or
  `ws,owner`.
- `hcdn-edge-features` is a comma-separated list; the connector trims and
  lower-cases each item and ignores unknown ones. `visible` means the edge
  sends the `visible` request (section 10) on this session.
- Every hello answer of a run carries the same `hcdn-owner-ticket`, or the
  same `hcdn-owner-absent` reason (section 9). A named tunnel sends
  `hcdn-owner-absent: not_requested`.

- A `hcdn-protocol` value other than `1` gets `400`, and the connector
  closes the session.
- A non-printable `hcdn-edge-node`, `hcdn-edge-pop`, `hcdn-pops-gen` or
  `hcdn-edge-features`
  (invalid UTF-8 or a control character) gets the same `400` and close.
- The connector closes a session without a hello within 10 s.
- `hello`, `goaway` and `visible` carry no `hcdn-request-id`. The connector matches
  them on the path before the visitor request checks. A control path with
  `hcdn-request-id` gets `404` and is never proxied.

## 4. Visitor request

- `:method`, `:scheme https`, `:authority` = visitor `Host`, `:path` =
  the byte-exact request URI.
- `hcdn-request-id` is required. A request without it gets `400`.
- `hcdn-vhost` names the vhost.
- The connector removes hop-by-hop headers and every `hcdn-*` and
  `x-hcdn-*` request header. It adds `Hcdn-Tunnel-Id`. It removes
  `Forwarded` and `X-Forwarded-Host`.
- The connector removes `hcdn-*` headers from the service response and
  adds `hcdn-connector-rt: <ms>` (time to first byte from the service).
  The edge records and removes it.
- Bodies stream in both directions.

Errors: `502`, an empty body and `hcdn-error`:

| `hcdn-error` | Cause |
|--------------|-------|
| `service_unreachable` | dial or TLS failure to the service |
| `service_timeout` | no response headers within `response_header_timeout` |
| `bad_gateway` | malformed response or connection reset |
| `overloaded` | the per-session inflight cap (`hcdn-max-inflight`) is full |

The edge replaces the response with a `530` page and shows the value in
`X-Hcdn-Tunnel-Error`.

Limits: 256 concurrent streams per session, 64 KiB HTTP/2 frames, 64 KiB
request and response headers.

## 5. WebSocket

The edge opens:

```
CONNECT
:authority: shop.example.com
hcdn-upgrade: websocket
hcdn-path: /ws?room=1
hcdn-request-id: <id>
hcdn-vhost: <vhost>
sec-websocket-key, sec-websocket-version, sec-websocket-protocol, origin, cookie, ...
```

- The connector sends an HTTP/1.1 Upgrade to the service.
- On `101` it answers `200` with `hcdn-ws-accept: <Sec-WebSocket-Accept>`
  and `hcdn-ws-protocol`, then copies bytes in both directions.
- Success is `200` and a non-empty `hcdn-ws-accept`. A `200` without
  `hcdn-ws-accept` is a normal response.
- The connector skips interim `1xx` responses. A `101` without
  `Sec-WebSocket-Accept` or `Upgrade: websocket` gets `bad_gateway`.
- The connector removes `Sec-WebSocket-Extensions` from the request to the
  service.

## 6. Goaway

The edge sends a control request before the HTTP/2 `GOAWAY`:

```
POST /_hcdn/v1/goaway
hcdn-reason: drain | revoked | disabled | unknown_serial | cap_exceeded | auth_unavailable | reselect | protocol_error | owner_required
hcdn-retry-after: 60          # seconds
```

The connector answers `204`. The edge then sends `GOAWAY(NO_ERROR)` and
closes after the in-flight streams finish (15 s maximum). An unknown
reason is handled as `protocol_error`.

| Reason | Default `hcdn-retry-after` | Ceiling | Connector |
|--------|----------------------------|---------|-----------|
| `drain` | - | - | Open a replacement session at once. Prefer another address of the same PoP. |
| `cap_exceeded` | 60 s | 15 min | Pause dials to that PoP |
| `auth_unavailable` | 15 s | 15 min | Exclude that address. After all addresses, pause the PoP. |
| `reselect` | - | - | Refresh `/_hcdn/v1/pops`, select again, open new sessions first, then drain the old ones |
| `disabled` | 300 s | 1 h | Drain the sessions, pause every PoP, then select again. No exit. |
| `revoked` | - | - | Stop and exit 78 |
| `unknown_serial` | - | - | Ignore it when the session used an older certificate than the current one. Else get new credentials one time. Exit 78 when they do not change. |
| `protocol_error` | - | - | Back off (1 s to 60 s, full jitter) |
| `owner_required` | - | - | Stop and exit 77. The edge serves this quick tunnel only with a valid owner ticket (section 9). The edge sends it only to a connector with the `owner` feature; older connectors get `revoked` |

A missing, negative, non-numeric or overflowing `hcdn-retry-after` gets
the default for the reason. A larger value gets the ceiling.

## 7. Exit codes

| Code | Meaning |
|------|---------|
| 0 | OK |
| 1 | Runtime failure |
| 2 | Usage error |
| 77 | The edge serves this quick tunnel only for a Hostinger account (`EX_NOPERM`): the whoami verdict in mode `require`, or goaway `owner_required`. Sign in, not "taken down" |
| 78 | Bad config or credentials, or the tunnel is revoked (goaway `revoked`, or `unknown_serial` without new credentials). A supervisor must not restart the process. |

## 8. Quick class

A quick tunnel needs no account. The connector makes its own key and a
self-signed client certificate. It is anonymous unless the edge asks for an
owner (section 9) and the caller can get an owner ticket. No Hostinger API
call happens before the first handshake; only after a whoami that asks for
an owner does the caller ask the issuer for a ticket. The id binds the key,
so only the key holder can serve the hostname. The class follows from the
id alone: a version 8 UUID is quick, a version 4 UUID is named. A quick id
never takes the CA chain path, and a named id never takes the quick path.

| Item | Rule |
|------|------|
| Key | ECDSA P-256 only |
| `NotBefore` | Whole seconds, UTC. The connector sets `now − 5 min` (clock skew) |
| `NotAfter` | `NotBefore + 24 h`. tunneld refuses a longer window |
| Id | `h = SHA-256(SPKI DER ‖ uint64_be(NotBefore unix seconds))`; `id = h[0:16]`; `id[6] = (id[6] & 0x0f) \| 0x80`; `id[8] = (id[8] & 0x3f) \| 0x80`; lowercase canonical UUID |
| SPKI DER | The certificate `SubjectPublicKeyInfo` bytes |
| Leaf | Self-signed, no intermediates, random 128-bit serial, `KeyUsage digitalSignature`, EKU `clientAuth`, exactly one URI SAN `hcdn-tunnel:<id>`, no other SAN, not a CA |
| Hostname | `<id without dashes>.<zone>`. The edge owns the zone (`hostingerpreview.com` in production, `hostingerpreview.dev` on staging). The connector learns the hostname from `whoami` |
| Lifetime | tunneld aborts quick sessions at `NotAfter`. The connector stops 1 min before. No renewal: a new certificate is a new id and a new hostname |
| Takedown | goaway `revoked` (exit 78). tunneld keeps the id refused for the rest of its life |
| Limits | goaway `cap_exceeded` when the network of the client (/24 or /56) or the node holds too many quick tunnels |

The TLS 1.3 CertificateVerify proves possession of the private key. A client
that wants another quick hostname needs that private key, or a SHA-256
second preimage on 122 bits.

Test vectors: `pkg/creds/testdata/quick_id.json`. The edge (tunneld) uses
the same vectors, so a change to the derivation needs a matching edge change.

## 9. Owner ticket

An owner ticket binds a quick tunnel to a Hostinger account (`client_id`).
The issuer (the Hostinger API) signs it; tunneld checks it offline. tunneld
never sees a sign-in token. The connector treats the ticket as an opaque
string.

- **Format.** A compact JWS (JWT), `alg: EdDSA` (Ed25519),
  `typ: hcdn-owner+jwt`, with a `kid`. Claims: `v` (1), `iss`, `aud`
  (`hcdn-tunnel`), `sub` (the client_id, a string), `tid` (the quick tunnel
  id), `iat`, `nbf`, `exp` (the certificate `NotAfter`), `jti`, and an
  optional `rid`. It only says "client X owns tunnel `tid` until `exp`".
- **Binding.** tunneld accepts a ticket only when `tid` equals the tunnel id
  proven by mTLS. A ticket for another tunnel is useless without that
  tunnel's key.
- **Owner mode** (tunneld `quick.owner.mode`): `off` (whoami has no `owner`
  object), `log` (an owner is attached when the ticket is valid; a session
  without one is still served) or `require` (a session without a valid
  ticket gets goaway `owner_required`).
- **Flow.**
  1. First whoami without a header (section 2).
  2. When it reports mode `log` or `require`, the caller asks the issuer for
     a ticket for the tunnel id and `NotAfter` the connector derived itself.
     The connector bounds the call: `log` mode one call within 2 s;
     `require` mode up to two calls within 3 s each, the second only after a
     temporary failure (a timeout, a network error or a 5xx).
  3. With a ticket, a second whoami carries `hcdn-owner-ticket` and returns
     the verdict.
  4. Every hello answer carries the ticket, or the no-ticket reason.
     Reconnects re-send the same value and never ask the issuer again. A run
     that started while the mode was `off` stays `not_requested`.
- **No-ticket reasons** (`hcdn-owner-absent`). The value is advisory:
  tunneld counts and logs it and never decides on it.

  | Value | Meaning |
  |-------|---------|
  | `no_token` | The caller has no credentials to ask for a ticket |
  | `opted_out` | The user asked for an anonymous tunnel |
  | `fetch_failed` | The issuer call failed or timed out, or the answer was not a compact JWS |
  | `not_requested` | The edge did not ask (mode `off`, an older tunneld, or a named tunnel) |
  | `unsupported` | The caller has no way to get a ticket (the standalone `hcdn-connector quick`) |

- **Verification labels**, in order; tunneld returns the first that fails:
  `missing`, `malformed` (over 2048 bytes, not three base64url parts, bad
  JSON), `bad_alg`, `unknown_kid`, `bad_signature`, `bad_claims`,
  `tid_mismatch`, `not_yet_valid` / `expired`, else `ok`. The leeway is 60 s.
- **Require mode.** No ticket, or a second-whoami verdict other than `ok`,
  stops the connector before any session with exit 77. A session whose
  ticket fails later (for example after a key change) gets goaway
  `owner_required`, also exit 77.
- **Another environment.** A verdict `unknown_kid` or `bad_claims` for a
  ticket whose (unverified) `iss` differs from the whoami `owner.issuer`
  means the ticket comes from another environment, for example a production
  issuer against a staging edge. The connector reports it so the caller
  can say so.
- **Standalone `hcdn-connector quick`.** It has no way to get a ticket: it
  sends `hcdn-owner-absent: unsupported` and cannot run in `require` mode.

Test vectors: `pkg/connector/testdata/owner_ticket.json`, a copy of the
edge's test vectors. The keys in it are for tests only; no environment
trusts them.

## 10. Visible

An edge that advertised `hcdn-edge-features: visible` tells the connector
when visitors can reach the tunnel through it:

```
POST /_hcdn/v1/visible
hcdn-visible-scope: pop | node
```

- `pop`: every node of the edge's PoP routes the tunnel. `node`: only the
  sending node does.
- The connector answers `204`. A scope other than `pop` or `node` (after
  trimming and lower-casing) gets `400`, and so does a `visible` before the
  session's hello. Another method gets `405`.
- The connector acts on the first `visible` of a session; a repeat gets
  `204` and is ignored. Each session gets its own.
- A connector reports the tunnel reachable at the first of: a `visible` on
  any session; a ready session on an edge without the feature; a ready
  session on an edge with the feature and no `visible` within its wait
  (3 s by default).
