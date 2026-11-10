# Standalone binary and connector reference

`cmd/hcdn-connector` is a thin wrapper over the library. It exists to
develop and test the connector: it runs named tunnels from `config.yml` and
`credentials.json`, and quick tunnels with `hcdn-connector quick`. It is
**not a supported product**:
Hostinger offers no support for it, and its commands, packages and release
files can change or go away in any version. To share a local server, use
`hostinger preview` in the [Hostinger CLI](https://github.com/hostinger/api-cli).

This page documents the binary as it is today, and the connector behaviour
behind it. The wire contract with the edge is [`protocol.md`](protocol.md).

## How it works

1. The connector gets a tunnel identity: a per-tunnel client certificate
   (a named tunnel), or a fresh key and self-signed certificate (a quick
   tunnel, which `hostinger preview` uses).
2. It calls the discovery API (`GET /_hcdn/v1/pops`) on a bootstrap
   endpoint and accepts only PoP endpoints in that endpoint's domain
   (`protocol.md`, section 2). It probes every allowed PoP (three TLS handshakes plus
   `GET /_hcdn/v1/ping`, median RTT) and picks the `home_pops` fastest
   PoPs. Pinned PoPs come first. The second PoP is in another region when
   the list allows it.
3. It keeps `sessions_per_pop` TLS 1.3 sessions per PoP. After the
   handshake the roles swap: the edge is the HTTP/2 client, the connector
   is the HTTP/2 server. The connector never sends the HTTP/2 client
   preface.
4. Each visitor request arrives as an HTTP/2 stream. The connector routes
   on the `Host`, proxies to the configured service and answers.
5. Every `reprobe_interval` the connector re-probes. It switches a PoP only
   when a candidate is faster by both `switch_min_gain_pct` and
   `switch_min_gain_ms`, and after `holddown`. A switch never removes the
   only PoP in a second region. New sessions open first, old sessions drain
   after.
6. A home PoP with no ready session for 30 s starts a new selection at once,
   at most once a minute. Time in a goaway pause does not count. The
   selection replaces that PoP, also within `holddown`, when another PoP is
   available.

## Ports

| Port | Peer | TLS ALPN | Use |
|------|------|----------|-----|
| 7844 | tunneld | `hcdn-tunnel/1` (sessions), `hcdn-tunnel-api/1` (discovery) | Primary. |
| 443 | nginx on the PoP | `http/1.1` | Fallback for networks that allow 80/443 only. The connector sends `GET /_tunnel/v1/connect` with `Upgrade: hcdn-tunnel` and runs HTTP/2 after the `101`. Discovery runs as plain HTTPS on the same host. Sessions on this path drop on every CDN deploy and reconnect within seconds. |

The connector tries the ports in the `ports` order per endpoint. A network
failure on 7844 falls through to 443. When 7844 failed on every resolved
address of the endpoint, the connector tries 443 first and re-tests 7844 after
1 minute, then after 2, 4, ... minutes (doubling on every failed re-test, at
most once a day). A certificate error or a TLS alert from the edge never
triggers the fallback. On 443 the connector offers ALPN `http/1.1` only; nginx
aborts a handshake whose ALPN list has neither `http/1.1` nor `h2`.

After a `drain` goaway (a planned tunneld restart) the redial retries 7844 every
200 ms for up to 5 s before it considers 443: the new tunneld binds within
milliseconds, and a refusal inside that window is not a 7844 failure.

## Quick tunnel

One command gives a public HTTPS URL for a local service. You need no
account, no files and no config:

```sh
$ hcdn-connector quick --url http://localhost:8080
Your quick tunnel is ready:
  https://7f3c9a1e0b2d8c4f9e6a5b3d1c0f2e4a.hostingerpreview.com
Expires 2026-10-08 14:05 UTC.
```

- The URL is random and lives at most 24 h. Run the command again for a new
  URL. The key stays in memory.
- `--host-header localhost` sets the `Host` header for the service. Dev
  servers such as Vite refuse unknown hosts.
- Outbound TCP 7844 must be open. The command says so when it is blocked.
- Sensitive ports on this machine are never shared: SSH, databases, the
  Docker and Kubernetes APIs, debuggers such as the Node inspector (9229),
  Chrome DevTools (9222) and Go pprof (6060), and similar services
  (`localguard.BlockedPorts`). Such a `--url` exits 2 before any edge call,
  whatever form names this machine (`0`, `127.1`, a name that resolves to
  loopback, a LAN address of this machine). Every dial is checked again
  after DNS, so a redirect or a changed DNS answer cannot reach one either.
- Exit 0 when the tunnel expires or on Ctrl-C. Exit 78 when the tunnel was
  taken down. Exit 77 when the edge serves quick tunnels only for a
  Hostinger account: this command cannot link one (`protocol.md`,
  section 9).
- Browsers see a warning page on the first visit. A request header
  `Hcdn-Skip-Browser-Warning: 1` skips it. API clients and webhooks do not
  see it.

The id and certificate rules are in [`protocol.md`](protocol.md),
section 8.

## Supported platforms

| OS | Arch | Artifacts | Service manager |
|----|------|-----------|-----------------|
| Linux | amd64, arm64 | `.deb`, `.rpm`, `.tar.gz`; container image built with `make docker` | systemd |
| macOS 12+ | amd64, arm64 | `.tar.gz` | none: run in the foreground |
| Windows 10 1803+, Server 2019+ | amd64, arm64 | `.zip` | none: run in the foreground |

All builds use `CGO_ENABLED=0`. Linux and Windows binaries are static. macOS
binaries link only the system library (`libSystem`). Other platforms can
compile, but they have no CI and no support.

| Area | Linux | macOS | Windows |
|------|-------|-------|---------|
| Default config | `/etc/hcdn-connector/config.yml` | `/usr/local/etc/hcdn-connector/config.yml` | `%ProgramData%\hcdn-connector\config.yml` |
| Default admin socket | `/run/hcdn-connector/admin.sock` | `/var/run/hcdn-connector/admin.sock` | `%ProgramData%\hcdn-connector\run\admin.sock` |
| Admin socket access | mode `0660` | same as Linux | the connector creates the directory with a DACL for SYSTEM, Administrators and the owner. It refuses an existing directory that Everyone, Users, Authenticated Users or Guests can read. |
| Credentials file check | refused when group- or world-readable (`chmod 0600`) | same as Linux | refused when Everyone, Users, Authenticated Users or Guests can read it (`icacls`) |
| Config, credentials and CA file trust | refused when the file is world-writable, or its directory is world-writable without the sticky bit | same as Linux | refused when an account other than SYSTEM, Administrators and the current user owns the file or its directory, or can change either (write, add a file or subdirectory, delete, change the DACL or owner) |
| Credentials reload | `SIGHUP` and a 10 s mtime poll | same as Linux | 10 s mtime poll only |
| Stop | `SIGTERM`, `SIGINT` | same as Linux | Ctrl-C, Ctrl-Break, console close, logoff, shutdown |

The default paths are for a system service. As a non-root user, set
`admin_socket: ""` to disable the admin socket, or set a path that you can
write and pass `--socket` to `status`.

## Install

Download a release from
[GitHub releases](https://github.com/hostinger/hcdn-connector/releases).
`<version>` below is the release version without the `v`, for example
`0.2.0`.

| File | For |
|------|-----|
| `hcdn-connector_<version>_amd64.deb`, `hcdn-connector_<version>_arm64.deb` | Debian, Ubuntu: binary, systemd unit, `hcdn-connector` user |
| `hcdn-connector-<version>-1.x86_64.rpm`, `hcdn-connector-<version>-1.aarch64.rpm` | RHEL, Fedora and similar: same content as the `.deb` |
| `hcdn-connector-<version>-linux-<arch>.tar.gz` | Linux without a package manager: binary, systemd unit, config example |
| `hcdn-connector-<version>-darwin-<arch>.tar.gz` | macOS |
| `hcdn-connector-<version>-windows-<arch>.zip` | Windows |
| `SHA256SUMS`, `<file>.sigstore.json`, `hcdn-connector-<version>.spdx.json` | checksums, a Sigstore signature bundle per file, SBOM |

`<arch>` is `amd64` or `arm64`. Every archive also holds `README.md`,
`LICENSE`, `NOTICE`, `config.example.yml`, and `docs/` with this page and
`protocol.md`. There is no published
container image: build one with `make docker` (see "Container" below).

Verify a download before you install it:

```sh
sha256sum --ignore-missing -c SHA256SUMS          # macOS: shasum -a 256 --ignore-missing -c SHA256SUMS
cosign verify-blob --bundle <file>.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/hostinger/hcdn-connector/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  <file>
```

With Go 1.27 or later, you can build the binary from source instead. It
reports the version you asked for (`hcdn-connector version`):

```sh
go install github.com/hostinger/hcdn-connector/cmd/hcdn-connector@latest
```

macOS marks a file downloaded with a browser as quarantined, and the binary
is not notarized. Download it with `curl -LO`, or clear the flag with
`xattr -d com.apple.quarantine hcdn-connector`.

Debian or Ubuntu (for RHEL, use `sudo rpm -i hcdn-connector-<version>-1.x86_64.rpm`):

```sh
sudo dpkg -i hcdn-connector_<version>_amd64.deb
sudo install -o hcdn-connector -g hcdn-connector -m 0600 credentials.json /etc/hcdn-connector/credentials.json
sudo $EDITOR /etc/hcdn-connector/config.yml
sudo -u hcdn-connector hcdn-connector check --config /etc/hcdn-connector/config.yml
sudo systemctl enable --now hcdn-connector
sudo hcdn-connector status
```

The admin socket is mode `0660`, owned by `hcdn-connector`. Run `status` with
`sudo`, or add your user to the `hcdn-connector` group.

`credentials.json` comes from hPanel (or from `POST /v2/tunnels` on the Hostinger API).
The connector refuses a credentials file that is group- or world-readable.

Container: build the distroless image from a checkout of the release tag,
then run it:

```sh
git clone --branch v<version> https://github.com/hostinger/hcdn-connector.git && cd hcdn-connector
make docker VERSION=<version>                    # tags hcdn-connector:<version>
docker run -d --name hcdn-connector --restart on-failure:5 --stop-timeout 25 \
  -v /etc/hcdn-connector:/etc/hcdn-connector:ro \
  hcdn-connector:<version>
```

- `--restart on-failure:5`: exit 78 (bad credentials, revoked tunnel) cannot
  recover by restart. `unless-stopped` or `always` restart it without limit.
- `--stop-timeout 25`: the drain takes up to 15 s. The Docker default of 10 s
  cuts in-flight requests.
- With `--read-only`, add `--tmpfs /run/hcdn-connector:uid=65532,mode=0750`
  for the admin socket.
- `metrics_addr` must be a loopback address, so the metrics listener is
  reachable only from inside the container network namespace.

Volume layout (the image runs as uid 65532, `nonroot`, and has no shell):

| Path in the container | Content | Owner / mode |
|-----------------------|---------|--------------|
| `/etc/hcdn-connector/config.yml` | config | `65532`, `0640` |
| `/etc/hcdn-connector/credentials.json` | credentials | `65532`, `0600` (the connector refuses wider modes) |
| `/run/hcdn-connector/` | admin socket dir, created in the image | `65532`, `0750` |

Prepare the host directory with `chown -R 65532:65532` before the first
start. `docker exec hcdn-connector hcdn-connector status` reads the socket
from inside the container.

Windows (`.zip`): any user can create a subdirectory of `%ProgramData%`, or a
junction there that points elsewhere, and then owns it. Create
`%ProgramData%\hcdn-connector` locked from the start, before you put
`config.yml` and `credentials.json` in it. Paste the whole block into an
elevated Windows PowerShell 5.1 (`powershell.exe`); it stops at the first
error:

```powershell
$dir = "$env:ProgramData\hcdn-connector"
& {
$ErrorActionPreference = 'Stop'
if (Get-ChildItem -LiteralPath $env:ProgramData -Filter hcdn-connector -Force) { throw "$dir exists: see below" }
$sec = New-Object Security.AccessControl.DirectorySecurity
$sec.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
[void][IO.Directory]::CreateDirectory($dir, $sec)   # SYSTEM and Administrators only, from the start
$item = Get-Item -LiteralPath $dir -Force         # created by another account in between? refuse it
if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
    ($item.GetAccessControl().GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544')) { throw "$dir is not ours: see below" }
Copy-Item config.yml, credentials.json $dir      # copy, not move: a moved file keeps its old DACL
icacls "$dir\*" /setowner "*S-1-5-32-544" /C
icacls "$dir\*" /reset /C                       # files inherit SYSTEM and Administrators only
hcdn-connector.exe check --config "$dir\config.yml"
}
```

Verify: `(Get-Acl $dir).Owner` prints `BUILTIN\Administrators`, and
`icacls $dir` and `icacls "$dir\*"` list only `NT AUTHORITY\SYSTEM` and
`BUILTIN\Administrators`: no `Users`, `Authenticated Users` or `Everyone`
entry, and no `(WD)`, `(AD)`, `(M)` or `(F)` for any other account. `run`,
`check` and `status` refuse a config file or directory that another account
owns or can change, a junction or symbolic link in its path that another
account owns or can re-point, and a network share, and name the path or the
link and the account.

If the block stops because `$dir` exists, look before you touch it:
`Get-Item $dir -Force | Format-List LinkType, Target, Attributes`. A junction
or symbolic link (`LinkType` set, `ReparsePoint` in `Attributes`): remove the
link with `cmd /c rmdir "$dir"`, which deletes the link and not its target,
and run the block again. Do not run `Get-Acl`, `takeown`, `icacls` or
`Copy-Item` on it first: they follow the link. A directory that another user
created may hold files, junctions or ACEs that user chose: take ownership with
`takeown /F $dir /R /A`, delete it with `cmd /c rmdir /s /q "$dir"` (it removes
a junction inside without following it), and run the block again. A directory
that this block created (not a link, owner `BUILTIN\Administrators`) can be
reused: copy new files with the last four lines of the block. To run the
connector as a standard user, grant that account read access
(`icacls $dir /grant "<user>:(OI)(CI)RX"`) and set `admin_socket: ""`: the
account cannot create `run\` in the directory.

## Commands

| Command | Purpose |
|---------|---------|
| `hcdn-connector quick --url http://localhost:8080` | Anonymous quick tunnel (see "Quick tunnel") |
| `hcdn-connector run --config /etc/hcdn-connector/config.yml` | Main loop |
| `hcdn-connector check --config ... [--whoami]` | Validate config, credentials permissions and ingress rules. Dial every service (TCP, TLS for `https`). `--whoami` also calls `GET /_hcdn/v1/whoami` on a bootstrap endpoint. |
| `hcdn-connector csr --out key.pem,csr.pem --tunnel-id <uuid>` | CSR mode: generate a P-256 key locally and print a CSR with no SANs. Submit the CSR to `POST /v2/tunnels/:id/certificates`. The key never leaves the host. |
| `hcdn-connector status [--json]` | Query the admin socket: probe table with the selection reason, sessions per PoP, last errors. Exits 1 with "admin socket disabled in config" when `admin_socket` is `""`. |
| `hcdn-connector version` | Build information |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | OK |
| 1 | Runtime failure (`check`: a service is unreachable) |
| 2 | Usage error |
| 77 | `quick` only: the edge serves this quick tunnel only for a Hostinger account (owner mode `require`, goaway `owner_required`) |
| 78 | Bad config or credentials, or the tunnel was **revoked**. The shipped unit sets `RestartPreventExitStatus=78`, so systemd does not restart the service. Install new credentials and start it again. |

A **disabled** tunnel does not exit. The connector pauses all sessions for
`hcdn-retry-after` (default 300 s), then re-runs PoP selection and
reconnects. Enabling the tunnel in hPanel needs no action on the host.

## Configuration

`config.yml` is parsed strictly. Unknown keys are errors.

The file formats (`config.yml`, `credentials.json`) do not change. Since
`v0.2.0`, `admin_socket: ""` disables the admin socket and `status` (before,
it selected the default path); an absent key keeps the default. The local
port guard (see "Request handling") applies to named tunnels too: a service on
a listed port of this machine answers `service_unreachable` until the port is
in `allow_local_ports`.

```yaml
tunnel_id: 3f9c2a7e-0b3e-4d0a-9d0a-1c8f5e7b2a11
credentials_file: /etc/hcdn-connector/credentials.json   # 0600, refused if group/world readable
home_pops: 2                   # how many PoPs to keep sessions to (1..3)
sessions_per_pop: 2            # 1..4; the server caps it too
pop_selection:
  mode: auto                   # auto = probe and pick fastest; manual = use `pops`
  pops: []                     # manual only; must be inside the tunnel's allowed PoPs
  reprobe_interval: 10m
  switch_min_gain_pct: 20
  switch_min_gain_ms: 15
  holddown: 30m
ports: [7844, 443]             # tried in order per endpoint; 443 = nginx fallback path
ingress:
  - hostname: shop.example.com
    service: http://127.0.0.1:8080
  - hostname: "*.example.com"
    service: https://10.0.0.5:8443
    origin_request:
      tls_server_name: app.internal
      ca_file: /etc/ssl/internal-ca.pem
      no_tls_verify: false
      connect_timeout: 5s
      response_header_timeout: 45s   # below the edge's 50 s so a slow service is attributed here
      keepalive_connections: 16
      http_host_header: ""     # default: pass the visitor Host through
      http2: false             # HTTP/2 to the service (https only)
  - service: http_status:404   # required catch-all: unknown Host never proxied
admin_socket: /run/hcdn-connector/admin.sock   # "" disables it; an absent key keeps the default
metrics_addr: 127.0.0.1:9112   # optional; "" disables; loopback only
server_spki_pins: []           # optional: sha256/<base64> SPKI pins for the edge chain
server_ca_file: ""             # optional: private CA (test setups); default = system roots
allow_local_ports: []          # optional: local ports to publish despite the local port guard
log:
  format: json                 # json | text
  level: info                  # debug | info | warn | error
transport: h2                  # reserved; only h2 is implemented
```

### Ingress rules

Rules match the request `Host`: an exact hostname first, then the longest
wildcard suffix, then the catch-all. `*.example.com` matches any depth
below `example.com` and never `example.com` itself. The catch-all (a rule
without `hostname`) is required, must be last, and must be an
`http_status:<code>` service. An unknown `Host` is never proxied.

A `service` is `http://host:port`, `https://host:port` or
`http_status:<code>` (200..599; answers that status with an empty body).

Durations need a unit (`5s`, `45s`, `30m`); yaml rejects bare integers.
Floors: `connect_timeout` >= 100 ms, `response_header_timeout` >= 1 s,
`holddown` 0 or >= 1 s, `reprobe_interval` >= 1 m. `ports` may only contain
7844 and 443 unless `server_ca_file` marks a private (staging) setup.

An explicit `0` keeps its value: `holddown: 0s` switches without a hold-down,
`switch_min_gain_pct: 0` and `switch_min_gain_ms: 0` drop that threshold,
and `keepalive_connections: 0` disables keep-alive to the service.

### Request handling

- Requests without `hcdn-request-id` are rejected with `400`. Only the edge
  speaks on a session. The control routes `/_hcdn/v1/hello`,
  `/_hcdn/v1/goaway` and `/_hcdn/v1/visible` are exempt and never proxied.
- Hop-by-hop headers and every `hcdn-*` / `x-hcdn-*` request header are
  removed before the service sees the request. `Hcdn-Tunnel-Id` is added.
  `X-Forwarded-For`, `X-Real-IP` and `X-Forwarded-Proto` pass through as
  the edge sent them. The connector never appends its own address.
  `Forwarded` and `X-Forwarded-Host` are removed: the edge does not set
  them, so a value there comes from the visitor.
- `hcdn-*` headers are removed from the service response.
  `hcdn-connector-rt: <ms>` (time to first byte from the service) is added;
  the edge records and removes it.
- Bodies stream in both directions. Nothing is buffered to disk.
- Every dial to a service (HTTP and WebSocket) goes through the local port
  guard (`pkg/localguard`): a sensitive port (`localguard.BlockedPorts`) on
  this machine is refused after DNS and answers `service_unreachable`, with
  a warning in the log. Loopback, the unspecified address, this machine's
  interface addresses and their IPv4-mapped forms count as this machine.
  The guard fails closed: when the interface addresses cannot be read
  (on Linux that needs an `AF_NETLINK` socket, which a sandbox may deny),
  any host may be this machine, so a sensitive port is refused on every
  host until they can be read. `run` logs a warning at start when that
  happens, and `check` shows the reason on each refused rule.
  `allow_local_ports: [9200]` in `config.yml` (each 1..65535) opts a port
  out for `run` and `check`. Library users set `Options.AllowLocalPorts`.
  Set it only to publish such a port on purpose.
- Errors are answered with `502`, an empty body and `hcdn-error`. The edge
  replaces that response with the branded 530 page and shows the value in
  `X-Hcdn-Tunnel-Error`:

  | `hcdn-error` | Cause |
  |--------------|-------|
  | `service_unreachable` | dial or TLS failure to the service |
  | `service_timeout` | no response headers within `response_header_timeout` |
  | `bad_gateway` | malformed response or connection reset |
  | `overloaded` | per-session inflight cap (`hcdn-max-inflight` from the edge) exceeded. |

- WebSocket: the edge opens a `CONNECT` stream with
  `hcdn-upgrade: websocket` and `hcdn-path`. The connector performs the
  HTTP/1.1 Upgrade against the service. On `101` it answers `200` with
  `hcdn-ws-accept` and `hcdn-ws-protocol` and pipes bytes both ways. A `200`
  without `hcdn-ws-accept` is a normal response, not an upgrade. A `101`
  without `Sec-WebSocket-Accept` or `Upgrade: websocket` gets `bad_gateway`.
  Interim `1xx` responses (for example `103`) are skipped. Any
  other status is returned as a normal response. `Sec-WebSocket-Extensions`
  is removed from the request to the service: the edge has no
  `hcdn-ws-extensions` yet, so a negotiated extension (for example
  `permessage-deflate`) would never reach the visitor. Adding
  `hcdn-ws-extensions` on both sides is a future contract change.
- Limits: 256 concurrent streams per session, 64 KiB HTTP/2 frames,
  64 KiB request and response headers.

### Goaway reasons

| Reason | Connector |
|--------|-----------|
| `drain` | Open a replacement session at once (another address of the same PoP preferred); on the same address 7844 is retried through the restart gap for up to 5 s before 443 is considered. The drained session finishes its in-flight streams in the background and shows as `draining` in `status`. A drain within 5 s of the dial redials after the backoff instead. |
| `cap_exceeded` | Pause that PoP for `hcdn-retry-after` (default 60 s) |
| `auth_unavailable` | Exclude that address for `hcdn-retry-after` (default 15 s); after all addresses, pause the PoP |
| `reselect` | Refresh the PoP list and re-run selection |
| `disabled` | Drain sessions (in-flight requests finish, 15 s max), pause every PoP for `hcdn-retry-after` (default 300 s), then re-run selection. No exit. |
| `revoked` | Log at error, stop, exit 78 |
| `unknown_serial` | Ignored when the session used an older certificate than the current one (the session redials). Otherwise reload credentials once; exit 78 when unchanged. A library memory store with a `RefreshFunc` refreshes in the background (30 s limit) and exits 78 when the refresh fails. |
| `protocol_error` | Back off (1 s to 60 s, full jitter) |
| `owner_required` | Log at error, stop, exit 77 (quick tunnels without a valid owner ticket in owner mode `require`) |

`hcdn-retry-after` is bounded: at most 15 min for `cap_exceeded` and
`auth_unavailable`, at most 1 h otherwise. A missing, negative, non-numeric
or overflowing value falls back to the default for that reason; the
connector logs the value it applies.

## Credentials

`credentials.json` (mode 0600):

```json
{
  "tunnel_id": "3f9c2a7e-...",
  "certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "private_key_pem": "-----BEGIN EC PRIVATE KEY-----...",
  "bootstrap_endpoints": ["fra.tunnel.hostinger.io", "phx.tunnel.hostinger.io", "mum.tunnel.hostinger.io"],
  "not_after": "2031-09-24T00:00:00Z"
}
```

The connector reloads the file on `SIGHUP` (`systemctl reload
hcdn-connector`) and on an mtime change. New sessions use the new
certificate; existing sessions rotate one at a time. With two or more
sessions per PoP, a rotation never drains the last ready session. If a re-dialed session is not ready
within 60 s, the rotation stops, and the other sessions keep the old
certificate until the edge closes them. A reload refuses a
certificate that is expired or not yet valid and keeps the current one. It
warns daily when the certificate expires in fewer than 30 days.

## systemd

`packaging/hcdn-connector.service` runs as the dedicated user
`hcdn-connector` with `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome`, `PrivateTmp`, an empty `CapabilityBoundingSet`,
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`, `Restart=on-failure`
and `RestartPreventExitStatus=78`. `AF_NETLINK` lets the local port guard
read the interface addresses; a unit that drops it makes the guard refuse
sensitive ports on every host. Ten failed starts within 60 s stop the
unit (`StartLimitBurst`); `systemctl reset-failed hcdn-connector` clears
that. The only listeners are the admin unix
socket (mode 0660, under `/run/hcdn-connector/`) and the optional metrics
endpoint on loopback. `ProtectSystem=strict` makes `/run` read-only except
the runtime directory, so `admin_socket` must stay under
`/run/hcdn-connector/`. A second `run` refuses to start while the admin
socket answers.

## Metrics

`GET http://127.0.0.1:9112/metrics`:

| Metric | Labels |
|--------|--------|
| `hcdn_connector_sessions` | `pop`, `state` = `connecting`, `handshaking`, `ready`, `draining`, `paused` |
| `hcdn_connector_requests_total` | `result` = `ok`, `service_unreachable`, `service_timeout`, `bad_gateway`, `overloaded`, `rejected`, `http_status`, `ws`, `canceled` (edge reset the stream) |
| `hcdn_connector_service_rt_seconds` | histogram, time to first byte from the service |
| `hcdn_connector_cert_days_left` | gauge |
| `hcdn_connector_reconnects_total` | `reason` = `goaway_<reason>`, `dial_error`, `hello_timeout`, `bad_hello`, `closed_before_hello`, `closed`, `closed_local` (the connector closed or drained the session) |
| `hcdn_connector_build_info` | `version`, `commit` |

Logs are `log/slog` JSON (or text) on stderr. The connector never logs
header values except the request id.
