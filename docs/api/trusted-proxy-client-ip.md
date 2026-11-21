# Trusted client-IP handling behind proxies

The API resolves a caller IP for two purposes:

- HTTP rate-limit bucket keys (`middleware/rate_limit.rs`),
- WebSocket per-IP connection limits (`routes/ws/mod.rs`), and
- admin audit attribution when no API key / bearer token is present
  (`admin_audit.rs`, used by `/api/v1/admin/*`).

Both go through the same resolver in `crates/api/src/client_ip.rs`. The
resolver is **secure by default**: forwarding headers are ignored unless the
TCP peer is explicitly listed in `TRUSTED_PROXY_CIDRS`.

## Why headers are not trusted by default

`X-Forwarded-For` and `X-Real-IP` are ordinary request headers. Any client can
send them. Trusting them unconditionally lets a caller:

- rotate a fake IP per request to bypass per-IP rate limits, and
- frame an arbitrary address in audit logs.

A forwarding header is only meaningful once a proxy **we operate** has appended
the address it observed.

## Configuration

| Variable | Type | Default | Description |
|---|---|---|---|
| `TRUSTED_PROXY_CIDRS` | comma-separated IPs/CIDRs | *(empty)* | Peers allowed to supply forwarding headers. IPv4 and IPv6 are supported. |

```bash
# Single local proxy (Cloudflare Tunnel / nginx / Envoy on the same host)
TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128

# Private network of load balancers
TRUSTED_PROXY_CIDRS=10.0.0.0/8,192.168.0.0/16
```

Notes:

- A bare address (`10.0.0.5`) means a host route (`/32` or `/128`).
- Blank entries are ignored.
- An invalid address, prefix, or prefix length **rejects the whole list**. The
  API logs a warning and falls back to trusting nobody rather than partially
  trusting a typo.
- When the list is empty or unset, the API logs at startup that forwarded
  headers will be ignored.

## Resolution algorithm

1. Read the TCP peer address from axum's `ConnectInfo` (the server is built
   with `into_make_service_with_connect_info`).
2. If the peer is **not** in `TRUSTED_PROXY_CIDRS`, return the peer. No headers
   are read.
3. If `X-Forwarded-For` is present, walk it **right to left**, skipping hops
   that are themselves trusted proxies. Return the first untrusted hop.
4. Otherwise, if `X-Real-IP` is present and parses, return it.
5. Otherwise return the peer.

Walking from the right defeats prefix spoofing:

```text
X-Forwarded-For: 1.2.3.4, 203.0.113.5
                 ^ fake    ^ appended by our trusted proxy
peer:            10.0.0.254 (trusted)          -> resolved client: 203.0.113.5
```

IPv4-mapped IPv6 peers (`::ffff:127.0.0.1`) are normalized before matching, so
an IPv4 allowlist entry works regardless of socket representation.

Without `ConnectInfo` (for example an embedded router or a unit test), the
resolver treats the peer as loopback. Loopback is not trusted unless listed, so
headers are still ignored.

## Deploying

### Cloudflare Tunnel (Wave 0 staging)

`cloudflared` connects to the API over loopback, so trust loopback:

```bash
TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128
```

### PaaS / cloud load balancer

Use the health-check/load-balancer subnet, not `0.0.0.0/0`. For example, an
in-VPC proxy that connects from `10.20.0.0/16`:

```bash
TRUSTED_PROXY_CIDRS=10.20.0.0/16
```

Do **not** set `0.0.0.0/0` or `::/0`. That trusts every direct caller and
restores the spoofing behavior this feature removes.

### Multiple proxy layers

List every proxy that may appear as the TCP peer **or** inside
`X-Forwarded-For`. Each entry must be a proxy you control: entries are skipped
from the right, so a trusted range that clients can join weakens the boundary.

## Operational impact of an empty allowlist

If `TRUSTED_PROXY_CIDRS` is unset behind a reverse proxy, every request resolves
to the proxy's address. Rate limits then apply to the proxy as a whole rather
than per client, and admin audit IPs will show the proxy. The API is still
secure; it is just coarse. Set the allowlist deliberately.

## Tests

- `crates/api/src/client_ip.rs`: CIDR parsing, right-to-left resolution,
  spoofed leftmost values, `X-Real-IP` gating, malformed headers, IPv4-mapped
  peers, empty allowlist.
- `crates/api/src/middleware/rate_limit.rs`: rate-limit identity uses the TCP
  peer from `ConnectInfo`, and ignores headers for untrusted peers.
- `crates/api/tests/rate_limit_integration.rs`: end-to-end boundary tests for
  trusted and untrusted peers.
- `crates/api/src/admin_audit.rs`: audit attribution uses the resolved IP and
  does not re-read forwarding headers.
