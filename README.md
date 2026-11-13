# API Everything — core gateway

One key for every connector. Weighted credits. **Zero data retention.**

This is the unified entry point that makes the hosted tier possible: a single
16-digit key works across Instagram, LinkedIn and TikTok, and a single credit
counter follows it. It is optional — every connector remains fully functional
without the gateway, with exactly the same features. The gateway is
infrastructure, not a capability gate.

## What is stored, exactly

```
{
  "version": 1,
  "keys": {
    "<sha256 of the key>": {
      "credits": 5000,
      "createdAt": "...",
      "expiresAt": "...",
      "revoked": false
    }
  },
  "vouchers": {
    "<sha256 of the code>": { "credits": 5000, "expiresAt": "...", "redeemed": false }
  }
}
```

That's the whole database. No IP address, no email, no wallet, no name, no
query string, no request history, no User-Agent, no timestamped log of what a
key looked up. Raw keys are shown **once** at creation and never stored or
logged. Rate-limit buckets live in memory only and vanish on restart.

Logs contain only: method, a **route template** (`/v1/instagram/:id/posts`),
status, duration and credit accounting. Query strings are stripped.

> Be precise about the claim: this is **"no identity collected"**, not
> "cryptographically unlinkable". A payment system that issues a voucher can
> still correlate its own records. What the gateway guarantees is that it has
> no join key to give anyone.

## Quick start

```bash
npm install
cp .env.example .env
# set CORE_ADMIN_TOKEN (see the example file)
node --env-file=.env server.js
```

In three terminals, start the connectors on ports 3000 / 3001 / 3002 (or set
`CORE_UPSTREAMS` accordingly). Then:

```bash
# issue a key (admin)
curl -X POST http://localhost:9000/v1/keys \
  -H "X-Admin-Token: $CORE_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"credits":5000,"expiresInDays":365}'
# -> { "key": "1234567890123456", "keyHash": "...", "credits": 5000, ... }

# use it on any connector
curl http://localhost:9000/v1/instagram/kametolol/posts?limit=2 \
  -H "X-API-Key: 1234567890123456"
# -> 200, with X-Credits-Cost: 3 and X-Credits-Remaining: 4997

# check what's left
curl http://localhost:9000/v1/usage -H "X-API-Key: 1234567890123456"
```

Docker:

```bash
docker compose up -d
```

## Credits are weighted

A flat « 1 request = 1 credit » would let a user arbitrage the margin by only
calling the most expensive endpoints. Cost follows upstream work:

| Route | Cost |
| --- | --- |
| Instagram / TikTok posts | 3 |
| LinkedIn aggregate signals | 2 |
| LinkedIn people (blocked by default) | 5 |
| Profile / job / company metadata | 1 |

Override with `CORE_COSTS` (a JSON array of `[regex, cost]` pairs).

**A request is charged only after the upstream returns 2xx with data.** A 429,
a 5xx, a 404, an empty body or an error envelope costs nothing —
`X-Charged: false` tells the client. This is deliberate: you should not pay
for our failures.

Rate limiting is per key and per minute (`CORE_RATE_PER_MIN`, default 60),
with `Retry-After: 60` on 429. Buckets are in memory, never persisted.

## Keys and vouchers

| Route | Auth | Purpose |
| --- | --- | --- |
| `POST /v1/keys` | admin | Create a key; raw key returned once |
| `GET /v1/keys` | admin | List hashes + counters (no raw keys) |
| `DELETE /v1/keys/:hash` | admin | Revoke |
| `POST /v1/keys/:hash/topup` | admin | Add credits |
| `POST /v1/vouchers` | admin | Issue a one-time credit code |
| `POST /v1/redeem` | public | Redeem a voucher into a key |
| `GET /v1/usage` | key | Credits, expiry, rate remaining |
| `GET /health`, `/`, `/openapi.yaml` | public | Ops |

Admin routes are **fail-closed**: without `CORE_ADMIN_TOKEN` they return
`503 ADMIN_DISABLED`. Token comparison is timing-safe. Keys are accepted only
via the `X-API-Key` header, never as a query parameter (query strings leak
into reverse-proxy logs).

### Vouchers decouple payment from keys

A voucher is a one-time bearer code. The payment system issues one; the gateway
stores only its hash. There is no wallet address, customer id or join key in
the gateway's database. Redemption accepts three modes:

```bash
# 1. Gateway generates the key, returns it once
curl -X POST .../v1/redeem -d '{"code":"..."}'

# 2. Client provides its own key (hashed server-side, never stored raw)
curl -X POST .../v1/redeem -d '{"code":"...","key":"1234567890123456"}'

# 3. Client generates the key locally and sends ONLY its SHA-256
#    (requires CORE_ALLOW_CLIENT_HASH=1) — the gateway never sees the raw key
curl -X POST .../v1/redeem -d '{"code":"...","keyHash":"<64 hex>"}'
```

Mode 3 is the strongest privacy option. Keys must come from a CSPRNG: 16
digits is ~53 bits, which is fine behind rate limiting but not against an
offline brute force, so keep `CORE_RATE_PER_MIN` enabled.

## Data policy routes

`CORE_ALLOW_PEOPLE=0` (default) blocks `/v1/linkedin/people/*` with
`403 ROUTE_BLOCKED`. The hosted tier serves jobs, companies and aggregate
counts; people profiles stay self-host only. The gateway enforces that rule
even if the underlying connector was configured otherwise.

## Routing

`CORE_UPSTREAMS` maps a service name to a base URL:

```json
{
  "instagram": "http://127.0.0.1:3000",
  "linkedin": "http://127.0.0.1:3002",
  "tiktok": "http://127.0.0.1:3001"
}
```

`/v1/<service>/<path>` is forwarded verbatim (including the query string) to
`<base>/v1/<service>/<path>`. Response status, content type and body are
relayed, plus four accounting headers. Hop-by-hop and credential headers are
stripped before forwarding so the connector never sees the gateway key.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` / `HOST` | `9000` / `0.0.0.0` | HTTP bind |
| `CORE_ADMIN_TOKEN` | — | Required for management routes |
| `CORE_UPSTREAMS` | three localhost URLs | Service → base URL map |
| `CORE_TIMEOUT_MS` | `20000` | Upstream timeout |
| `CORE_DEFAULT_CREDITS` | `5000` | New key/voucher credits |
| `CORE_COSTS` | built-in table | `[regex, cost]` JSON pairs |
| `CORE_RATE_PER_MIN` | `60` | Per-key limit |
| `CORE_ALLOW_PEOPLE` | `0` | Allow personal-data routes |
| `CORE_ALLOW_CLIENT_HASH` | `0` | Allow client-side key hashes |
| `CORE_STORE` | `file` | `file` or `memory` |
| `CORE_DATA_DIR` / `CORE_DATA_FILE` | `./.data/keys.json` | Store location |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` / `silent` |

`Ctrl+R` reloads configuration in place (and rebinds the port if it changed);
`Ctrl+C` stops cleanly. Hotkeys are disabled when stdin is not a TTY.

## Tests

```bash
npm test       # 22 offline unit tests
npm run smoke  # end-to-end with a mock connector, 20 checks
```

Unit tests cover key generation and hashing, the credit table, the « charge
only on success » rule, atomic debits, rate limiting, voucher issue / redeem /
replay prevention, client-hash mode, the people gate, admin fail-closed
behaviour and log redaction. The smoke test starts the gateway with a mock
connector and verifies the full key → proxy → debit → voucher flow, including
that no raw key or query string ever reaches disk or logs. Neither command
makes a network call to a real service.

## Structure

```
server.js              HTTP gateway, banner, Ctrl+R, hotkeys
core/config.js         .env loader with hot-reload
core/keys.js           16-digit CSPRNG keys, SHA-256 hashing, timing-safe compare
core/store.js          atomic file / memory store, hash-only records
core/ledger.js         weighted costs, billable responses, expiry
core/ratelimit.js      in-memory sliding window (never persisted)
core/registry.js       key & voucher lifecycle
core/proxy.js          upstream resolution and forwarding
core/errors.js         typed errors and hints
core/logger.js         privacy-first logging (route templates only)
openapi.yaml           API schema
```

## Honest status

This is the **implementation** of the key/quota layer, not a launched hosted
service. No payment provider is integrated, no pricing is defined, and no
public instance is running. The voucher flow is the seam where a payment system
would plug in — deliberately kept separate so the gateway never handles money
or identity.

Self-hosting remains free and complete. The gateway is a convenience layer for
people who would rather run one endpoint than three, and the foundation for a
future hosted tier that funds the project without selling anyone's data.

## License

MIT with an attribution notice — see the organisation's `LICENSE.md`. Any
project reusing this code elsewhere must visibly credit **API Everything**.
