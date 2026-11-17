# API Everything — core gateway

One account, rotatable API keys, weighted credits. **Zero data retention.**
**PayAsYouGo — no monthly subscription, no recurring billing, no monthly reset.**

This is the unified entry point that makes the hosted tier possible: one credit
counter follows an **account**, and every connector is reachable through the
same gateway. It is optional — every connector remains fully functional without
it, with exactly the same features. The gateway is infrastructure, not a
capability gate.

## Two credentials, deliberately separate

| | Unlock code | API key |
| --- | --- | --- |
| Format | 16 digits | `ae_` + 48 hex |
| Header | `X-Unlock-Code` | `X-API-Key` |
| Purpose | Opens the account (create / reset / revoke keys, read quota) | Calls the APIs |
| Shown | Once, at signup | Once, at creation or reset |
| Rotation | Never — it *is* the account | Anytime, independently |
| If leaked | The account is compromised | Reset that one key; credits and account stay put |

**The 16-digit code is never accepted as `X-API-Key`.** Sending it there returns
`401 UNLOCK_CODE_NOT_API_KEY` with a hint, instead of a generic 401. This keeps
a short, human-friendly, hard-to-rotate secret out of client code, curl
examples, CI secrets and screenshots. The long `ae_` prefix makes API keys
greppable in logs and impossible to confuse with the code.

Credits, expiry and the rate-limit bucket belong to the **account**, not to an
individual key: several keys can share one balance, and rotating a key never
costs a credit.

## What is stored, exactly

```json
{
  "version": 2,
  "accounts": {
    "<sha256 of the unlock code>": {
      "credits": 5000,
      "createdAt": "...",
      "expiresAt": null,
      "revoked": false
    }
  },
  "apiKeys": {
    "<sha256 of the API key>": {
      "accountHash": "...",
      "name": "laptop",
      "createdAt": "...",
      "lastUsedAt": null,
      "revoked": false
    }
  },
  "vouchers": {
    "<sha256 of the code>": { "credits": 5000, "expiresAt": "...", "redeemed": false }
  }
}
```

That's the whole database. No IP address, no email, no wallet, no name, no
query string, no request history, no User-Agent, no timestamped log of what an
account looked up. Raw unlock codes and raw API keys are shown **once** at
creation and never stored or logged. Rate-limit buckets live in memory only and
vanish on restart.

Logs contain only: method, a **route template** (`/v1/instagram/:id/posts`),
status, duration and credit accounting. Query strings are stripped.

> Be precise about the claim: this is **"no identity collected"**, not
> "cryptographically unlinkable". A payment system that issues a voucher can
> still correlate its own records. What the gateway guarantees is that it has
> no join key to give anyone.

### Upgrading from v1

A v1 `keys.json` (16-digit keys used directly as API keys) is migrated **in
place on read**: those codes become unlock codes, credits are preserved, and no
API key is minted automatically. Unlock the account with the same 16 digits and
create a key. Nothing is lost, nothing is rewritten until the next write.

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
# 1. Create an account. Save the 16-digit UNLOCK CODE — it is not an API key.
curl -X POST http://localhost:9000/v1/signup
# -> { "unlockCode": "1234567890123456", "credits": 50, "expiresAt": null,
#      "model": "pay_as_you_go",
#      "notice": "Save this 16-digit unlock code. It opens your account; it is NOT an API key." }

# 2. Create a rotatable API key with the unlock code.
curl -X POST http://localhost:9000/v1/keys \
  -H "X-Unlock-Code: 1234567890123456" \
  -H "Content-Type: application/json" \
  -d '{"name":"laptop"}'
# -> { "apiKey": "ae_…", "keyHash": "...", "name": "laptop", ... }

# 3. Call every connector with the API key.
curl "http://localhost:9000/v1/instagram/kametolol/posts?limit=2" \
  -H "X-API-Key: ae_…"
# -> 200, with X-Credits-Cost: 3 and X-Credits-Remaining: 47

# 4. Manage keys without ever exposing the unlock code to your API clients.
curl http://localhost:9000/v1/keys -H "X-Unlock-Code: 1234567890123456"
curl -X POST http://localhost:9000/v1/keys/reset -H "X-Unlock-Code: 1234567890123456"
curl -X DELETE http://localhost:9000/v1/keys/<keyId> -H "X-Unlock-Code: 1234567890123456"
curl -X POST http://localhost:9000/v1/keys/<keyId>/reset -H "X-Unlock-Code: 1234567890123456"
```

Trying the unlock code as `X-API-Key` is explicitly rejected:

```bash
curl "http://localhost:9000/v1/instagram/x" -H "X-API-Key: 1234567890123456"
# -> 401 { "error": { "code": "UNLOCK_CODE_NOT_API_KEY",
#      "hint": "Unlock your account with the 16-digit code, then create an API key…" } }
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

Rate limiting is **per account** and per minute (`CORE_RATE_PER_MIN`, default
60), with `Retry-After: 60` on 429. All API keys of one account share the
bucket. Buckets are in memory, never persisted.

## PayAsYouGo, explicitly

There is **no subscription**. An account created through `/v1/signup` has no
expiry, credits never reset on a calendar date, and nothing is charged unless
you actually make a successful request. You add quota only when you want to, by
redeeming a prepaid voucher — the same model as a prepaid card, not a plan.

```bash
curl -X POST http://localhost:9000/v1/redeem \
  -H "Content-Type: application/json" \
  -d '{"code":"...","unlockCode":"1234567890123456"}'
```

Signup abuse protection hashes the client address with a **random per-process
salt**, keeps it in memory for one hour and never writes it anywhere. After a
restart there is nothing left to correlate. A new account gets
`CORE_STARTER_CREDITS` (default 50) and `CORE_SIGNUP_PER_HOUR` (default 5)
limits how many accounts one network can create per hour.

## Routes

| Route | Auth | Purpose |
| --- | --- | --- |
| `POST /v1/signup` | public | Create an account; **unlock code shown once** |
| `POST /v1/unlock` | unlock code | Open an existing account, show key count |
| `GET /v1/keys` | unlock code | List API keys (sanitized, no raw keys) |
| `POST /v1/keys` | unlock code | Create an API key; raw key returned once |
| `POST /v1/keys/reset` | unlock code | Revoke all keys, issue a fresh one |
| `POST /v1/keys/:keyId/reset` | unlock code | Rotate one key |
| `DELETE /v1/keys/:keyId` | unlock code | Revoke one key |
| `GET /v1/status` | public | Health of every connector |
| `GET /v1/usage` | API key **or** unlock code | Credits, expiry, rate remaining, key count |
| `POST /v1/redeem` | public | Redeem a prepaid voucher |
| `POST /v1/vouchers` | admin | Issue a one-time credit code |
| `GET/POST /v1/admin/accounts` | admin | List / create accounts with a custom balance |
| `DELETE /v1/admin/accounts/:hash` | admin | Revoke an account and all its keys |
| `POST /v1/admin/accounts/:hash/topup` | admin | Add credits |
| `GET /health`, `/`, `/openapi.yaml` | public | Ops |

Admin routes are **fail-closed**: without `CORE_ADMIN_TOKEN` they return
`503 ADMIN_DISABLED`. Token comparison is timing-safe. Both credentials are
accepted only via headers, never as query parameters (query strings leak into
reverse-proxy logs). `X-Unlock-Code`, `X-API-Key` and `X-Admin-Token` are
stripped before a request is forwarded, so no connector ever sees them.
`CORE_MAX_API_KEYS` (default 20) caps active keys per account.

### Vouchers decouple payment from accounts

A voucher is a one-time bearer code. The payment system issues one; the gateway
stores only its hash. There is no wallet address, customer id or join key in
the gateway's database. Redemption accepts four modes:

```bash
# 1. Address the account with its unlock code
curl -X POST .../v1/redeem -d '{"code":"...","unlockCode":"1234567890123456"}'

# 2. Or with an existing API key
curl -X POST .../v1/redeem -d '{"code":"...","apiKey":"ae_…"}'

# 3. Or only a client-generated account hash (requires CORE_ALLOW_CLIENT_HASH=1)
#    — the gateway never sees the raw unlock code
curl -X POST .../v1/redeem -d '{"code":"...","accountHash":"<64 hex>"}'

# 4. Or nothing: a fresh account + unlock code is created and returned once
curl -X POST .../v1/redeem -d '{"code":"..."}'
```

`key` is still accepted as a deprecated alias for the 16-digit unlock code, so
older redemption scripts keep working.

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
stripped before forwarding.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` / `HOST` | `9000` / `0.0.0.0` | HTTP bind |
| `CORE_ADMIN_TOKEN` | — | Required for management routes |
| `CORE_UPSTREAMS` | three localhost URLs | Service → base URL map |
| `CORE_TIMEOUT_MS` | `20000` | Upstream timeout |
| `CORE_DEFAULT_CREDITS` | `5000` | Admin-issued account/voucher credits |
| `CORE_STARTER_CREDITS` | `50` | Free starter balance on `/v1/signup` |
| `CORE_SIGNUP_PER_HOUR` | `5` | Signup limit per network (transient) |
| `CORE_MAX_API_KEYS` | `20` | Max active API keys per account |
| `CORE_COSTS` | built-in table | `[regex, cost]` JSON pairs |
| `CORE_RATE_PER_MIN` | `60` | Per-account limit |
| `CORE_ALLOW_PEOPLE` | `0` | Allow personal-data routes |
| `CORE_ALLOW_CLIENT_HASH` | `0` | Allow client-side account hashes |
| `CORE_STORE` | `file` | `file` or `memory` |
| `CORE_DATA_DIR` / `CORE_DATA_FILE` | `./.data/keys.json` | Store location |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` / `silent` |

`Ctrl+R` reloads configuration in place (and rebinds the port if it changed);
`Ctrl+C` stops cleanly. Hotkeys are disabled when stdin is not a TTY.

## Tests

```bash
npm test       # 34 offline unit tests
npm run smoke  # end-to-end with a mock connector, 38 checks
```

Unit tests cover the two credential formats and their strict separation, the
credit table, the « charge only on success » rule, atomic debits, rate limiting,
public signup and its salted abuse limiter, account/API-key lifecycle
(create, list sanitization, rotate, revoke, reset-all, ownership checks, key
cap), voucher issue / redeem / replay prevention, client-hash mode, the people
gate, admin fail-closed behaviour and log redaction. The smoke test starts the
gateway with a mock connector and verifies the full
signup → unlock → API key → proxy/debit → rotation → voucher flow, including
that the unlock code is **rejected** as `X-API-Key`, and that no raw
credential, internal URL or query string ever reaches disk or logs. Neither
command makes a network call to a real service.

## Structure

```
server.js              HTTP gateway, banner, Ctrl+R, hotkeys
core/config.js         .env loader with hot-reload
core/keys.js           unlock codes, API keys, SHA-256 hashing, timing-safe compare
core/store.js          atomic file / memory store, hash-only records, v1 migration
core/ledger.js         weighted costs, billable responses, expiry
core/ratelimit.js      in-memory sliding window (never persisted)
core/registry.js       account, API key & voucher lifecycle
core/signup.js         identity-free account creation + transient abuse limiter
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
