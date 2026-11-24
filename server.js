"use strict";

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");
const { config } = require("./core/config");

config.load();

const { GatewayError } = require("./core/errors");
const { createStore } = require("./core/store");
const { RateLimiter } = require("./core/ratelimit");
const { costFor, billable, isActive } = require("./core/ledger");
const {
  hashKey, assertApiKeyFormat, assertUnlockCodeFormat, timingSafeEqual,
} = require("./core/keys");
const registry = require("./core/registry");
const { upstreams, resolveUpstream, forwardHeaders, forward } = require("./core/proxy");
const { SignupLimiter, signup } = require("./core/signup");
const { connectorStatus, resetStatusCache } = require("./core/status");
const { ResponseCache } = require("./core/cache");
const { PaymentBridge } = require("./core/payments");
const { buildUnifiedOpenApi, resetOpenApiCache } = require("./core/openapi-merge");
const logger = require("./core/logger");
const { log } = logger;

const pkg = require("./package.json");
const PORT = () => Number(process.env.PORT ?? 9000);
const HOST = () => process.env.HOST ?? "0.0.0.0";
const ADMIN = () => process.env.CORE_ADMIN_TOKEN?.trim() || null;
const TIMEOUT = () => Math.max(1000, Number(process.env.CORE_TIMEOUT_MS ?? 20000));
const ALLOW_PEOPLE = () => process.env.CORE_ALLOW_PEOPLE === "1";
const MAX_BODY = 64 * 1024;
const CORS_HEADERS = "Content-Type, X-API-Key, X-Unlock-Code, X-Admin-Token, Cache-Control";
const EXPOSE_HEADERS = "X-Credits-Cost, X-Credits-Remaining, X-RateLimit-Remaining, X-Charged, X-Cache";

const CONFIG_KEYS = [
  "PORT", "HOST", "CORE_ADMIN_TOKEN", "CORE_UPSTREAMS",
  "CORE_INSTAGRAM_URL", "CORE_YOUTUBE_URL", "CORE_LINKEDIN_URL", "CORE_TIKTOK_URL",
  "CORE_COSTS", "CORE_RATE_PER_MIN", "CORE_TIMEOUT_MS",
  "CORE_CACHE_ENABLED", "CORE_CACHE_TTL_MS", "CORE_CACHE_MAX_ENTRIES",
  "CORE_PAYMENT_SANDBOX", "CORE_CREDIT_PACKS",
  "CORE_BTCPAY_URL", "CORE_BTCPAY_STORE_ID", "CORE_BTCPAY_API_KEY", "CORE_WEBHOOK_SECRET",
  "CORE_ALLOW_PEOPLE", "CORE_ALLOW_CLIENT_HASH", "CORE_DEFAULT_CREDITS",
  "CORE_STARTER_CREDITS", "CORE_SIGNUP_PER_HOUR", "CORE_MAX_API_KEYS",
  "CORE_STORE", "CORE_DATA_DIR", "CORE_DATA_FILE",
  "LOG_LEVEL", "NO_COLOR", "FORCE_COLOR",
];

let store = createStore();
let limiter = new RateLimiter({ perMinute: Number(process.env.CORE_RATE_PER_MIN ?? 60) });
let signupLimiter = new SignupLimiter(Number(process.env.CORE_SIGNUP_PER_HOUR ?? 5));
const cache = new ResponseCache();
const payments = new PaymentBridge();
let bound = { port: PORT(), host: HOST() };
let reloading = false;
let stopping = false;

function send(res, status, payload, extra = {}) {
  if (status === 204) {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": CORS_HEADERS,
      "Access-Control-Expose-Headers": EXPOSE_HEADERS,
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    });
    return res.end();
  }
  const body = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2) + "\n";
  res.writeHead(status, {
    "Content-Type": typeof payload === "string" ? "text/yaml; charset=utf-8" : "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": CORS_HEADERS,
    "Access-Control-Expose-Headers": EXPOSE_HEADERS,
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    ...extra,
  });
  res.end(body);
}

function fail(res, err) {
  if (err instanceof GatewayError) {
    const headers = err.code === "RATE_LIMITED" ? { "Retry-After": "60" } : {};
    return send(res, err.status, {
      error: { code: err.code, message: err.message, hint: err.hint, details: err.details },
    }, headers);
  }
  log.error(`unexpected error: ${err.message}`);
  return send(res, 500, { error: { code: "INTERNAL_ERROR", message: "Internal gateway error." } });
}

async function readRawBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buf.length;
    if (size > MAX_BODY) throw new GatewayError("BAD_REQUEST", "Request body too large.", 413);
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}

async function readBody(req) {
  const raw = await readRawBody(req);
  if (!raw.length) return {};
  const text = raw.toString("utf8");
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    throw new GatewayError("BAD_REQUEST", "Body must be valid JSON.", 400);
  }
}

function requireAdmin(req) {
  const token = ADMIN();
  if (!token) throw new GatewayError("ADMIN_DISABLED", "Management routes are disabled.", 503);
  const provided = req.headers["x-admin-token"] ?? "";
  if (!timingSafeEqual(provided, token)) {
    throw new GatewayError("ADMIN_REQUIRED", "Invalid admin token.", 401);
  }
}

/**
 * Management auth: the 16-digit unlock code. This header is NEVER forwarded
 * to a connector and is never accepted as X-API-Key.
 */
async function requireUnlock(req, body = {}) {
  const raw = req.headers["x-unlock-code"] ?? body.unlockCode ?? "";
  assertUnlockCodeFormat(raw);
  const accountHash = hashKey(raw);
  const state = await store.read();
  const account = state.accounts[accountHash];
  if (!account) throw new GatewayError("INVALID_UNLOCK_CODE", "Unknown unlock code.", 401);
  if (account.revoked) throw new GatewayError("ACCOUNT_REVOKED", "This account is revoked.", 403);
  return { accountHash, account, unlockCode: raw };
}

/**
 * API auth: an ae_… API key only. A 16-digit unlock code is rejected with an
 * explicit UNLOCK_CODE_NOT_API_KEY error instead of a generic 401.
 */
async function authenticate(req, cost) {
  const raw = req.headers["x-api-key"] ?? "";
  assertApiKeyFormat(raw);
  const keyHash = hashKey(raw);
  const state = await store.read();
  const meta = state.apiKeys[keyHash];
  if (!meta) throw new GatewayError("INVALID_KEY", "Unknown API key.", 401);
  if (meta.revoked) throw new GatewayError("KEY_REVOKED", "API key revoked.", 403);
  const accountHash = meta.accountHash;
  const account = state.accounts[accountHash];
  if (!account) throw new GatewayError("INVALID_KEY", "Unknown API key.", 401);
  if (account.revoked) throw new GatewayError("ACCOUNT_REVOKED", "This account is revoked.", 403);
  if (account.expiresAt && Date.parse(account.expiresAt) <= Date.now()) {
    throw new GatewayError("KEY_EXPIRED", "Account expired.", 403);
  }
  if (account.credits < cost) throw new GatewayError("NO_CREDITS", "Not enough credits.", 402);
  // Rate limiting is per ACCOUNT, so several API keys share one budget.
  const rate = limiter.check(accountHash);
  if (!rate.allowed) throw new GatewayError("RATE_LIMITED", "Rate limit exceeded.", 429);
  return { accountHash, account, keyHash, meta, rate };
}

/** Usage accepts either credential: an API key or the account unlock code. */
async function resolveAccount(req, cost = 0) {
  if (req.headers["x-api-key"]) return { ...(await authenticate(req, cost)), via: "apiKey" };
  if (req.headers["x-unlock-code"]) {
    const found = await requireUnlock(req);
    const rate = limiter.check(found.accountHash);
    return { ...found, rate, keyHash: null, via: "unlockCode" };
  }
  throw new GatewayError(
    "INVALID_KEY",
    "Provide X-API-Key (or X-Unlock-Code for account management).",
    401
  );
}

async function debit(accountHash, cost, keyHash) {
  const state = await store.write((current) => {
    const account = current.accounts[accountHash];
    if (account && !account.revoked) account.credits = Math.max(0, account.credits - cost);
    const meta = keyHash ? current.apiKeys[keyHash] : null;
    if (meta) meta.lastUsedAt = new Date().toISOString();
    return current;
  });
  return state.accounts[accountHash]?.credits ?? 0;
}

async function touch(keyHash) {
  if (!keyHash) return;
  await store.write((current) => {
    const meta = current.apiKeys[keyHash];
    if (meta) meta.lastUsedAt = new Date().toISOString();
    return current;
  });
}

async function handle(req, res) {
  if (req.method === "OPTIONS") return send(res, 204, {});
  const url = new URL(req.url, `http://${req.headers.host ?? "localhost"}`);
  const pathname = url.pathname.replace(/\/+$/, "") || "/";
  const started = Date.now();
  let cost;
  let remaining;

  try {
    if (pathname === "/") {
      return send(res, 200, {
        name: "API Everything - core gateway",
        version: pkg.version,
        description: "A 16-digit unlock code opens your account; rotatable ae_… API keys call the APIs. Weighted credits, zero data retention.",
        upstreams: Object.keys(upstreams()),
        peopleRoutes: ALLOW_PEOPLE() ? "allowed" : "blocked",
        dataPolicy: "Only hashes, credit counters and timestamps are stored. No raw unlock code or API key is ever written.",
        model: "PayAsYouGo — no subscription, no monthly reset, top up with vouchers",
        credentials: {
          unlockCode: "16 digits · X-Unlock-Code · opens the account · NOT an API key",
          apiKey: "ae_… · X-API-Key · create / reset / revoke from the account",
        },
        endpoints: {
          health: "GET /health",
          status: "GET /v1/status",
          signup: "POST /v1/signup (returns the unlock code ONCE)",
          unlock: "POST /v1/unlock (X-Unlock-Code)",
          keys: "GET|POST /v1/keys, POST /v1/keys/reset, DELETE /v1/keys/:id (X-Unlock-Code)",
          usage: "GET /v1/usage (X-API-Key or X-Unlock-Code)",
          payments: "GET /v1/payments/packs, POST /v1/payments/checkout",
          redeem: "POST /v1/redeem",
          admin: "POST /v1/vouchers, /v1/admin/accounts (X-Admin-Token)",
          proxy: "GET|POST /v1/:service/... (X-API-Key only)",
          schema: "GET /openapi.yaml",
          openapi: "GET /v1/openapi.json",
        },
      });
    }

    if (pathname === "/health") {
      const state = await store.read();
      const accounts = Object.values(state.accounts);
      const apiKeys = Object.values(state.apiKeys);
      return send(res, 200, {
        status: "ok",
        upstreams: Object.keys(upstreams()),
        accounts: accounts.length,
        activeAccounts: accounts.filter((a) => isActive(a)).length,
        apiKeys: apiKeys.length,
        activeApiKeys: apiKeys.filter((k) => !k.revoked).length,
        vouchers: Object.values(state.vouchers).filter((v) => !v.redeemed).length,
        adminEnabled: Boolean(ADMIN()),
        peopleRoutes: ALLOW_PEOPLE() ? "allowed" : "blocked",
        cache: cache.stats(),
      });
    }

    if (pathname === "/openapi.yaml") {
      const file = path.join(__dirname, "openapi.yaml");
      if (!fs.existsSync(file)) return send(res, 404, { error: { code: "NOT_FOUND" } });
      return send(res, 200, fs.readFileSync(file, "utf8"));
    }

    if (pathname === "/v1/openapi.json") {
      if (req.method !== "GET") {
        return send(res, 404, { error: { code: "NOT_FOUND", message: "Unknown route." } });
      }
      return send(res, 200, await buildUnifiedOpenApi());
    }

    // Public, identity-free signup. Returns the UNLOCK CODE, shown once.
    if (pathname === "/v1/signup" && req.method === "POST") {
      const result = await signup(store, signupLimiter, req);
      return send(res, 201, result);
    }

    // Public connector health. No internal URLs are exposed.
    if (pathname === "/v1/status" && req.method === "GET") {
      return send(res, 200, await connectorStatus());
    }

    // Zero-identity PayAsYouGo payment -> voucher bridge.
    if (pathname === "/v1/payments" || pathname.startsWith("/v1/payments/")) {
      if (pathname === "/v1/payments/packs" && req.method === "GET") {
        return send(res, 200, payments.listPacks());
      }
      if (pathname === "/v1/payments/checkout" && req.method === "POST") {
        const body = await readBody(req);
        return send(res, 201, await payments.checkout(body));
      }
      if (pathname === "/v1/payments/webhook" && req.method === "POST") {
        const raw = await readRawBody(req);
        return send(res, 200, await payments.handleWebhook(store, raw, req.headers["btcpay-sig"]));
      }
      const invoiceMatch = /^\/v1\/payments\/invoices\/([^/]+)$/.exec(pathname);
      if (invoiceMatch && req.method === "GET") {
        return send(res, 200, payments.getInvoice(decodeURIComponent(invoiceMatch[1])));
      }
      const settleMatch = /^\/v1\/payments\/sandbox\/([^/]+)\/settle$/.exec(pathname);
      if (settleMatch && req.method === "POST") {
        return send(res, 200, await payments.sandboxSettle(store, decodeURIComponent(settleMatch[1])));
      }
      return send(res, 404, { error: { code: "NOT_FOUND", message: "Unknown payment route." } });
    }

    // Public voucher redemption: no identity, credits an account.
    if (pathname === "/v1/redeem" && req.method === "POST") {
      const body = await readBody(req);
      const result = await registry.redeemVoucher(store, body);
      return send(res, 200, result);
    }

    if (pathname === "/v1/usage" && req.method === "GET") {
      const found = await resolveAccount(req, 0);
      const state = await store.read();
      const activeKeys = Object.values(state.apiKeys)
        .filter((m) => m.accountHash === found.accountHash && !m.revoked).length;
      return send(res, 200, {
        accountHash: found.accountHash,
        credits: found.account.credits,
        expiresAt: found.account.expiresAt,
        revoked: found.account.revoked,
        activeApiKeys: activeKeys,
        rateLimitRemaining: found.rate.remaining,
        authenticatedWith: found.via,
      });
    }

    // Unlock an existing account (explicit "open the account" endpoint).
    if (pathname === "/v1/unlock" && req.method === "POST") {
      const body = await readBody(req);
      const found = await requireUnlock(req, body);
      const state = await store.read();
      const activeKeys = Object.values(state.apiKeys)
        .filter((m) => m.accountHash === found.accountHash && !m.revoked).length;
      return send(res, 200, {
        accountHash: found.accountHash,
        credits: found.account.credits,
        expiresAt: found.account.expiresAt,
        activeApiKeys: activeKeys,
        next: activeKeys ? "Use an existing API key, or create/reset one." : "Create your first API key.",
      });
    }

    // ---- Account-level API key management (X-Unlock-Code) ----
    if (pathname === "/v1/keys" || pathname.startsWith("/v1/keys/")) {
      const body = req.method === "POST" ? await readBody(req) : {};
      const { accountHash } = await requireUnlock(req, body);

      if (pathname === "/v1/keys" && req.method === "GET") {
        return send(res, 200, { keys: await registry.listApiKeys(store, accountHash) });
      }
      if (pathname === "/v1/keys" && req.method === "POST") {
        return send(res, 201, await registry.createApiKey(store, accountHash, { name: body.name }));
      }
      if (pathname === "/v1/keys/reset" && req.method === "POST") {
        return send(res, 201, await registry.resetAllApiKeys(store, accountHash));
      }
      const keyMatch = pathname.match(/^\/v1\/keys\/([a-f0-9]{64})(\/reset)?$/);
      if (keyMatch) {
        if (req.method === "DELETE" && !keyMatch[2]) {
          return send(res, 200, await registry.revokeApiKey(store, accountHash, keyMatch[1]));
        }
        if (req.method === "POST" && keyMatch[2]) {
          return send(res, 201, await registry.resetApiKey(store, accountHash, keyMatch[1]));
        }
      }
      return send(res, 404, { error: { code: "NOT_FOUND", message: "Unknown key management route." } });
    }

    // ---- Admin / operator routes (X-Admin-Token) ----
    if (pathname === "/v1/vouchers" || pathname.startsWith("/v1/admin/")) {
      requireAdmin(req);
      const body = req.method === "POST" ? await readBody(req) : {};

      if (pathname === "/v1/vouchers" && req.method === "POST") {
        return send(res, 201, await registry.createVoucher(store, body));
      }
      if (pathname === "/v1/admin/accounts" && req.method === "POST") {
        return send(res, 201, await registry.createAccount(store, {
          credits: body.credits ?? Number(process.env.CORE_DEFAULT_CREDITS ?? 5000),
          expiresInDays: body.expiresInDays ?? null,
        }));
      }
      if (pathname === "/v1/admin/accounts" && req.method === "GET") {
        return send(res, 200, { accounts: await registry.listAccounts(store) });
      }
      const accountMatch = pathname.match(/^\/v1\/admin\/accounts\/([a-f0-9]{64})(\/topup)?$/);
      if (accountMatch) {
        if (req.method === "DELETE" && !accountMatch[2]) {
          return send(res, 200, await registry.revokeAccount(store, accountMatch[1]));
        }
        if (req.method === "POST" && accountMatch[2]) {
          return send(res, 200, await registry.topUpAccount(store, accountMatch[1], body.credits));
        }
      }
      return send(res, 404, { error: { code: "NOT_FOUND", message: "Unknown admin route." } });
    }

    // ---- Proxied connector routes (X-API-Key ONLY) ----
    const match = /^\/v1\/([^/]+)/.exec(pathname);
    if (!match || !["GET", "POST", "PUT", "DELETE", "HEAD"].includes(req.method)) {
      return send(res, 404, { error: { code: "NOT_FOUND", message: "Unknown route." } });
    }
    if (!ALLOW_PEOPLE() && /^\/v1\/linkedin\/people\//.test(pathname)) {
      throw new GatewayError(
        "ROUTE_BLOCKED",
        "Personal-data endpoints are blocked on this gateway by default.",
        403
      );
    }
    cost = costFor(pathname);
    const auth = await authenticate(req, cost);
    const target = resolveUpstream(pathname);
    if (!target) throw new GatewayError("UNKNOWN_SERVICE", `No upstream for /v1/${match[1]}.`, 502);

    const upstreamUrl = `${target.base}${target.path}${url.search}`;
    let upstream;
    let xCache = "BYPASS";

    if (req.method === "GET" || req.method === "HEAD") {
      const resolved = await cache.resolve({
        method: req.method,
        pathname,
        search: url.search,
        cacheControl: req.headers["cache-control"],
        loader: () => forward({
          method: req.method,
          url: upstreamUrl,
          body: null,
          headers: forwardHeaders(req),
          timeoutMs: TIMEOUT(),
        }),
      });
      upstream = resolved.response;
      xCache = resolved.xCache;
    } else {
      const body = await readBody(req);
      upstream = await forward({
        method: req.method,
        url: upstreamUrl,
        body,
        headers: forwardHeaders(req),
        timeoutMs: TIMEOUT(),
      });
    }

    const charged = billable(upstream.status, upstream.body);
    if (charged) {
      remaining = await debit(auth.accountHash, cost, auth.keyHash);
    } else {
      // A failed or empty upstream is never charged, but the key was used.
      await touch(auth.keyHash);
      remaining = auth.account.credits;
    }

    const headers = {
      "Content-Type": upstream.contentType,
      "X-Credits-Cost": String(cost),
      "X-Credits-Remaining": String(remaining),
      "X-RateLimit-Remaining": String(auth.rate.remaining),
      "X-Charged": charged ? "true" : "false",
      "X-Cache": xCache,
    };
    res.writeHead(upstream.status, {
      ...headers,
      "Content-Length": Buffer.byteLength(upstream.body),
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": CORS_HEADERS,
      "Access-Control-Expose-Headers": EXPOSE_HEADERS,
    });
    return req.method === "HEAD" ? res.end() : res.end(upstream.body);
  } catch (err) {
    return fail(res, err);
  } finally {
    logger.request({
      method: req.method, path: pathname, status: res.statusCode,
      durationMs: Date.now() - started, cost, remaining,
    });
  }
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((err) => fail(res, err));
});

function listenOn(p, h) {
  return new Promise((resolve, reject) => {
    const onError = (err) => { server.removeListener("error", onError); reject(err); };
    server.once("error", onError);
    server.listen(p, h, () => { server.removeListener("error", onError); resolve(); });
  });
}
function closeServer() {
  return new Promise((resolve) => {
    if (!server.listening) return resolve();
    server.close(() => resolve());
    server.closeAllConnections?.();
  });
}

async function announce() {
  const state = await store.read();
  logger.banner({
    port: bound.port, host: bound.host, version: pkg.version,
    upstreams: upstreams(),
    accounts: Object.values(state.accounts).filter((a) => isActive(a)).length,
    apiKeys: Object.values(state.apiKeys).filter((k) => !k.revoked).length,
    people: ALLOW_PEOPLE(),
  });
  logger.ready();
}

function snapshot() { return Object.fromEntries(CONFIG_KEYS.map((k) => [k, process.env[k]])); }

async function reload() {
  if (reloading || stopping) return;
  reloading = true;
  try {
    const before = snapshot();
    const info = config.load();
    const after = snapshot();
    const changed = CONFIG_KEYS.filter((k) => before[k] !== after[k]);
    log.info(`reload       ${path.basename(info.file)}${info.found ? "" : " (no .env)"}`);
    if (changed.some((k) => ["CORE_STORE", "CORE_DATA_DIR", "CORE_DATA_FILE"].includes(k))) store = createStore();
    if (changed.includes("CORE_RATE_PER_MIN")) limiter = new RateLimiter({ perMinute: Number(process.env.CORE_RATE_PER_MIN ?? 60) });
    if (changed.includes("CORE_SIGNUP_PER_HOUR")) signupLimiter = new SignupLimiter(Number(process.env.CORE_SIGNUP_PER_HOUR ?? 5));
    if (changed.some((k) => ["CORE_CACHE_ENABLED", "CORE_CACHE_TTL_MS", "CORE_CACHE_MAX_ENTRIES"].includes(k))) {
      cache.configure();
    }
    if (changed.some((k) => k.startsWith("CORE_PAYMENT_") || k.startsWith("CORE_BTCPAY_") || k === "CORE_CREDIT_PACKS" || k === "CORE_WEBHOOK_SECRET")) {
      payments.purgeExpired();
    }
    if (changed.includes("CORE_UPSTREAMS") || changed.includes("CORE_ALLOW_PEOPLE") || changed.some((k) => k.startsWith("CORE_") && k.endsWith("_URL"))) {
      resetStatusCache();
      resetOpenApiCache();
    }
    const nextPort = PORT(), nextHost = HOST();
    if (nextPort !== bound.port || nextHost !== bound.host) {
      await closeServer();
      await listenOn(nextPort, nextHost);
      bound = { port: nextPort, host: nextHost };
      log.success(`rebound      ${nextHost}:${nextPort}`);
    }
    log.info(`config       ${changed.length} key(s) changed`);
    await announce();
  } catch (err) {
    log.error(`reload failed: ${err.message}`);
  } finally { reloading = false; }
}

async function shutdown() {
  if (stopping) return;
  stopping = true;
  log.info("Shutting down...");
  if (process.stdin.isTTY && process.stdin.setRawMode) process.stdin.setRawMode(false);
  await closeServer();
  process.exit(0);
}
function setupHotkeys() {
  if (!process.stdin.isTTY) { log.debug("Ctrl+R reload unavailable (stdin is not a TTY)"); return; }
  readline.emitKeypressEvents(process.stdin);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.on("keypress", (str, key) => {
    if (!key) return;
    if ((key.ctrl && key.name === "r") || key.sequence === "\x12") reload().catch((e) => log.error(`reload failed: ${e.message}`));
    else if (key.ctrl && key.name === "c") shutdown();
  });
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

async function start() {
  await listenOn(bound.port, bound.host);
  await announce();
  setupHotkeys();
}
start().catch((err) => { console.error(`[api] Could not start: ${err.message}`); process.exit(1); });

module.exports = { server, reload, config, cache, payments };
