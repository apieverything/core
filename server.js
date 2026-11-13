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
const { assertKeyFormat, hashKey, timingSafeEqual } = require("./core/keys");
const {
  createKey, listKeys, revokeKey, topUpKey, createVoucher, redeemVoucher,
} = require("./core/registry");
const { upstreams, resolveUpstream, forwardHeaders, forward } = require("./core/proxy");
const logger = require("./core/logger");
const { log } = logger;

const pkg = require("./package.json");
const PORT = () => Number(process.env.PORT ?? 9000);
const HOST = () => process.env.HOST ?? "0.0.0.0";
const ADMIN = () => process.env.CORE_ADMIN_TOKEN?.trim() || null;
const TIMEOUT = () => Math.max(1000, Number(process.env.CORE_TIMEOUT_MS ?? 20000));
const ALLOW_PEOPLE = () => process.env.CORE_ALLOW_PEOPLE === "1";
const MAX_BODY = 64 * 1024;

const CONFIG_KEYS = [
  "PORT", "HOST", "CORE_ADMIN_TOKEN", "CORE_UPSTREAMS",
  "CORE_INSTAGRAM_URL", "CORE_LINKEDIN_URL", "CORE_TIKTOK_URL",
  "CORE_COSTS", "CORE_RATE_PER_MIN", "CORE_TIMEOUT_MS",
  "CORE_ALLOW_PEOPLE", "CORE_ALLOW_CLIENT_HASH", "CORE_DEFAULT_CREDITS",
  "CORE_STORE", "CORE_DATA_DIR", "CORE_DATA_FILE",
  "LOG_LEVEL", "NO_COLOR", "FORCE_COLOR",
];

let store = createStore();
let limiter = new RateLimiter({ perMinute: Number(process.env.CORE_RATE_PER_MIN ?? 60) });
let bound = { port: PORT(), host: HOST() };
let reloading = false;
let stopping = false;

function send(res, status, payload, extra = {}) {
  if (status === 204) {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, X-API-Key, X-Admin-Token",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    });
    return res.end();
  }
  const body = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2) + "\n";
  res.writeHead(status, {
    "Content-Type": typeof payload === "string" ? "text/yaml; charset=utf-8" : "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, X-API-Key, X-Admin-Token",
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

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new GatewayError("BAD_REQUEST", "Request body too large.", 413);
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  const text = Buffer.concat(chunks).toString("utf8");
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

async function authenticate(req, cost) {
  const raw = req.headers["x-api-key"] ?? "";
  assertKeyFormat(raw);
  const keyHash = hashKey(raw);
  const state = await store.read();
  const record = state.keys[keyHash];
  if (!record) throw new GatewayError("INVALID_KEY", "Unknown API key.", 401);
  if (record.revoked) throw new GatewayError("KEY_REVOKED", "Key revoked.", 403);
  if (record.expiresAt && Date.parse(record.expiresAt) <= Date.now()) {
    throw new GatewayError("KEY_EXPIRED", "Key expired.", 403);
  }
  if (record.credits < cost) throw new GatewayError("NO_CREDITS", "Not enough credits.", 402);
  const rate = limiter.check(keyHash);
  if (!rate.allowed) throw new GatewayError("RATE_LIMITED", "Rate limit exceeded.", 429);
  return { keyHash, record, rate };
}

async function debit(keyHash, cost) {
  const state = await store.write((current) => {
    const record = current.keys[keyHash];
    if (record && !record.revoked) record.credits = Math.max(0, record.credits - cost);
    return current;
  });
  return state.keys[keyHash]?.credits ?? 0;
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
        description: "One key, weighted credits, zero data retention.",
        upstreams: Object.keys(upstreams()),
        peopleRoutes: ALLOW_PEOPLE() ? "allowed" : "blocked",
        dataPolicy: "Only key hashes, credit counters and expiry dates are stored.",
        endpoints: {
          health: "GET /health",
          usage: "GET /v1/usage",
          redeem: "POST /v1/redeem",
          admin: "POST /v1/keys, POST /v1/vouchers (X-Admin-Token)",
          proxy: "GET|POST /v1/:service/... (X-API-Key)",
          schema: "GET /openapi.yaml",
        },
      });
    }

    if (pathname === "/health") {
      const state = await store.read();
      const keys = Object.values(state.keys);
      return send(res, 200, {
        status: "ok",
        upstreams: Object.keys(upstreams()),
        keys: keys.length,
        activeKeys: keys.filter((k) => isActive(k)).length,
        vouchers: Object.values(state.vouchers).filter((v) => !v.redeemed).length,
        adminEnabled: Boolean(ADMIN()),
        peopleRoutes: ALLOW_PEOPLE() ? "allowed" : "blocked",
      });
    }

    if (pathname === "/openapi.yaml") {
      const file = path.join(__dirname, "openapi.yaml");
      if (!fs.existsSync(file)) return send(res, 404, { error: { code: "NOT_FOUND" } });
      return send(res, 200, fs.readFileSync(file, "utf8"));
    }

    // Public voucher redemption: no identity, no key required.
    if (pathname === "/v1/redeem" && req.method === "POST") {
      const body = await readBody(req);
      const result = await redeemVoucher(store, body);
      return send(res, 200, result);
    }

    if (pathname === "/v1/usage") {
      const raw = req.headers["x-api-key"] ?? "";
      assertKeyFormat(raw);
      const keyHash = hashKey(raw);
      const state = await store.read();
      const record = state.keys[keyHash];
      if (!record) throw new GatewayError("INVALID_KEY", "Unknown API key.", 401);
      const rate = limiter.check(keyHash);
      return send(res, 200, {
        keyHash,
        credits: record.credits,
        expiresAt: record.expiresAt,
        revoked: record.revoked,
        rateLimitRemaining: rate.remaining,
      });
    }

    // ---- Admin routes ----
    if (pathname.startsWith("/v1/keys") || pathname === "/v1/vouchers") {
      requireAdmin(req);
      if (pathname === "/v1/keys" && req.method === "POST") {
        const body = await readBody(req);
        const result = await createKey(store, {
          credits: body.credits ?? Number(process.env.CORE_DEFAULT_CREDITS ?? 5000),
          expiresInDays: body.expiresInDays ?? 365,
        });
        return send(res, 201, result);
      }
      if (pathname === "/v1/keys" && req.method === "GET") {
        return send(res, 200, { keys: await listKeys(store) });
      }
      if (pathname === "/v1/vouchers" && req.method === "POST") {
        const body = await readBody(req);
        const result = await createVoucher(store, body);
        return send(res, 201, result);
      }
      const keyMatch = pathname.match(/^\/v1\/keys\/([a-f0-9]{64})(\/topup)?$/);
      if (keyMatch) {
        if (req.method === "DELETE") return send(res, 200, await revokeKey(store, keyMatch[1]));
        if (req.method === "POST" && keyMatch[2]) {
          const body = await readBody(req);
          return send(res, 200, await topUpKey(store, keyMatch[1], body.credits));
        }
      }
      return send(res, 404, { error: { code: "NOT_FOUND", message: "Unknown management route." } });
    }

    // ---- Proxied connector routes ----
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
    const body = req.method === "GET" || req.method === "HEAD" ? null : await readBody(req);
    const upstream = await forward({
      method: req.method,
      url: upstreamUrl,
      body,
      headers: forwardHeaders(req),
      timeoutMs: TIMEOUT(),
    });

    const charged = billable(upstream.status, upstream.body);
    remaining = charged
      ? await debit(auth.keyHash, cost)
      : auth.record.credits; // a failed or empty upstream is never charged

    const headers = {
      "Content-Type": upstream.contentType,
      "X-Credits-Cost": String(cost),
      "X-Credits-Remaining": String(remaining),
      "X-RateLimit-Remaining": String(auth.rate.remaining),
      "X-Charged": charged ? "true" : "false",
    };
    res.writeHead(upstream.status, {
      ...headers,
      "Content-Length": Buffer.byteLength(upstream.body),
      "Access-Control-Allow-Origin": "*",
    });
    return res.end(upstream.body);
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
    keys: Object.values(state.keys).filter((k) => isActive(k)).length,
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

module.exports = { server, reload, config };
