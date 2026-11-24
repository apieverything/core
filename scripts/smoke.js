#!/usr/bin/env node
/**
 * End-to-end smoke test with a mock connector. No network calls to real
 * services, no dependencies beyond Node. Verifies the full
 * signup -> unlock -> API key -> proxy/debit -> cache/coalesce -> rotate ->
 * payments/webhook -> voucher -> unified OpenAPI flow.
 *
 *   npm run smoke
 */
"use strict";

const http = require("node:http");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "core-smoke-"));
const dataFile = path.join(dir, "keys.json");
const logFile = path.join(dir, "core.log");
const checks = [];
const rawCredentials = [];

function check(name, condition, detail = "") {
  checks.push({ name, pass: Boolean(condition), detail });
  console.log(`  ${condition ? "✓" : "✗"} ${name}${detail ? `  (${detail})` : ""}`);
}
function freePort() {
  return new Promise((resolve) => {
    const s = http.createServer();
    s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

const MOCK_CONNECTOR_OPENAPI = [
  "openapi: 3.0.3",
  "info:",
  "  title: Mock Connector",
  "  version: 1.0.0",
  "paths:",
  "  /health:",
  "    get:",
  '      responses: { "200": { description: OK } }',
  "  /v1/instagram/{username}/posts:",
  "    get:",
  "      summary: Instagram posts",
  '      responses: { "200": { description: Posts } }',
  "  /v1/youtube/{handle}/posts:",
  "    get:",
  "      summary: YouTube channel videos",
  '      responses: { "200": { description: Videos } }',
].join("\n");

async function main() {
  const upstreamPort = await freePort();
  const corePort = await freePort();
  const lockedPort = await freePort();
  const upstreamHits = new Map();

  // Mock connector: instagram & youtube succeed, tiktok is throttled, /openapi.yaml serves YAML.
  const upstream = http.createServer(async (req, res) => {
    const p = req.url.split("?")[0];
    upstreamHits.set(p, (upstreamHits.get(p) ?? 0) + 1);
    if (p === "/openapi.yaml") {
      res.writeHead(200, { "Content-Type": "text/yaml; charset=utf-8" });
      return res.end(MOCK_CONNECTOR_OPENAPI);
    }
    if (p.includes("/tiktok/")) {
      res.writeHead(429, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: { code: "TT_RATE_LIMITED" } }));
    }
    if (p.includes("/youtube/@mkbhd/posts")) {
      await new Promise((r) => setTimeout(r, 30));
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, path: p, posts: [{ id: 1 }] }));
  });
  await new Promise((r) => upstream.listen(upstreamPort, "127.0.0.1", r));

  const env = {
    ...process.env,
    PORT: String(corePort),
    CORE_ENV_FILE: path.join(dir, "no.env"),
    CORE_ADMIN_TOKEN: "smoke-admin-token",
    CORE_UPSTREAMS: JSON.stringify({
      instagram: `http://127.0.0.1:${upstreamPort}`,
      youtube: `http://127.0.0.1:${upstreamPort}`,
      linkedin: `http://127.0.0.1:${upstreamPort}`,
      tiktok: `http://127.0.0.1:${upstreamPort}`,
    }),
    CORE_CACHE_ENABLED: "1",
    CORE_CACHE_TTL_MS: "120000",
    CORE_PAYMENT_SANDBOX: "1",
    CORE_WEBHOOK_SECRET: "smoke-webhook-secret",
    CORE_STORE: "file",
    CORE_DATA_FILE: dataFile,
    CORE_RATE_PER_MIN: "200",
    LOG_LEVEL: "info",
    NO_COLOR: "1",
  };
  const fd = fs.openSync(logFile, "w");
  const child = spawn(process.execPath, ["server.js"], { cwd: ROOT, env, stdio: ["ignore", fd, fd] });
  const base = `http://127.0.0.1:${corePort}`;

  // Second lightweight instance with CORE_PAYMENT_SANDBOX=0 & no webhook secret to verify fail-closed gates.
  const lockedChild = spawn(process.execPath, ["server.js"], {
    cwd: ROOT,
    env: {
      ...env,
      PORT: String(lockedPort),
      CORE_STORE: "memory",
      CORE_PAYMENT_SANDBOX: "0",
      CORE_WEBHOOK_SECRET: "",
      LOG_LEVEL: "silent",
    },
    stdio: "ignore",
  });
  const lockedBase = `http://127.0.0.1:${lockedPort}`;

  const reqTo = (origin) => async (method, p, headers = {}, body = null) => {
    const r = await fetch(origin + p, {
      method,
      headers: { ...headers, ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: r.status, json, text, headers: r.headers };
  };
  const req = reqTo(base);
  const reqLocked = reqTo(lockedBase);

  for (let i = 0; i < 50; i += 1) {
    try {
      const [a, b] = await Promise.all([fetch(base + "/health"), fetch(lockedBase + "/health")]);
      if (a.ok && b.ok) break;
    } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }

  const admin = { "X-Admin-Token": "smoke-admin-token" };
  const health = await req("GET", "/health");
  check("GET /health", health.status === 200 && health.json.status === "ok");
  check("people routes blocked by default", health.json.peopleRoutes === "blocked");
  check("health counts accounts and API keys separately",
    Number.isInteger(health.json.accounts) && Number.isInteger(health.json.apiKeys));
  check("health exposes cache stats",
    health.json.cache?.enabled === true && Number.isInteger(health.json.cache?.maxEntries));
  check("CORS exposes accounting and cache headers",
    (health.headers.get("access-control-expose-headers") ?? "").includes("X-Cache") &&
    (health.headers.get("access-control-allow-headers") ?? "").includes("Cache-Control"));

  const noAdmin = await req("POST", "/v1/vouchers", {}, { credits: 10 });
  check("admin routes are protected", noAdmin.status === 401);

  const signupRes = await req("POST", "/v1/signup");
  const unlockCode = signupRes.json?.unlockCode;
  rawCredentials.push(unlockCode);
  check("public signup returns a 16-digit UNLOCK CODE", signupRes.status === 201 && /^\d{16}$/.test(String(unlockCode)));
  check("signup never returns an API key", signupRes.json?.key === undefined && signupRes.json?.apiKey === undefined);
  check("signup is PayAsYouGo: no expiry, starter credits",
    signupRes.json?.model === "pay_as_you_go" && signupRes.json?.expiresAt === null && signupRes.json?.credits === 50);
  check("signup says the code is NOT an API key", /NOT an API key/i.test(signupRes.json?.notice ?? ""));

  const status = await req("GET", "/v1/status");
  check("public status reports every connector", status.status === 200 && status.json?.total === 4 && status.json?.healthy === 4);
  check("status never exposes internal upstream URLs", !JSON.stringify(status.json).includes(`127.0.0.1:${upstreamPort}`));

  // The whole point of the split: the unlock code must be rejected as an API key.
  const confused = await req("GET", "/v1/instagram/kametolol/posts", { "X-API-Key": unlockCode });
  check("unlock code is REJECTED as X-API-Key", confused.json?.error?.code === "UNLOCK_CODE_NOT_API_KEY");
  const noUnlock = await req("GET", "/v1/keys");
  check("key management requires an unlock code", noUnlock.json?.error?.code === "INVALID_UNLOCK_CODE");

  const unlocked = await req("POST", "/v1/unlock", {}, { unlockCode });
  check("unlock opens the account", unlocked.status === 200 && unlocked.json?.activeApiKeys === 0);

  const unlockHeader = { "X-Unlock-Code": unlockCode };
  const created = await req("POST", "/v1/keys", unlockHeader, { name: "first" });
  const apiKey = created.json?.apiKey;
  rawCredentials.push(apiKey);
  check("first API key created and returned once", created.status === 201 && /^ae_[a-f0-9]{48}$/.test(String(apiKey)));

  const listed = await req("GET", "/v1/keys", unlockHeader);
  check("key list is sanitized (no raw key)", listed.json?.keys?.length === 1 && !JSON.stringify(listed.json).includes(apiKey));

  // Admin-issued account with a known balance for the debit & cache assertions.
  const adminAccount = await req("POST", "/v1/admin/accounts", admin, { credits: 60 });
  const adminUnlock = adminAccount.json?.unlockCode;
  rawCredentials.push(adminUnlock);
  const adminKey = (await req("POST", "/v1/keys", { "X-Unlock-Code": adminUnlock }, { name: "smoke" })).json?.apiKey;
  rawCredentials.push(adminKey);
  const adminAuth = { "X-API-Key": adminKey };

  const usage = await req("GET", "/v1/usage", adminAuth);
  check("usage shows the ACCOUNT credits", usage.json?.credits === 60);
  const usageUnlock = await req("GET", "/v1/usage", { "X-Unlock-Code": adminUnlock });
  check("usage also accepts the unlock code", usageUnlock.json?.credits === 60 && usageUnlock.json?.authenticatedWith === "unlockCode");

  const ok = await req("GET", "/v1/instagram/kametolol/posts?limit=2&cursor=SECRET", adminAuth);
  check("proxy relays 200", ok.status === 200);
  check("weighted cost applied", ok.headers.get("x-credits-cost") === "3");
  check("successful call is charged", ok.headers.get("x-charged") === "true" && ok.headers.get("x-credits-remaining") === "57");
  check("first call is X-Cache: MISS and exposes headers",
    ok.headers.get("x-cache") === "MISS" && (ok.headers.get("access-control-expose-headers") ?? "").includes("X-Cache"));

  const cachedHit = await req("GET", "/v1/instagram/kametolol/posts?limit=2&cursor=SECRET", adminAuth);
  check("repeat call hits RAM cache (X-Cache: HIT, upstream hit count === 1)",
    cachedHit.headers.get("x-cache") === "HIT" &&
    upstreamHits.get("/v1/instagram/kametolol/posts") === 1 &&
    cachedHit.headers.get("x-credits-remaining") === "54");

  const bypassRes = await req("GET", "/v1/instagram/kametolol/posts?limit=2&cursor=SECRET", {
    ...adminAuth,
    "Cache-Control": "no-cache",
  });
  check("Cache-Control: no-cache bypasses cache (X-Cache: BYPASS)",
    bypassRes.headers.get("x-cache") === "BYPASS" &&
    upstreamHits.get("/v1/instagram/kametolol/posts") === 2 &&
    bypassRes.headers.get("x-credits-remaining") === "51");

  // YouTube cost weighting + 10 concurrent coalesced requests.
  const ytProfile = await req("GET", "/v1/youtube/@mkbhd", adminAuth);
  check("YouTube channel metadata costs 1 credit",
    ytProfile.status === 200 && ytProfile.headers.get("x-credits-cost") === "1" && ytProfile.headers.get("x-credits-remaining") === "50");

  const coalescedBatch = await Promise.all(
    Array.from({ length: 10 }, () => req("GET", "/v1/youtube/@mkbhd/posts?limit=2", adminAuth))
  );
  const xCaches = coalescedBatch.map((r) => r.headers.get("x-cache"));
  check("YouTube video feed costs 2 credits",
    coalescedBatch.every((r) => r.status === 200 && r.headers.get("x-credits-cost") === "2"));
  check("10 concurrent misses coalesce into 1 upstream call (1 MISS + 9 COALESCED)",
    upstreamHits.get("/v1/youtube/@mkbhd/posts") === 1 &&
    xCaches.filter((s) => s === "MISS").length === 1 &&
    xCaches.filter((s) => s === "COALESCED").length === 9);

  const throttled = await req("GET", "/v1/tiktok/khaby.lame/posts?limit=2", adminAuth);
  check("throttled upstream relayed as 429", throttled.status === 429);
  check("failed upstream is NOT charged", throttled.headers.get("x-charged") === "false" && throttled.headers.get("x-credits-remaining") === "30");

  const people = await req("GET", "/v1/linkedin/people/reidhoffman", adminAuth);
  check("people route blocked", people.json?.error?.code === "ROUTE_BLOCKED");
  const bad = await req("GET", "/v1/instagram/x", { "X-API-Key": "1234" });
  check("bad key rejected", bad.json?.error?.code === "INVALID_KEY");
  const unknown = await req("GET", "/v1/unknown/x", adminAuth);
  check("unknown service rejected", unknown.json?.error?.code === "UNKNOWN_SERVICE");

  // Rotation: old key dies, new key works, credits are untouched.
  const rotated = await req("POST", `/v1/keys/${created.json.keyHash}/reset`, unlockHeader);
  const rotatedKey = rotated.json?.apiKey;
  rawCredentials.push(rotatedKey);
  check("key rotation returns a fresh API key", rotated.status === 201 && /^ae_[a-f0-9]{48}$/.test(String(rotatedKey)));
  const dead = await req("GET", "/v1/instagram/x", { "X-API-Key": apiKey });
  check("rotated-out key is revoked", dead.json?.error?.code === "KEY_REVOKED");
  check("replacement key works", (await req("GET", "/v1/usage", { "X-API-Key": rotatedKey })).status === 200);
  const second = await req("POST", "/v1/keys", unlockHeader, { name: "spare" });
  rawCredentials.push(second.json?.apiKey);
  const revoked = await req("DELETE", `/v1/keys/${second.json.keyHash}`, unlockHeader);
  check("a key can be revoked", revoked.json?.revoked === true);
  check("revoked key is refused", (await req("GET", "/v1/usage", { "X-API-Key": second.json.apiKey })).json?.error?.code === "KEY_REVOKED");

  const voucher = await req("POST", "/v1/vouchers", admin, { credits: 30 });
  rawCredentials.push(voucher.json?.code);
  check("voucher issued", voucher.status === 201 && Boolean(voucher.json?.code));
  const redeem = await req("POST", "/v1/redeem", {}, { code: voucher.json.code, unlockCode });
  check("voucher redeemed into the account", redeem.status === 200 && redeem.json?.credits === 80);
  const replay = await req("POST", "/v1/redeem", {}, { code: voucher.json.code, unlockCode });
  check("voucher replay rejected", replay.json?.error?.code === "BAD_VOUCHER");

  // Zero-identity PayAsYouGo payment -> voucher flow (sandbox + disabled gate + BTCPay webhook).
  const packsRes = await req("GET", "/v1/payments/packs");
  check("payment packs listed in sandbox mode",
    packsRes.status === 200 && packsRes.json?.enabled === true && packsRes.json?.mode === "sandbox" && packsRes.json?.packs?.length === 3);

  const checkoutRes = await req("POST", "/v1/payments/checkout", {}, { packId: "pack_1k" });
  const invoiceId = checkoutRes.json?.invoiceId;
  check("payment checkout creates transient pending invoice",
    checkoutRes.status === 201 && /^inv_[a-f0-9]{24}$/.test(String(invoiceId)) && checkoutRes.json?.status === "pending");

  const settledRes = await req("POST", `/v1/payments/sandbox/${invoiceId}/settle`);
  const settledAgain = await req("POST", `/v1/payments/sandbox/${invoiceId}/settle`);
  const paidVoucher = settledRes.json?.voucherCode;
  rawCredentials.push(paidVoucher);
  check("sandbox settle idempotently mints one-time voucher",
    settledRes.status === 200 && settledRes.json?.credits === 1000 && Boolean(paidVoucher) && settledAgain.json?.voucherCode === paidVoucher);

  const polledInv = await req("GET", `/v1/payments/invoices/${invoiceId}`);
  check("invoice status endpoint returns settled voucherCode",
    polledInv.status === 200 && polledInv.json?.status === "settled" && polledInv.json?.voucherCode === paidVoucher);

  const redeemPaid = await req("POST", "/v1/redeem", {}, { code: paidVoucher, unlockCode });
  check("settled payment voucher redeems into account",
    redeemPaid.status === 200 && redeemPaid.json?.credits === 1080);

  // Fail-closed checks when CORE_PAYMENT_SANDBOX=0 & CORE_WEBHOOK_SECRET unset.
  const lockedPacks = await reqLocked("GET", "/v1/payments/packs");
  const lockedCheckout = await reqLocked("POST", "/v1/payments/checkout", {}, { packId: "pack_1k" });
  const lockedSettle = await reqLocked("POST", `/v1/payments/sandbox/${invoiceId}/settle`);
  const lockedWebhook = await reqLocked("POST", "/v1/payments/webhook", { "btcpay-sig": "sha256=" + "0".repeat(64) }, { type: "InvoiceSettled" });
  check("SANDBOX_DISABLED enforced when CORE_PAYMENT_SANDBOX=0",
    lockedPacks.json?.enabled === false &&
    lockedCheckout.status === 503 && lockedCheckout.json?.error?.code === "PAYMENTS_DISABLED" &&
    lockedSettle.status === 403 && lockedSettle.json?.error?.code === "SANDBOX_DISABLED" &&
    lockedWebhook.status === 503 && lockedWebhook.json?.error?.code === "WEBHOOK_DISABLED");

  // BTCPay webhook HMAC-SHA256 verification on exact raw bytes.
  const rawWebhookPayload = '{\n  "type": "InvoiceSettled",\n  "metadata": { "invoiceId": "inv_abcdef0123456789abcdef01", "packId": "pack_5k", "credits": 5000 }\n}';
  const badWebhook = await fetch(base + "/v1/payments/webhook", {
    method: "POST",
    headers: { "Content-Type": "application/json", "btcpay-sig": "sha256=" + "a".repeat(64) },
    body: rawWebhookPayload,
  });
  check("BTCPay webhook rejects invalid HMAC signature with 401",
    badWebhook.status === 401 && (await badWebhook.json())?.error?.code === "INVALID_SIGNATURE");

  const validSig = "sha256=" + crypto.createHmac("sha256", "smoke-webhook-secret").update(Buffer.from(rawWebhookPayload, "utf8")).digest("hex");
  const goodWebhookRes = await fetch(base + "/v1/payments/webhook", {
    method: "POST",
    headers: { "Content-Type": "application/json", "btcpay-sig": validSig },
    body: rawWebhookPayload,
  });
  const goodWebhookJson = await goodWebhookRes.json();
  rawCredentials.push(goodWebhookJson?.voucherCode);
  const redeemWebhook = await req("POST", "/v1/redeem", {}, { code: goodWebhookJson.voucherCode, unlockCode });
  check("BTCPay webhook verifies valid HMAC and mints redeemable voucher",
    goodWebhookRes.status === 200 && goodWebhookJson?.settled === true && redeemWebhook.json?.credits === 6080);

  const schema = await req("GET", "/openapi.yaml");
  check("OpenAPI YAML served", schema.status === 200 && /0\.3\.0/.test(schema.text) && /X-Cache/.test(schema.text));

  const unified = await req("GET", "/v1/openapi.json");
  check("GET /v1/openapi.json merges gateway + discovered connector routes without leaking internal URLs",
    unified.status === 200 &&
    unified.json?.openapi === "3.0.3" &&
    unified.json?.info?.version === "0.3.0" &&
    Boolean(unified.json?.paths?.["/v1/payments/packs"]) &&
    Boolean(unified.json?.paths?.["/v1/youtube/{handle}/posts"]) &&
    !JSON.stringify(unified.json).includes(`127.0.0.1:${upstreamPort}`));

  child.kill("SIGTERM");
  lockedChild.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 400));
  upstream.close();
  fs.closeSync(fd);

  const disk = fs.readFileSync(dataFile, "utf8");
  const log = fs.readFileSync(logFile, "utf8");
  check("no raw credential ever written to disk", rawCredentials.every((c) => c && !disk.includes(c)));
  check("no raw credential in logs", rawCredentials.every((c) => c && !log.includes(c)));
  check("no query strings in logs", !/cursor=SECRET|limit=2|keywords=/.test(log));
  check("no identity or invoice fields in store", !/"(email|ip|query|history|wallet|invoices|invoiceId)"/i.test(disk));

  fs.rmSync(dir, { recursive: true, force: true });
  const failed = checks.filter((c) => !c.pass);
  console.log(`\n  ${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length) process.exit(1);
}
main().catch((e) => { console.error("ERR", e); process.exit(1); });
