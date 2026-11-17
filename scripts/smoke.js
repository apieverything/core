#!/usr/bin/env node
/**
 * End-to-end smoke test with a mock connector. No network calls to real
 * services, no dependencies beyond Node. Verifies the whole key/quota flow.
 *
 *   npm run smoke
 */
"use strict";

const http = require("node:http");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "core-smoke-"));
const dataFile = path.join(dir, "keys.json");
const logFile = path.join(dir, "core.log");
const checks = [];

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

async function main() {
  const upstreamPort = await freePort();
  const corePort = await freePort();

  // Mock connector: instagram succeeds, tiktok is throttled.
  const upstream = http.createServer((req, res) => {
    const p = req.url.split("?")[0];
    if (p.includes("/tiktok/")) {
      res.writeHead(429, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: { code: "TT_RATE_LIMITED" } }));
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
      linkedin: `http://127.0.0.1:${upstreamPort}`,
      tiktok: `http://127.0.0.1:${upstreamPort}`,
    }),
    CORE_STORE: "file",
    CORE_DATA_FILE: dataFile,
    CORE_RATE_PER_MIN: "100",
    LOG_LEVEL: "info",
    NO_COLOR: "1",
  };
  const fd = fs.openSync(logFile, "w");
  const child = spawn(process.execPath, ["server.js"], { cwd: ROOT, env, stdio: ["ignore", fd, fd] });
  const base = `http://127.0.0.1:${corePort}`;

  const req = async (method, p, headers = {}, body = null) => {
    const r = await fetch(base + p, {
      method,
      headers: { ...headers, ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: r.status, json, headers: r.headers };
  };

  for (let i = 0; i < 50; i += 1) {
    try { if ((await fetch(base + "/health")).ok) break; } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }

  const admin = { "X-Admin-Token": "smoke-admin-token" };
  const health = await req("GET", "/health");
  check("GET /health", health.status === 200 && health.json.status === "ok");
  check("people routes blocked by default", health.json.peopleRoutes === "blocked");

  const noAdmin = await req("POST", "/v1/keys", {}, { credits: 10 });
  check("admin routes are protected", noAdmin.status === 401);

  const signupRes = await req("POST", "/v1/signup");
  const signupKey = signupRes.json?.key;
  check("public signup creates a key with no identity", signupRes.status === 201 && /^\d{16}$/.test(String(signupKey)));
  check("signup is PayAsYouGo: no expiry, starter credits", signupRes.json?.model === "pay_as_you_go" && signupRes.json?.expiresAt === null && signupRes.json?.credits === 50);
  const status = await req("GET", "/v1/status");
  check("public status reports every connector", status.status === 200 && status.json?.total === 3 && status.json?.healthy === 3);
  check("status never exposes internal upstream URLs", !JSON.stringify(status.json).includes(`127.0.0.1:${upstreamPort}`));

  const created = await req("POST", "/v1/keys", admin, { credits: 20, expiresInDays: 30 });
  const key = created.json?.key;
  check("key created and returned once", created.status === 201 && /^\d{16}$/.test(String(key)));
  const auth = { "X-API-Key": key };

  const usage = await req("GET", "/v1/usage", auth);
  check("usage shows credits", usage.json?.credits === 20);

  const ok = await req("GET", "/v1/instagram/kametolol/posts?limit=2&cursor=SECRET", auth);
  check("proxy relays 200", ok.status === 200);
  check("weighted cost applied", ok.headers.get("x-credits-cost") === "3");
  check("successful call is charged", ok.headers.get("x-charged") === "true" && ok.headers.get("x-credits-remaining") === "17");

  const throttled = await req("GET", "/v1/tiktok/khaby.lame/posts?limit=2", auth);
  check("throttled upstream relayed as 429", throttled.status === 429);
  check("failed upstream is NOT charged", throttled.headers.get("x-charged") === "false" && throttled.headers.get("x-credits-remaining") === "17");

  const people = await req("GET", "/v1/linkedin/people/reidhoffman", auth);
  check("people route blocked", people.json?.error?.code === "ROUTE_BLOCKED");
  const bad = await req("GET", "/v1/instagram/x", { "X-API-Key": "1234" });
  check("bad key rejected", bad.json?.error?.code === "INVALID_KEY");
  const unknown = await req("GET", "/v1/unknown/x", auth);
  check("unknown service rejected", unknown.json?.error?.code === "UNKNOWN_SERVICE");

  const voucher = await req("POST", "/v1/vouchers", admin, { credits: 30 });
  check("voucher issued", voucher.status === 201 && Boolean(voucher.json?.code));
  const redeem = await req("POST", "/v1/redeem", {}, { code: voucher.json.code });
  check("voucher redeemed", redeem.status === 200 && redeem.json?.credits === 30);
  const replay = await req("POST", "/v1/redeem", {}, { code: voucher.json.code });
  check("voucher replay rejected", replay.json?.error?.code === "BAD_VOUCHER");

  const schema = await req("GET", "/openapi.yaml");
  check("OpenAPI served", schema.status === 200);

  child.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 400));
  upstream.close();
  fs.closeSync(fd);

  const disk = fs.readFileSync(dataFile, "utf8");
  const log = fs.readFileSync(logFile, "utf8");
  check("raw key never written to disk", !disk.includes(key) && !disk.includes(signupKey));
  check("no query strings in logs", !/cursor=SECRET|limit=2|keywords=/.test(log));
  check("no identity fields in store", !/"(email|ip|query|history|wallet)"/i.test(disk));

  fs.rmSync(dir, { recursive: true, force: true });
  const failed = checks.filter((c) => !c.pass);
  console.log(`\n  ${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length) process.exit(1);
}
main().catch((e) => { console.error("ERR", e); process.exit(1); });
