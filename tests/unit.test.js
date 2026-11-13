"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const keys = require("../core/keys");
const { MemoryStore, FileStore } = require("../core/store");
const ledger = require("../core/ledger");
const { RateLimiter } = require("../core/ratelimit");
const registry = require("../core/registry");
const { routeTemplate } = require("../core/logger");
const { resolveUpstream, forwardHeaders } = require("../core/proxy");
const { GatewayError } = require("../core/errors");

/* ---------- keys ---------- */
test("keys are 16 digits and unique", () => {
  const set = new Set();
  for (let i = 0; i < 300; i += 1) {
    const k = keys.generateKey();
    assert.match(k, /^\d{16}$/);
    set.add(k);
  }
  assert.equal(set.size, 300);
});

test("hashKey is deterministic and never contains the raw key", () => {
  const raw = "1234567890123456";
  const hash = keys.hashKey(raw);
  assert.equal(hash.length, 64);
  assert.match(hash, /^[a-f0-9]{64}$/);
  assert.equal(keys.hashKey(raw), hash);
  assert.ok(!hash.includes(raw));
});

test("key / hash format assertions", () => {
  assert.doesNotThrow(() => keys.assertKeyFormat("1234567890123456"));
  assert.throws(() => keys.assertKeyFormat("1234"), (e) => e.code === "INVALID_KEY");
  assert.doesNotThrow(() => keys.assertHashFormat("a".repeat(64)));
  assert.throws(() => keys.assertHashFormat("xyz"), (e) => e.code === "BAD_KEYHASH");
});

test("timingSafeEqual rejects different lengths and values", () => {
  assert.equal(keys.timingSafeEqual("abc", "abc"), true);
  assert.equal(keys.timingSafeEqual("abc", "abd"), false);
  assert.equal(keys.timingSafeEqual("abc", "abcd"), false);
});

test("maskKey never reveals more than the last 4 digits", () => {
  assert.equal(keys.maskKey("1234567890123456"), "•••• •••• •••• 3456");
  assert.ok(!keys.maskKey("1234567890123456").includes("9012"));
});

/* ---------- ledger ---------- */
test("costs are weighted by upstream work", () => {
  assert.equal(ledger.costFor("/v1/instagram/kametolol/posts"), 3);
  assert.equal(ledger.costFor("/v1/tiktok/khaby.lame/posts"), 3);
  assert.equal(ledger.costFor("/v1/linkedin/signals/hiring"), 2);
  assert.equal(ledger.costFor("/v1/linkedin/people/reidhoffman"), 5);
  assert.equal(ledger.costFor("/v1/linkedin/jobs/search?keywords=python"), 1);
  assert.equal(ledger.costFor("/v1/instagram/kametolol"), 1);
  assert.equal(ledger.costFor("/unknown"), 1);
});

test("CORE_COSTS overrides the default table", () => {
  const saved = process.env.CORE_COSTS;
  try {
    process.env.CORE_COSTS = '[["^/v1/instagram/[^/]+/posts",7]]';
    assert.equal(ledger.costFor("/v1/instagram/kametolol/posts"), 7);
    assert.equal(ledger.costFor("/v1/tiktok/x"), 1);
    process.env.CORE_COSTS = "not json";
    assert.equal(ledger.costFor("/v1/instagram/kametolol/posts"), 3);
  } finally {
    if (saved === undefined) delete process.env.CORE_COSTS;
    else process.env.CORE_COSTS = saved;
  }
});

test("only successful data responses are billable", () => {
  assert.equal(ledger.billable(200, '{"posts":[{"id":1}]}'), true);
  assert.equal(ledger.billable(200, '{"error":{"code":"IG_BLOCKED"}}'), false);
  assert.equal(ledger.billable(429, '{"posts":[]}'), false);
  assert.equal(ledger.billable(502, "upstream down"), false);
  assert.equal(ledger.billable(200, ""), false);
  assert.equal(ledger.billable(404, ""), false);
  assert.equal(ledger.billable(200, "plain text body"), true);
});

test("isActive and expiryFrom", () => {
  assert.equal(ledger.isActive({ credits: 5, revoked: false, expiresAt: null }), true);
  assert.equal(ledger.isActive({ credits: 0, revoked: false }), false);
  assert.equal(ledger.isActive({ credits: 5, revoked: true }), false);
  assert.equal(ledger.isActive({ credits: 5, expiresAt: new Date(Date.now() - 1000).toISOString() }), false);
  assert.ok(Date.parse(ledger.expiryFrom(30)) > Date.now());
});

/* ---------- store ---------- */
test("MemoryStore reads and mutates state", async () => {
  const store = new MemoryStore();
  await store.write((s) => { s.keys.abc = { credits: 10 }; return s; });
  assert.equal((await store.read()).keys.abc.credits, 10);
});

test("FileStore persists atomically and stores no raw key", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "core-store-"));
  const file = path.join(dir, "keys.json");
  const raw = "9876543210987654";
  const hash = keys.hashKey(raw);
  try {
    const store = new FileStore(file);
    await store.write((s) => {
      s.keys[hash] = { credits: 123, createdAt: "x", expiresAt: null, revoked: false };
      return s;
    });
    const text = fs.readFileSync(file, "utf8");
    assert.ok(!text.includes(raw), "raw key must never be written to disk");
    assert.ok(!/"ip"|"email"|"query"|"history"/i.test(text));
    assert.equal((await new FileStore(file).read()).keys[hash].credits, 123);
    assert.equal(fs.existsSync(`${file}.tmp`), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("concurrent debits are serialized and never lose a decrement", async () => {
  const store = new MemoryStore();
  const hash = keys.hashKey("1111111111111111");
  await store.write((s) => { s.keys[hash] = { credits: 50 }; return s; });
  await Promise.all(Array.from({ length: 25 }, () =>
    store.write((s) => { s.keys[hash].credits -= 1; return s; })
  ));
  assert.equal((await store.read()).keys[hash].credits, 25);
});

/* ---------- rate limit ---------- */
test("RateLimiter allows within the window and blocks beyond", () => {
  const rl = new RateLimiter({ perMinute: 3 });
  const now = 1_000_000;
  assert.equal(rl.check("k", now).allowed, true);
  assert.equal(rl.check("k", now + 1).allowed, true);
  assert.equal(rl.check("k", now + 2).allowed, true);
  assert.equal(rl.check("k", now + 3).allowed, false);
  assert.equal(rl.check("k", now + 61000).allowed, true);
  rl.reset();
  assert.equal(rl.check("k", now).allowed, true);
});

/* ---------- registry ---------- */
test("createKey returns the key once and stores only its hash", async () => {
  const store = new MemoryStore();
  const created = await registry.createKey(store, { credits: 5000 });
  assert.match(created.key, /^\d{16}$/);
  const state = await store.read();
  assert.equal(state.keys[created.keyHash].credits, 5000);
  assert.equal(state.keys[created.key], undefined);
  assert.equal(Object.keys(state.keys).length, 1);
  const keysList = await registry.listKeys(store);
  assert.ok(!JSON.stringify(keysList).includes(created.key));
});

test("revoke and topUp", async () => {
  const store = new MemoryStore();
  const { keyHash } = await registry.createKey(store, { credits: 10 });
  await registry.topUpKey(store, keyHash, 5);
  assert.equal((await store.read()).keys[keyHash].credits, 15);
  await registry.revokeKey(store, keyHash);
  assert.equal((await store.read()).keys[keyHash].revoked, true);
  await assert.rejects(
    () => registry.topUpKey(store, "z".repeat(64), 5),
    (e) => e instanceof GatewayError && e.code === "BAD_KEYHASH"
  );
});

test("voucher redeem credits a key and cannot be replayed", async () => {
  const store = new MemoryStore();
  const { code } = await registry.createVoucher(store, { credits: 100 });
  const redeemed = await registry.redeemVoucher(store, { code });
  assert.match(redeemed.key, /^\d{16}$/);
  assert.equal(redeemed.credits, 100);
  await assert.rejects(
    () => registry.redeemVoucher(store, { code }),
    (e) => e.code === "BAD_VOUCHER"
  );
});

test("redeem with a client-provided key hash is gated", async () => {
  const store = new MemoryStore();
  const { code } = await registry.createVoucher(store, { credits: 10 });
  const keyHash = keys.hashKey("2222222222222222");
  const saved = process.env.CORE_ALLOW_CLIENT_HASH;
  try {
    delete process.env.CORE_ALLOW_CLIENT_HASH;
    await assert.rejects(
      () => registry.redeemVoucher(store, { code, keyHash }),
      (e) => e.code === "CLIENT_HASH_DISABLED"
    );
    process.env.CORE_ALLOW_CLIENT_HASH = "1";
    const out = await registry.redeemVoucher(store, { code, keyHash });
    assert.equal(out.keyHash, keyHash);
    assert.equal(out.key, undefined, "raw key is never returned in hash mode");
    assert.equal((await store.read()).keys[keyHash].credits, 10);
  } finally {
    if (saved === undefined) delete process.env.CORE_ALLOW_CLIENT_HASH;
    else process.env.CORE_ALLOW_CLIENT_HASH = saved;
  }
});

test("redeem tops up an existing key hash", async () => {
  const store = new MemoryStore();
  const created = await registry.createKey(store, { credits: 5 });
  const { code } = await registry.createVoucher(store, { credits: 20 });
  const out = await registry.redeemVoucher(store, { code, key: created.key });
  assert.equal(out.keyHash, created.keyHash);
  assert.equal(out.credits, 25);
});

/* ---------- privacy / proxy ---------- */
test("routeTemplate strips query strings and identifiers", () => {
  assert.equal(routeTemplate("/v1/instagram/kametolol/posts?limit=12&cursor=SECRET"), "/v1/instagram/:id/posts");
  assert.equal(routeTemplate("/v1/linkedin/jobs/4486054169?keywords=python"), "/v1/linkedin/jobs/:id");
  assert.equal(routeTemplate("/v1/keys/" + "a".repeat(64)), "/v1/keys/:hash");
});

test("resolveUpstream maps services and rejects unknown ones", () => {
  const map = { instagram: "http://ig:3000", linkedin: "http://li:3002", tiktok: "http://tt:3001" };
  assert.equal(resolveUpstream("/v1/instagram/kametolol/posts", map).base, "http://ig:3000");
  assert.equal(resolveUpstream("/v1/linkedin/jobs/search", map).service, "linkedin");
  assert.equal(resolveUpstream("/v1/unknown/x", map), null);
  assert.equal(resolveUpstream("/health", map), null);
});

test("forwardHeaders strips gateway credentials and hop-by-hop headers", () => {
  const out = forwardHeaders({
    headers: {
      "x-api-key": "1234567890123456",
      "x-admin-token": "secret",
      cookie: "li_at=abc",
      host: "localhost:9000",
      "content-length": "12",
      accept: "application/json",
    },
  });
  assert.equal(out["x-api-key"], undefined);
  assert.equal(out["x-admin-token"], undefined);
  assert.equal(out.cookie, undefined);
  assert.equal(out.host, undefined);
  assert.equal(out["content-length"], undefined);
  assert.equal(out.accept, "application/json");
  assert.equal(out["X-Forwarded-By"], "api-everything-core");
});

test("GatewayError carries a hint and a status", () => {
  const err = new GatewayError("NO_CREDITS", "empty", 402);
  assert.equal(err.status, 402);
  assert.match(err.hint, /voucher/i);
});
