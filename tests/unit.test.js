"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const keys = require("../core/keys");
const { MemoryStore, FileStore, normalize } = require("../core/store");
const ledger = require("../core/ledger");
const { RateLimiter } = require("../core/ratelimit");
const registry = require("../core/registry");
const { routeTemplate } = require("../core/logger");
const { resolveUpstream, forwardHeaders, upstreams } = require("../core/proxy");
const { GatewayError } = require("../core/errors");
const { SignupLimiter, signup, starterCredits, addressHash } = require("../core/signup");
const { ResponseCache, cacheKey, shouldBypassCache } = require("../core/cache");
const { PaymentBridge, verifyWebhookSignature, verifyNowPaymentsSignature, sortObject, DEFAULT_PACKS } = require("../core/payments");
const { parseSimpleYaml, loadGatewaySpec, buildUnifiedOpenApi, resetOpenApiCache } = require("../core/openapi-merge");
const crypto = require("node:crypto");

/* ---------- two credential classes ---------- */
test("unlock codes are 16 digits and unique", () => {
  const set = new Set();
  for (let i = 0; i < 300; i += 1) {
    const code = keys.generateUnlockCode();
    assert.match(code, /^\d{16}$/);
    set.add(code);
  }
  assert.equal(set.size, 300);
});

test("API keys are ae_ + 48 hex and unique", () => {
  const set = new Set();
  for (let i = 0; i < 200; i += 1) {
    const k = keys.generateApiKey();
    assert.match(k, /^ae_[a-f0-9]{48}$/);
    set.add(k);
  }
  assert.equal(set.size, 200);
});

test("hashKey is deterministic and never contains the raw credential", () => {
  for (const raw of ["1234567890123456", keys.generateApiKey()]) {
    const hash = keys.hashKey(raw);
    assert.match(hash, /^[a-f0-9]{64}$/);
    assert.equal(keys.hashKey(raw), hash);
    assert.ok(!hash.includes(raw));
  }
});

test("the 16-digit unlock code is NEVER accepted as an API key", () => {
  assert.doesNotThrow(() => keys.assertUnlockCodeFormat("1234567890123456"));
  assert.throws(() => keys.assertUnlockCodeFormat("1234"), (e) => e.code === "INVALID_UNLOCK_CODE");
  assert.doesNotThrow(() => keys.assertApiKeyFormat(keys.generateApiKey()));
  assert.throws(
    () => keys.assertApiKeyFormat("1234567890123456"),
    (e) => e instanceof GatewayError && e.code === "UNLOCK_CODE_NOT_API_KEY" && e.status === 401
  );
  assert.throws(() => keys.assertApiKeyFormat("ae_nope"), (e) => e.code === "INVALID_KEY");
});

test("hash format assertion", () => {
  assert.doesNotThrow(() => keys.assertHashFormat("a".repeat(64)));
  assert.throws(() => keys.assertHashFormat("xyz"), (e) => e.code === "BAD_KEYHASH");
});

test("timingSafeEqual rejects different lengths and values", () => {
  assert.equal(keys.timingSafeEqual("abc", "abc"), true);
  assert.equal(keys.timingSafeEqual("abc", "abd"), false);
  assert.equal(keys.timingSafeEqual("abc", "abcd"), false);
});

test("masks never reveal the credential", () => {
  assert.equal(keys.maskUnlockCode("1234567890123456"), "•••• •••• •••• 3456");
  assert.ok(!keys.maskUnlockCode("1234567890123456").includes("9012"));
  const apiKey = `ae_${"a".repeat(48)}`;
  assert.equal(keys.maskApiKey(apiKey), "ae_••••aaaaaa");
  assert.ok(!keys.maskApiKey(apiKey).includes("a".repeat(48)));
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
  await store.write((s) => { s.accounts.abc = { credits: 10 }; return s; });
  assert.equal((await store.read()).accounts.abc.credits, 10);
});

test("FileStore persists atomically and stores no raw credential", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "core-store-"));
  const file = path.join(dir, "keys.json");
  const unlockCode = "9876543210987654";
  const apiKey = keys.generateApiKey();
  const accountHash = keys.hashKey(unlockCode);
  const keyHash = keys.hashKey(apiKey);
  try {
    const store = new FileStore(file);
    await store.write((s) => {
      s.accounts[accountHash] = { credits: 123, createdAt: "x", expiresAt: null, revoked: false };
      s.apiKeys[keyHash] = { accountHash, name: "default", createdAt: "x", lastUsedAt: null, revoked: false };
      return s;
    });
    const text = fs.readFileSync(file, "utf8");
    assert.ok(!text.includes(unlockCode), "raw unlock code must never be written");
    assert.ok(!text.includes(apiKey), "raw API key must never be written");
    assert.ok(!/"ip"|"email"|"query"|"history"/i.test(text));
    const again = await new FileStore(file).read();
    assert.equal(again.accounts[accountHash].credits, 123);
    assert.equal(again.apiKeys[keyHash].accountHash, accountHash);
    assert.equal(fs.existsSync(`${file}.tmp`), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("v1 databases migrate in place: old keys become accounts", () => {
  const hash = keys.hashKey("1111111111111111");
  const migrated = normalize({
    version: 1,
    keys: { [hash]: { credits: 42, createdAt: "old", expiresAt: null, revoked: false } },
    vouchers: {},
  });
  assert.equal(migrated.version, 2);
  assert.equal(migrated.accounts[hash].credits, 42);
  assert.equal(Object.keys(migrated.apiKeys).length, 0, "no API key is minted by the migration");
  assert.equal(migrated.keys, undefined);
});

test("concurrent debits are serialized and never lose a decrement", async () => {
  const store = new MemoryStore();
  const hash = keys.hashKey("1111111111111111");
  await store.write((s) => { s.accounts[hash] = { credits: 50 }; return s; });
  await Promise.all(Array.from({ length: 25 }, () =>
    store.write((s) => { s.accounts[hash].credits -= 1; return s; })
  ));
  assert.equal((await store.read()).accounts[hash].credits, 25);
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

/* ---------- accounts and API keys ---------- */
test("createAccount returns the unlock code once and stores only its hash", async () => {
  const store = new MemoryStore();
  const created = await registry.createAccount(store, { credits: 5000 });
  assert.match(created.unlockCode, /^\d{16}$/);
  const state = await store.read();
  assert.equal(state.accounts[created.accountHash].credits, 5000);
  assert.equal(state.accounts[created.unlockCode], undefined);
  assert.equal(Object.keys(state.apiKeys).length, 0);
  const list = await registry.listAccounts(store);
  assert.ok(!JSON.stringify(list).includes(created.unlockCode));
});

test("resolveAccountByUnlock accepts only a 16-digit code", async () => {
  const store = new MemoryStore();
  const { unlockCode, accountHash } = await registry.createAccount(store, { credits: 10 });
  const found = await registry.resolveAccountByUnlock(store, unlockCode);
  assert.equal(found.accountHash, accountHash);
  await assert.rejects(
    () => registry.resolveAccountByUnlock(store, keys.generateApiKey()),
    (e) => e.code === "INVALID_UNLOCK_CODE"
  );
  await assert.rejects(
    () => registry.resolveAccountByUnlock(store, "0000000000000000"),
    (e) => e.code === "INVALID_UNLOCK_CODE"
  );
});

test("createApiKey returns the key once and the list is sanitized", async () => {
  const store = new MemoryStore();
  const { unlockCode, accountHash } = await registry.createAccount(store, { credits: 100 });
  const created = await registry.createApiKey(store, accountHash, { name: "laptop" });
  assert.match(created.apiKey, /^ae_[a-f0-9]{48}$/);
  const state = await store.read();
  assert.equal(state.apiKeys[created.keyHash].name, "laptop");
  assert.equal(state.apiKeys[created.apiKey], undefined);
  const list = await registry.listApiKeys(store, accountHash);
  assert.equal(list.length, 1);
  assert.equal(list[0].keyId, created.keyHash);
  assert.ok(list[0].hint.startsWith("ae_…"));
  assert.ok(!JSON.stringify(list).includes(created.apiKey));
  assert.ok(!JSON.stringify(list).includes(unlockCode));
});

test("rotating a key revokes the old one and keeps the same credits", async () => {
  const store = new MemoryStore();
  const { accountHash } = await registry.createAccount(store, { credits: 100 });
  const first = await registry.createApiKey(store, accountHash);
  const rotated = await registry.resetApiKey(store, accountHash, first.keyHash);
  assert.match(rotated.apiKey, /^ae_[a-f0-9]{48}$/);
  assert.equal((await store.read()).apiKeys[first.keyHash].revoked, true);
  await assert.rejects(
    () => registry.resolveAccountByApiKey(store, first.apiKey),
    (e) => e.code === "KEY_REVOKED"
  );
  const found = await registry.resolveAccountByApiKey(store, rotated.apiKey);
  assert.equal(found.accountHash, accountHash);
  assert.equal(found.account.credits, 100);
});

test("several API keys share one account balance", async () => {
  const store = new MemoryStore();
  const { accountHash } = await registry.createAccount(store, { credits: 50 });
  const a = await registry.createApiKey(store, accountHash, { name: "ci" });
  const b = await registry.createApiKey(store, accountHash, { name: "prod" });
  const foundA = await registry.resolveAccountByApiKey(store, a.apiKey);
  const foundB = await registry.resolveAccountByApiKey(store, b.apiKey);
  assert.equal(foundA.accountHash, foundB.accountHash);
  assert.equal(foundA.account.credits, 50);
});

test("revoke checks ownership and reset-all revokes every active key", async () => {
  const store = new MemoryStore();
  const { accountHash } = await registry.createAccount(store, { credits: 50 });
  const other = await registry.createAccount(store, { credits: 50 });
  const a = await registry.createApiKey(store, accountHash);
  const b = await registry.createApiKey(store, accountHash);
  const foreign = await registry.createApiKey(store, other.accountHash);
  await assert.rejects(
    () => registry.revokeApiKey(store, accountHash, foreign.keyHash),
    (e) => e.code === "KEY_NOT_FOUND"
  );
  await registry.revokeApiKey(store, accountHash, b.keyHash);
  const reset = await registry.resetAllApiKeys(store, accountHash);
  const state = await store.read();
  assert.equal(state.apiKeys[a.keyHash].revoked, true);
  assert.equal(state.apiKeys[b.keyHash].revoked, true);
  assert.equal(state.apiKeys[foreign.keyHash].revoked, false, "other account untouched");
  assert.equal(state.apiKeys[reset.keyHash].revoked, false);
  assert.equal((await registry.listApiKeys(store, accountHash)).filter((k) => !k.revoked).length, 1);
});

test("CORE_MAX_API_KEYS caps keys per account", async () => {
  const saved = process.env.CORE_MAX_API_KEYS;
  const store = new MemoryStore();
  const { accountHash } = await registry.createAccount(store, { credits: 50 });
  try {
    process.env.CORE_MAX_API_KEYS = "2";
    await registry.createApiKey(store, accountHash);
    await registry.createApiKey(store, accountHash);
    await assert.rejects(
      () => registry.createApiKey(store, accountHash),
      (e) => e.code === "TOO_MANY_KEYS"
    );
    await registry.revokeApiKey(store, accountHash, (await registry.listApiKeys(store, accountHash))[0].keyId);
    await assert.doesNotReject(() => registry.createApiKey(store, accountHash));
  } finally {
    if (saved === undefined) delete process.env.CORE_MAX_API_KEYS;
    else process.env.CORE_MAX_API_KEYS = saved;
  }
});

/* ---------- vouchers ---------- */
test("voucher redeem credits an account and cannot be replayed", async () => {
  const store = new MemoryStore();
  const { unlockCode, accountHash } = await registry.createAccount(store, { credits: 10 });
  const { code } = await registry.createVoucher(store, { credits: 100 });
  const redeemed = await registry.redeemVoucher(store, { code, unlockCode });
  assert.equal(redeemed.accountHash, accountHash);
  assert.equal(redeemed.credits, 110);
  await assert.rejects(
    () => registry.redeemVoucher(store, { code, unlockCode }),
    (e) => e.code === "BAD_VOUCHER"
  );
});

test("redeem accepts an API key, a legacy `key` alias, or creates an account", async () => {
  const store = new MemoryStore();
  const { unlockCode, accountHash } = await registry.createAccount(store, { credits: 5 });
  const apiKey = (await registry.createApiKey(store, accountHash)).apiKey;

  const byApi = await registry.createVoucher(store, { credits: 10 });
  assert.equal((await registry.redeemVoucher(store, { code: byApi.code, apiKey })).credits, 15);

  const legacy = await registry.createVoucher(store, { credits: 20 });
  assert.equal((await registry.redeemVoucher(store, { code: legacy.code, key: unlockCode })).credits, 35);

  const fresh = await registry.createVoucher(store, { credits: 7 });
  const created = await registry.redeemVoucher(store, { code: fresh.code });
  assert.match(created.unlockCode, /^\d{16}$/);
  assert.equal(created.credits, 7);
});

test("redeem with a client-provided account hash is gated", async () => {
  const store = new MemoryStore();
  const { code } = await registry.createVoucher(store, { credits: 10 });
  const accountHash = keys.hashKey("2222222222222222");
  const saved = process.env.CORE_ALLOW_CLIENT_HASH;
  try {
    delete process.env.CORE_ALLOW_CLIENT_HASH;
    await assert.rejects(
      () => registry.redeemVoucher(store, { code, accountHash }),
      (e) => e.code === "CLIENT_HASH_DISABLED"
    );
    process.env.CORE_ALLOW_CLIENT_HASH = "1";
    const out = await registry.redeemVoucher(store, { code, accountHash });
    assert.equal(out.accountHash, accountHash);
    assert.equal(out.unlockCode, undefined);
    assert.equal((await store.read()).accounts[accountHash].credits, 10);
  } finally {
    if (saved === undefined) delete process.env.CORE_ALLOW_CLIENT_HASH;
    else process.env.CORE_ALLOW_CLIENT_HASH = saved;
  }
});

/* ---------- privacy / proxy ---------- */
test("routeTemplate strips query strings and identifiers", () => {
  assert.equal(routeTemplate("/v1/instagram/kametolol/posts?limit=12&cursor=SECRET"), "/v1/instagram/:id/posts");
  assert.equal(routeTemplate("/v1/linkedin/jobs/4486054169?keywords=python"), "/v1/linkedin/jobs/:id");
  assert.equal(routeTemplate("/v1/keys/" + "a".repeat(64)), "/v1/keys/:hash");
  assert.equal(routeTemplate("/v1/admin/accounts/" + "a".repeat(64) + "/topup"), "/v1/admin/accounts/:hash/topup");
});

test("resolveUpstream maps services and rejects unknown ones", () => {
  const map = { instagram: "http://ig:3000", linkedin: "http://li:3002", tiktok: "http://tt:3001" };
  assert.equal(resolveUpstream("/v1/instagram/kametolol/posts", map).base, "http://ig:3000");
  assert.equal(resolveUpstream("/v1/linkedin/jobs/search", map).service, "linkedin");
  assert.equal(resolveUpstream("/v1/unknown/x", map), null);
  assert.equal(resolveUpstream("/health", map), null);
});

test("forwardHeaders strips BOTH gateway credentials and hop-by-hop headers", () => {
  const out = forwardHeaders({
    headers: {
      "x-api-key": keys.generateApiKey(),
      "x-unlock-code": "1234567890123456",
      "x-admin-token": "secret",
      cookie: "li_at=abc",
      host: "localhost:9000",
      "content-length": "12",
      accept: "application/json",
    },
  });
  assert.equal(out["x-api-key"], undefined);
  assert.equal(out["x-unlock-code"], undefined);
  assert.equal(out["x-admin-token"], undefined);
  assert.equal(out.cookie, undefined);
  assert.equal(out.host, undefined);
  assert.equal(out["content-length"], undefined);
  assert.equal(out.accept, "application/json");
  assert.equal(out["X-Forwarded-By"], "api-everything-core");
});

test("GatewayError hints explain the unlock-code/API-key split", () => {
  const err = new GatewayError("UNLOCK_CODE_NOT_API_KEY", "nope", 401);
  assert.equal(err.status, 401);
  assert.match(err.hint, /API key/i);
  assert.match(new GatewayError("NO_CREDITS", "empty", 402).hint, /voucher/i);
});

/* ---------- public signup (PayAsYouGo) ---------- */
test("signup mints an unlock code (not an API key) with no expiry", async () => {
  const store = new MemoryStore();
  const limiter = new SignupLimiter(5);
  const req = { headers: {}, socket: { remoteAddress: "203.0.113.7" } };
  const result = await signup(store, limiter, req);
  assert.match(result.unlockCode, /^\d{16}$/);
  assert.equal(result.key, undefined, "signup must never return an API key");
  assert.equal(result.model, "pay_as_you_go");
  assert.equal(result.expiresAt, null, "no monthly expiry");
  assert.equal(result.credits, 50);
  assert.match(result.notice, /NOT an API key/i);
  const state = await store.read();
  assert.equal(state.accounts[result.accountHash].credits, 50);
  assert.equal(state.accounts[result.unlockCode], undefined);
  assert.equal(Object.keys(state.apiKeys).length, 0, "no API key exists until unlocked");
});

test("signup is rate limited per network", async () => {
  const store = new MemoryStore();
  const limiter = new SignupLimiter(2);
  const req = { headers: {}, socket: { remoteAddress: "198.51.100.2" } };
  await signup(store, limiter, req);
  await signup(store, limiter, req);
  await assert.rejects(() => signup(store, limiter, req), (e) => e.code === "RATE_LIMITED");
});

test("addressHash is a salted digest that never contains the raw address", () => {
  const req = { headers: { "x-forwarded-for": "192.0.2.44" }, socket: {} };
  const hash = addressHash(req);
  assert.match(hash, /^[a-f0-9]{64}$/);
  assert.ok(!hash.includes("192.0.2.44"));
});

test("starterCredits is configurable and bounded", () => {
  const saved = process.env.CORE_STARTER_CREDITS;
  try {
    process.env.CORE_STARTER_CREDITS = "125";
    assert.equal(starterCredits(), 125);
    process.env.CORE_STARTER_CREDITS = "-4";
    assert.equal(starterCredits(), 50);
  } finally {
    if (saved === undefined) delete process.env.CORE_STARTER_CREDITS;
    else process.env.CORE_STARTER_CREDITS = saved;
  }
});

/* ---------- YouTube upstream & weighted costs ---------- */
test("YouTube upstream defaults to port 3003 and weights feeds/search/transcripts at 2 credits", () => {
  const savedUpstreams = process.env.CORE_UPSTREAMS;
  const savedYt = process.env.CORE_YOUTUBE_URL;
  try {
    delete process.env.CORE_UPSTREAMS;
    delete process.env.CORE_YOUTUBE_URL;
    assert.equal(upstreams().youtube, "http://127.0.0.1:3003");
    process.env.CORE_YOUTUBE_URL = "http://yt-box:4321";
    assert.equal(upstreams().youtube, "http://yt-box:4321");
  } finally {
    if (savedUpstreams === undefined) delete process.env.CORE_UPSTREAMS;
    else process.env.CORE_UPSTREAMS = savedUpstreams;
    if (savedYt === undefined) delete process.env.CORE_YOUTUBE_URL;
    else process.env.CORE_YOUTUBE_URL = savedYt;
  }

  assert.equal(ledger.costFor("/v1/youtube/@mkbhd/posts"), 2);
  assert.equal(ledger.costFor("/v1/youtube/mkbhd/posts?limit=12"), 2);
  assert.equal(ledger.costFor("/v1/youtube/search?q=open+source"), 2);
  assert.equal(ledger.costFor("/v1/youtube/videos/dQw4w9WgXcQ/transcript?lang=en"), 2);
  assert.equal(ledger.costFor("/v1/youtube/@mkbhd"), 1);
  assert.equal(ledger.costFor("/v1/youtube/videos/dQw4w9WgXcQ"), 1);

  assert.equal(routeTemplate("/v1/youtube/@mkbhd/posts?limit=2"), "/v1/youtube/:id/posts");
  assert.equal(routeTemplate("/v1/youtube/search?q=secret"), "/v1/youtube/search");
  assert.equal(routeTemplate("/v1/youtube/videos/dQw4w9WgXcQ/transcript?lang=en"), "/v1/youtube/videos/:id/transcript");
  assert.equal(routeTemplate("/v1/payments/invoices/inv_1234567890abcdef12345678"), "/v1/payments/invoices/:id");
  assert.equal(routeTemplate("/v1/payments/sandbox/inv_1234567890abcdef12345678/settle"), "/v1/payments/sandbox/:id/settle");
});

/* ---------- privacy-first RAM cache + coalescing ---------- */
test("cacheKey hashes method + path + query and never retains raw URLs in memory", async () => {
  const k1 = cacheKey("GET", "/v1/youtube/search", "?q=private+query");
  const k2 = cacheKey("HEAD", "/v1/youtube/search", "?q=private+query");
  assert.match(k1, /^[a-f0-9]{64}$/);
  assert.notEqual(k1, k2);
  assert.ok(!k1.includes("private"));

  const c = new ResponseCache({ enabled: true, ttlMs: 5000, maxEntries: 10 });
  await c.resolve({
    method: "GET",
    pathname: "/v1/youtube/search",
    search: "?q=supersecret",
    loader: async () => ({ status: 200, body: '{"items":[1]}', contentType: "application/json" }),
  });
  const dump = JSON.stringify([...c.entries.entries()]);
  assert.ok(!dump.includes("supersecret"));
  assert.ok(!dump.includes("/v1/youtube"));
});

test("ResponseCache MISS -> HIT, Cache-Control BYPASS, TTL expiry and LRU eviction", async () => {
  let clock = 10_000;
  let calls = 0;
  const c = new ResponseCache({ enabled: true, ttlMs: 1000, maxEntries: 2, now: () => clock });
  const loader = async () => {
    calls += 1;
    return { status: 200, body: JSON.stringify({ call: calls }), contentType: "application/json" };
  };

  const first = await c.resolve({ method: "GET", pathname: "/v1/instagram/a", loader });
  assert.equal(first.xCache, "MISS");
  assert.equal(calls, 1);

  const second = await c.resolve({ method: "GET", pathname: "/v1/instagram/a", loader });
  assert.equal(second.xCache, "HIT");
  assert.equal(second.response.body, '{"call":1}');
  assert.equal(calls, 1);

  assert.equal(shouldBypassCache("no-cache"), true);
  assert.equal(shouldBypassCache("max-age=0, no-store"), true);
  const bypassed = await c.resolve({
    method: "GET",
    pathname: "/v1/instagram/a",
    cacheControl: "no-cache",
    loader,
  });
  assert.equal(bypassed.xCache, "BYPASS");
  assert.equal(bypassed.response.body, '{"call":2}');
  assert.equal(calls, 2);

  // Fresh value from BYPASS updated the cache.
  const hitUpdated = await c.resolve({ method: "GET", pathname: "/v1/instagram/a", loader });
  assert.equal(hitUpdated.xCache, "HIT");
  assert.equal(hitUpdated.response.body, '{"call":2}');

  // LRU eviction when maxEntries = 2: insert b, touch a, insert c -> b is evicted.
  await c.resolve({ method: "GET", pathname: "/v1/instagram/b", loader });
  await c.resolve({ method: "GET", pathname: "/v1/instagram/a", loader }); // refresh a
  await c.resolve({ method: "GET", pathname: "/v1/instagram/c", loader }); // evicts b
  assert.equal(c.stats().entries, 2);
  const aStillHit = await c.resolve({ method: "GET", pathname: "/v1/instagram/a", loader });
  assert.equal(aStillHit.xCache, "HIT");
  const bMiss = await c.resolve({ method: "GET", pathname: "/v1/instagram/b", loader });
  assert.equal(bMiss.xCache, "MISS");

  // TTL expiry evicts stale entries.
  clock += 2000;
  assert.equal(c.stats().entries, 0);
});

test("ResponseCache coalesces 10 concurrent misses into 1 upstream call", async () => {
  const c = new ResponseCache({ enabled: true, ttlMs: 60_000, maxEntries: 50 });
  let upstreamHits = 0;
  const loader = async () => {
    upstreamHits += 1;
    await new Promise((r) => setTimeout(r, 20));
    return { status: 200, body: '{"videos":[{"id":"v1"}]}', contentType: "application/json" };
  };

  const results = await Promise.all(
    Array.from({ length: 10 }, () =>
      c.resolve({ method: "GET", pathname: "/v1/youtube/@mkbhd/posts", search: "?limit=2", loader })
    )
  );
  assert.equal(upstreamHits, 1, "forward() must execute exactly ONCE");
  const states = results.map((r) => r.xCache);
  assert.equal(states.filter((s) => s === "MISS").length, 1);
  assert.equal(states.filter((s) => s === "COALESCED").length, 9);

  const followUp = await c.resolve({ method: "GET", pathname: "/v1/youtube/@mkbhd/posts", search: "?limit=2", loader });
  assert.equal(followUp.xCache, "HIT");
  assert.equal(upstreamHits, 1);
  assert.deepEqual(c.stats(), {
    enabled: true,
    entries: 1,
    maxEntries: 50,
    ttlMs: 60_000,
    hits: 1,
    misses: 1,
    coalesced: 9,
  });
});

test("ResponseCache never caches non-billable responses, POSTs, or when disabled", async () => {
  const c = new ResponseCache({ enabled: true, ttlMs: 60_000, maxEntries: 10 });
  let hits = 0;
  await c.resolve({
    method: "GET",
    pathname: "/v1/tiktok/x/posts",
    loader: async () => { hits += 1; return { status: 429, body: '{"error":{"code":"RATE"}}', contentType: "application/json" }; },
  });
  await c.resolve({
    method: "GET",
    pathname: "/v1/tiktok/x/posts",
    loader: async () => { hits += 1; return { status: 200, body: '{"error":{"code":"BAD"}}', contentType: "application/json" }; },
  });
  assert.equal(hits, 2);
  assert.equal(c.stats().entries, 0);

  const postRes = await c.resolve({
    method: "POST",
    pathname: "/v1/instagram/x",
    loader: async () => ({ status: 200, body: '{"ok":true}', contentType: "application/json" }),
  });
  assert.equal(postRes.xCache, "BYPASS");
  assert.equal(c.stats().entries, 0);

  const disabled = new ResponseCache({ enabled: false });
  const offRes = await disabled.resolve({
    method: "GET",
    pathname: "/v1/instagram/x",
    loader: async () => ({ status: 200, body: '{"ok":true}', contentType: "application/json" }),
  });
  assert.equal(offRes.xCache, "BYPASS");
});

/* ---------- payments -> voucher bridge ---------- */
test("PaymentBridge disabled by default and blocks sandbox settle when CORE_PAYMENT_SANDBOX=0", async () => {
  const savedSandbox = process.env.CORE_PAYMENT_SANDBOX;
  const savedUrl = process.env.CORE_BTCPAY_URL;
  const store = new MemoryStore();
  const bridge = new PaymentBridge();
  try {
    delete process.env.CORE_BTCPAY_URL;
    process.env.CORE_PAYMENT_SANDBOX = "0";
    const packs = bridge.listPacks();
    assert.equal(packs.enabled, false);
    assert.equal(packs.mode, "disabled");
    assert.equal(packs.packs.length, DEFAULT_PACKS.length);

    await assert.rejects(() => bridge.checkout({ packId: "pack_1k" }), (e) => e.code === "PAYMENTS_DISABLED" && e.status === 503);
    await assert.rejects(() => bridge.sandboxSettle(store, "inv_" + "a".repeat(24)), (e) => e.code === "SANDBOX_DISABLED" && e.status === 403);
  } finally {
    if (savedSandbox === undefined) delete process.env.CORE_PAYMENT_SANDBOX;
    else process.env.CORE_PAYMENT_SANDBOX = savedSandbox;
    if (savedUrl === undefined) delete process.env.CORE_BTCPAY_URL;
    else process.env.CORE_BTCPAY_URL = savedUrl;
  }
});

test("PaymentBridge sandbox checkout -> idempotent settle -> voucher redeem stays zero-identity", async () => {
  const savedSandbox = process.env.CORE_PAYMENT_SANDBOX;
  const store = new MemoryStore();
  let now = 50_000;
  const bridge = new PaymentBridge({ maxInvoices: 3, ttlMs: 3_600_000, now: () => now });
  try {
    process.env.CORE_PAYMENT_SANDBOX = "1";
    await assert.rejects(() => bridge.checkout({ packId: "nope" }), (e) => e.code === "BAD_PACK" && e.status === 400);

    const inv = await bridge.checkout({ packId: "pack_1k" });
    assert.match(inv.invoiceId, /^inv_[a-f0-9]{24}$/);
    assert.equal(inv.mode, "sandbox");
    assert.equal(inv.status, "pending");
    assert.equal(inv.checkoutUrl, null);

    const pending = bridge.getInvoice(inv.invoiceId);
    assert.equal(pending.voucherCode, null);

    // Concurrent settle calls mint only ONE voucher.
    const [s1, s2] = await Promise.all([
      bridge.sandboxSettle(store, inv.invoiceId),
      bridge.sandboxSettle(store, inv.invoiceId),
    ]);
    assert.equal(s1.status, "settled");
    assert.equal(s1.credits, 1000);
    assert.equal(s1.voucherCode, s2.voucherCode);
    assert.equal(Object.keys((await store.read()).vouchers).length, 1);

    // Turning off sandbox immediately blocks settle even for existing invoices.
    process.env.CORE_PAYMENT_SANDBOX = "0";
    await assert.rejects(() => bridge.sandboxSettle(store, inv.invoiceId), (e) => e.code === "SANDBOX_DISABLED" && e.status === 403);

    // Voucher redeems cleanly into an account, and store never contains invoiceId.
    const { unlockCode } = await registry.createAccount(store, { credits: 25 });
    const redeemed = await registry.redeemVoucher(store, { code: s1.voucherCode, unlockCode });
    assert.equal(redeemed.credits, 1025);
    assert.ok(!JSON.stringify(await store.read()).includes(inv.invoiceId));

    // After 1h TTL, invoice vanishes from memory.
    now += 3_600_001;
    assert.throws(() => bridge.getInvoice(inv.invoiceId), (e) => e.code === "INVOICE_NOT_FOUND" && e.status === 404);
  } finally {
    if (savedSandbox === undefined) delete process.env.CORE_PAYMENT_SANDBOX;
    else process.env.CORE_PAYMENT_SANDBOX = savedSandbox;
  }
});

test("PaymentBridge BTCPay checkout and HMAC-SHA256 webhook verification", async () => {
  const savedEnv = {
    url: process.env.CORE_BTCPAY_URL,
    storeId: process.env.CORE_BTCPAY_STORE_ID,
    apiKey: process.env.CORE_BTCPAY_API_KEY,
    secret: process.env.CORE_WEBHOOK_SECRET,
  };
  const store = new MemoryStore();
  let posted = null;
  const mockHttp = {
    post: async (url, data, cfg) => {
      posted = { url, data, headers: cfg.headers };
      return { status: 200, data: { id: "btcpay_99", checkoutLink: "https://pay.example/i/btcpay_99" } };
    },
  };
  const bridge = new PaymentBridge({ httpClient: mockHttp });

  try {
    process.env.CORE_BTCPAY_URL = "https://pay.example";
    process.env.CORE_BTCPAY_STORE_ID = "store_1";
    process.env.CORE_BTCPAY_API_KEY = "secret_key";
    delete process.env.CORE_WEBHOOK_SECRET;

    const checkout = await bridge.checkout({ packId: "pack_5k" });
    assert.equal(checkout.mode, "btcpay");
    assert.equal(checkout.checkoutUrl, "https://pay.example/i/btcpay_99");
    assert.equal(posted.headers.Authorization, "token secret_key");
    assert.equal(posted.data.metadata.invoiceId, checkout.invoiceId);
    assert.equal(posted.data.metadata.credits, 5000);

    // Webhook fail-closed without CORE_WEBHOOK_SECRET.
    const rawBody = Buffer.from(JSON.stringify({
      type: "InvoiceSettled",
      invoiceId: "btcpay_99",
      metadata: { invoiceId: checkout.invoiceId, packId: "pack_5k", credits: 5000 },
    }, null, 2));
    await assert.rejects(() => bridge.handleWebhook(store, rawBody, "sha256=" + "0".repeat(64)), (e) => e.code === "WEBHOOK_DISABLED" && e.status === 503);

    process.env.CORE_WEBHOOK_SECRET = "whsec_test_123";
    await assert.rejects(() => bridge.handleWebhook(store, rawBody, "sha256=" + "f".repeat(64)), (e) => e.code === "INVALID_SIGNATURE" && e.status === 401);
    assert.throws(() => verifyWebhookSignature(rawBody, "badheader", "whsec_test_123"), (e) => e.code === "INVALID_SIGNATURE");

    const sig = "sha256=" + crypto.createHmac("sha256", "whsec_test_123").update(rawBody).digest("hex");
    const first = await bridge.handleWebhook(store, rawBody, sig);
    const replay = await bridge.handleWebhook(store, rawBody, sig);
    assert.equal(first.settled, true);
    assert.equal(first.credits, 5000);
    assert.equal(first.voucherCode, replay.voucherCode, "webhook settlement must be idempotent");
    assert.equal(bridge.getInvoice(checkout.invoiceId).voucherCode, first.voucherCode);

    // Post-restart webhook: unknown invoiceId reconstructed from metadata.credits.
    const restartRaw = Buffer.from('{"type":"InvoicePaymentSettled","metadata":{"invoiceId":"inv_0123456789abcdef01234567","credits":20000}}');
    const restartSig = "sha256=" + crypto.createHmac("sha256", "whsec_test_123").update(restartRaw).digest("hex");
    const recovered = await bridge.handleWebhook(store, restartRaw, restartSig);
    assert.equal(recovered.credits, 20000);
    assert.equal(bridge.getInvoice("inv_0123456789abcdef01234567").voucherCode, recovered.voucherCode);
  } finally {
    for (const [k, envName] of [
      ["url", "CORE_BTCPAY_URL"],
      ["storeId", "CORE_BTCPAY_STORE_ID"],
      ["apiKey", "CORE_BTCPAY_API_KEY"],
      ["secret", "CORE_WEBHOOK_SECRET"],
    ]) {
      if (savedEnv[k] === undefined) delete process.env[envName];
      else process.env[envName] = savedEnv[k];
    }
  }
});

test("PaymentBridge NOWPayments checkout, sorted HMAC-SHA512 IPN, polling and restart recovery", async () => {
  const saved = {
    apiKey: process.env.CORE_NOWPAYMENTS_API_KEY,
    ipnSecret: process.env.CORE_NOWPAYMENTS_IPN_SECRET,
    webhookUrl: process.env.CORE_PUBLIC_WEBHOOK_URL,
  };
  const store = new MemoryStore();
  let posted = null;
  let pollStatus = "confirming";
  let clock = 10_000;
  const mockHttp = {
    post: async (url, data, cfg) => {
      posted = { url, data, headers: cfg.headers };
      return {
        status: 200,
        data: { id: "4328618452", order_id: data.order_id, invoice_url: "https://nowpayments.io/payment/?iid=4328618452" },
      };
    },
    get: async () => ({
      status: 200,
      data: { payment_id: 998877, payment_status: pollStatus },
    }),
  };
  const bridge = new PaymentBridge({ httpClient: mockHttp, now: () => clock });

  try {
    process.env.CORE_NOWPAYMENTS_API_KEY = "np_test_key_placeholder";
    process.env.CORE_PUBLIC_WEBHOOK_URL = "https://api.example/v1/payments/webhook";
    delete process.env.CORE_NOWPAYMENTS_IPN_SECRET;

    assert.equal(bridge.listPacks().mode, "nowpayments");
    const checkout = await bridge.checkout({ packId: "pack_1k" });
    assert.equal(checkout.mode, "nowpayments");
    assert.equal(checkout.checkoutUrl, "https://nowpayments.io/payment/?iid=4328618452");
    assert.equal(posted.headers["x-api-key"], "np_test_key_placeholder");
    assert.equal(posted.data.order_id, checkout.invoiceId);
    assert.equal(posted.data.is_fee_paid_by_user, true);
    assert.equal(posted.data.ipn_callback_url, "https://api.example/v1/payments/webhook");

    // Fail-closed without IPN secret
    const waitingBody = {
      payment_status: "waiting",
      payment_id: 998877,
      invoice_id: 4328618452,
      order_id: checkout.invoiceId,
      nested: { z: 1, a: 2 },
    };
    await assert.rejects(
      () => bridge.handleWebhook(store, Buffer.from(JSON.stringify(waitingBody)), { "x-nowpayments-sig": "0".repeat(128) }),
      (e) => e.code === "WEBHOOK_DISABLED" && e.status === 503
    );

    process.env.CORE_NOWPAYMENTS_IPN_SECRET = "ipn_secret_xyz";
    const signNp = (obj) =>
      crypto.createHmac("sha512", "ipn_secret_xyz").update(JSON.stringify(sortObject(obj))).digest("hex");

    // Invalid signature rejected
    await assert.rejects(
      () => bridge.handleWebhook(store, Buffer.from(JSON.stringify(waitingBody)), { "x-nowpayments-sig": "a".repeat(128) }),
      (e) => e.code === "INVALID_SIGNATURE" && e.status === 401
    );
    assert.ok(verifyNowPaymentsSignature(waitingBody, signNp(waitingBody), "ipn_secret_xyz"));

    // Non-settled IPN records providerPaymentId without minting a voucher
    const wRes = await bridge.handleWebhook(store, Buffer.from(JSON.stringify(waitingBody)), {
      "x-nowpayments-sig": signNp(waitingBody),
    });
    assert.equal(wRes.settled, false);
    assert.equal(bridge.getInvoice(checkout.invoiceId).voucherCode, null);

    // Polling GET /v1/payment/:id settles once status turns "finished"
    clock += 5_000;
    const stillPending = await bridge.refreshInvoice(store, checkout.invoiceId);
    assert.equal(stillPending.status, "pending");
    pollStatus = "finished";
    clock += 5_000;
    const settledViaPoll = await bridge.refreshInvoice(store, checkout.invoiceId);
    assert.equal(settledViaPoll.status, "settled");
    assert.ok(settledViaPoll.voucherCode);

    // Post-restart IPN recovery from order_description
    const restartPayload = {
      order_id: "inv_fedcba9876543210fedcba98",
      invoice_id: 777111,
      payment_id: 888222,
      payment_status: "finished",
      price_amount: 20,
      order_description: "API Everything — Builder (5000 credits)",
    };
    const rec = await bridge.handleWebhook(store, Buffer.from(JSON.stringify(restartPayload)), {
      "x-nowpayments-sig": signNp(restartPayload),
    });
    assert.equal(rec.settled, true);
    assert.equal(rec.credits, 5000);
    assert.ok(rec.voucherCode);
  } finally {
    if (saved.apiKey === undefined) delete process.env.CORE_NOWPAYMENTS_API_KEY;
    else process.env.CORE_NOWPAYMENTS_API_KEY = saved.apiKey;
    if (saved.ipnSecret === undefined) delete process.env.CORE_NOWPAYMENTS_IPN_SECRET;
    else process.env.CORE_NOWPAYMENTS_IPN_SECRET = saved.ipnSecret;
    if (saved.webhookUrl === undefined) delete process.env.CORE_PUBLIC_WEBHOOK_URL;
    else process.env.CORE_PUBLIC_WEBHOOK_URL = saved.webhookUrl;
  }
});

/* ---------- unified OpenAPI 3.0.3 ---------- */
test("Unified OpenAPI parses v0.3.0 spec, merges connector paths, and falls back offline", async () => {
  resetOpenApiCache();
  const base = loadGatewaySpec();
  assert.equal(base.openapi, "3.0.3");
  assert.equal(base.info.version, "0.3.0");
  assert.ok(base.paths["/v1/openapi.json"]);
  assert.ok(base.paths["/v1/payments/packs"]);
  assert.ok(base.paths["/v1/payments/webhook"]);
  const serviceParam = base.paths["/v1/{service}/{path}"].get.parameters.find((p) => p.name === "service");
  assert.ok(serviceParam.schema.enum.includes("youtube"));
  assert.ok(base.paths["/v1/{service}/{path}"].get.responses["200"].headers["X-Cache"]);

  const sampleYtYaml = [
    "openapi: 3.0.3",
    "info:",
    "  title: YouTube connector",
    "  version: 1.0.0",
    "paths:",
    "  /health:",
    "    get:",
    '      responses: { "200": { description: OK } }',
    "  /v1/youtube/{handle}/posts:",
    "    get:",
    "      summary: Channel videos",
    "      responses:",
    '        "200":',
    "          description: Videos",
    "          content:",
    "            application/json:",
    "              schema: { $ref: \"#/components/schemas/Video\" }",
    "components:",
    "  schemas:",
    "    Video:",
    "      type: object",
    "      properties:",
    "        videoId: { type: string }",
  ].join("\n");

  const parsedYt = parseSimpleYaml(sampleYtYaml);
  assert.equal(parsedYt.info.title, "YouTube connector");

  const merged = await buildUnifiedOpenApi({
    force: true,
    upstreamMap: {
      youtube: "http://127.0.0.1:19991",
      instagram: "http://127.0.0.1:19992",
    },
    httpClient: {
      get: async (url) => {
        if (url.includes("19991")) return { status: 200, data: sampleYtYaml };
        throw new Error("ECONNREFUSED");
      },
    },
  });

  assert.equal(merged.openapi, "3.0.3");
  assert.ok(merged.paths["/v1/youtube/{handle}/posts"]);
  assert.equal(merged.paths["/v1/youtube/{handle}/posts"].get["x-credits-cost"], 2);
  assert.ok(merged.components.schemas.YoutubeVideo);
  assert.deepEqual(merged["x-discovered-services"], ["youtube"]);
  assert.ok(!JSON.stringify(merged).includes("19991"), "must never leak internal upstream URLs");
  resetOpenApiCache();
});
