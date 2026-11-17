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
const { resolveUpstream, forwardHeaders } = require("../core/proxy");
const { GatewayError } = require("../core/errors");
const { SignupLimiter, signup, starterCredits, addressHash } = require("../core/signup");

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
