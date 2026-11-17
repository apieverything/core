"use strict";

/**
 * Account + API key + voucher registry.
 *
 * An account is opened by a 16-digit unlock code (stored only as its hash).
 * Inside it live zero or more API keys, each stored only as its hash. Credits
 * belong to the ACCOUNT, never to an individual key: rotating a key never
 * costs a credit, and several keys can share one balance.
 *
 * Vouchers are one-time bearer codes: the payment system issues them, the
 * gateway stores only their hash. There is no join key between a payment and
 * an account.
 */
const {
  generateUnlockCode, generateApiKey, hashKey,
  assertUnlockCodeFormat, assertApiKeyFormat, assertHashFormat,
  generateVoucherCode, hashVoucher,
} = require("./keys");
const { expiryFrom } = require("./ledger");
const { GatewayError } = require("./errors");

function creditsFrom(value, fallback = 5000) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 100000000) return fallback;
  return n;
}

function maxApiKeys() {
  const n = Number(process.env.CORE_MAX_API_KEYS ?? 20);
  return Number.isInteger(n) && n >= 1 && n <= 100 ? n : 20;
}

function safeName(name) {
  const s = String(name ?? "").replace(/[\x00-\x1f\x7f]/g, "").trim().slice(0, 40);
  return s || "default";
}

/* ------------------------------------------------------------------ accounts */

async function createAccount(store, { credits = 5000, expiresInDays = null } = {}) {
  const unlockCode = generateUnlockCode();
  const accountHash = hashKey(unlockCode);
  const record = {
    credits: creditsFrom(credits),
    createdAt: new Date().toISOString(),
    expiresAt: expiresInDays === null || expiresInDays === undefined
      ? null
      : expiryFrom(expiresInDays),
    revoked: false,
  };
  await store.write((state) => { state.accounts[accountHash] = record; return state; });
  // The raw unlock code is returned ONCE and never stored or logged.
  return { unlockCode, accountHash, ...record };
}

async function listAccounts(store) {
  const state = await store.read();
  return Object.entries(state.accounts).map(([accountHash, record]) => ({ accountHash, ...record }));
}

async function getAccount(store, accountHash) {
  assertHashFormat(accountHash);
  const state = await store.read();
  return state.accounts[accountHash] ?? null;
}

async function revokeAccount(store, accountHash) {
  assertHashFormat(accountHash);
  const result = await store.write((state) => {
    if (!state.accounts[accountHash]) return state;
    state.accounts[accountHash].revoked = true;
    for (const meta of Object.values(state.apiKeys)) {
      if (meta.accountHash === accountHash) meta.revoked = true;
    }
    return state;
  });
  if (!result.accounts[accountHash]) throw new GatewayError("INVALID_KEY", "Account not found.", 404);
  return { accountHash, revoked: true };
}

async function topUpAccount(store, accountHash, credits) {
  assertHashFormat(accountHash);
  const amount = creditsFrom(credits, 0);
  if (!amount) throw new GatewayError("BAD_REQUEST", "credits must be a positive integer.", 400);
  const result = await store.write((state) => {
    if (!state.accounts[accountHash]) return state;
    state.accounts[accountHash].credits += amount;
    return state;
  });
  if (!result.accounts[accountHash]) throw new GatewayError("INVALID_KEY", "Account not found.", 404);
  return { accountHash, credits: result.accounts[accountHash].credits };
}

/** Resolve an account from the 16-digit unlock code. Never accepts an API key. */
async function resolveAccountByUnlock(store, unlockCode) {
  assertUnlockCodeFormat(unlockCode);
  const accountHash = hashKey(unlockCode);
  const state = await store.read();
  const account = state.accounts[accountHash];
  if (!account) throw new GatewayError("INVALID_UNLOCK_CODE", "Unknown unlock code.", 401);
  if (account.revoked) throw new GatewayError("ACCOUNT_REVOKED", "This account is revoked.", 403);
  return { accountHash, account };
}

/** Resolve an account from an API key. Never accepts the 16-digit unlock code. */
async function resolveAccountByApiKey(store, apiKey) {
  assertApiKeyFormat(apiKey);
  const keyHash = hashKey(apiKey);
  const state = await store.read();
  const meta = state.apiKeys[keyHash];
  if (!meta) throw new GatewayError("INVALID_KEY", "Unknown API key.", 401);
  if (meta.revoked) throw new GatewayError("KEY_REVOKED", "API key revoked.", 403);
  const account = state.accounts[meta.accountHash];
  if (!account) throw new GatewayError("INVALID_KEY", "Unknown API key.", 401);
  if (account.revoked) throw new GatewayError("ACCOUNT_REVOKED", "This account is revoked.", 403);
  return { accountHash: meta.accountHash, account, keyHash, meta };
}

/* ------------------------------------------------------------------ API keys */

async function createApiKey(store, accountHash, { name = "default" } = {}) {
  assertHashFormat(accountHash);
  const apiKey = generateApiKey();
  const keyHash = hashKey(apiKey);
  const meta = {
    accountHash,
    name: safeName(name),
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
    revoked: false,
  };
  const result = await store.write((state) => {
    if (!state.accounts[accountHash]) throw new GatewayError("INVALID_KEY", "Account not found.", 404);
    const active = Object.values(state.apiKeys)
      .filter((m) => m.accountHash === accountHash && !m.revoked).length;
    if (active >= maxApiKeys()) {
      throw new GatewayError("TOO_MANY_KEYS", "Too many API keys on this account.", 409);
    }
    state.apiKeys[keyHash] = meta;
    return state;
  });
  if (!result.apiKeys[keyHash]) throw new GatewayError("INVALID_KEY", "Account not found.", 404);
  // The raw API key is returned ONCE and never stored or logged.
  return { apiKey, keyHash, ...meta, notice: "Save this API key now. It is shown once and can be reset anytime." };
}

/** Sanitized list: no raw key ever leaves this function. */
async function listApiKeys(store, accountHash) {
  assertHashFormat(accountHash);
  const state = await store.read();
  return Object.entries(state.apiKeys)
    .filter(([, meta]) => meta.accountHash === accountHash)
    .map(([keyHash, meta]) => ({
      keyId: keyHash,
      name: meta.name,
      hint: `ae_…${keyHash.slice(-6)}`,
      createdAt: meta.createdAt,
      lastUsedAt: meta.lastUsedAt ?? null,
      revoked: Boolean(meta.revoked),
    }))
    .sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));
}

function ownedKey(state, accountHash, keyId) {
  assertHashFormat(keyId);
  const meta = state.apiKeys[keyId];
  if (!meta || meta.accountHash !== accountHash) {
    throw new GatewayError("KEY_NOT_FOUND", "That API key does not belong to this account.", 404);
  }
  return meta;
}

async function revokeApiKey(store, accountHash, keyId) {
  const result = await store.write((state) => {
    ownedKey(state, accountHash, keyId);
    state.apiKeys[keyId].revoked = true;
    return state;
  });
  return { keyId, revoked: true, active: Object.values(result.apiKeys)
    .filter((m) => m.accountHash === accountHash && !m.revoked).length };
}

/** Rotate one key: revoke the old one, mint a new one, return the new raw key once. */
async function resetApiKey(store, accountHash, keyId) {
  const apiKey = generateApiKey();
  const keyHash = hashKey(apiKey);
  const meta = {
    accountHash,
    name: "default",
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
    revoked: false,
  };
  const result = await store.write((state) => {
    const old = ownedKey(state, accountHash, keyId);
    meta.name = old.name;
    state.apiKeys[keyId].revoked = true;
    state.apiKeys[keyHash] = meta;
    return state;
  });
  return { apiKey, keyHash, ...result.apiKeys[keyHash], rotatedFrom: keyId };
}

/** Reset ALL keys: revoke every active key and issue a single fresh one. */
async function resetAllApiKeys(store, accountHash) {
  assertHashFormat(accountHash);
  const apiKey = generateApiKey();
  const keyHash = hashKey(apiKey);
  const meta = {
    accountHash,
    name: "reset",
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
    revoked: false,
  };
  const result = await store.write((state) => {
    if (!state.accounts[accountHash]) throw new GatewayError("INVALID_KEY", "Account not found.", 404);
    let revoked = 0;
    for (const m of Object.values(state.apiKeys)) {
      if (m.accountHash === accountHash && !m.revoked) { m.revoked = true; revoked += 1; }
    }
    state.apiKeys[keyHash] = meta;
    return state;
  });
  return { apiKey, keyHash, ...result.apiKeys[keyHash], revokedCount:
    Object.values(result.apiKeys).filter((m) => m.accountHash === accountHash && m.revoked).length };
}

/* ------------------------------------------------------------------ vouchers */

async function createVoucher(store, { credits = 5000, expiresInDays = 365 } = {}) {
  const code = generateVoucherCode();
  const codeHash = hashVoucher(code);
  const record = {
    credits: creditsFrom(credits),
    expiresAt: expiryFrom(expiresInDays),
    redeemed: false,
  };
  await store.write((state) => { state.vouchers[codeHash] = record; return state; });
  return { code, codeHash, ...record };
}

/**
 * Credit an account with a one-time voucher. The account can be addressed by
 * unlock code, by API key, by client-generated hash (gated), or not at all —
 * in which case a fresh account + unlock code is created and returned once.
 */
async function redeemVoucher(store, { code, unlockCode = null, apiKey = null, accountHash = null, key = null } = {}) {
  if (!code) throw new GatewayError("BAD_VOUCHER", "Voucher code required.", 400);
  const codeHash = hashVoucher(code);

  // `key` is a deprecated alias kept so old redemption scripts keep working:
  // the old 16-digit "key" is exactly today's unlock code.
  let effectiveUnlock = unlockCode;
  let effectiveApiKey = apiKey;
  if (!effectiveUnlock && !effectiveApiKey && key) {
    if (String(key).startsWith("ae_")) effectiveApiKey = key;
    else effectiveUnlock = key;
  }

  let resolvedHash;
  let generatedUnlock = null;
  if (effectiveUnlock) {
    assertUnlockCodeFormat(effectiveUnlock);
    resolvedHash = hashKey(effectiveUnlock);
  } else if (effectiveApiKey) {
    const found = await resolveAccountByApiKey(store, effectiveApiKey);
    resolvedHash = found.accountHash;
  } else if (accountHash) {
    if (process.env.CORE_ALLOW_CLIENT_HASH !== "1") {
      throw new GatewayError("CLIENT_HASH_DISABLED", "Client-side account hashes are disabled.", 403);
    }
    assertHashFormat(accountHash);
    resolvedHash = accountHash;
  } else {
    generatedUnlock = generateUnlockCode();
    resolvedHash = hashKey(generatedUnlock);
  }

  // Validate inside the serialized write so two redeem calls cannot both
  // consume the same voucher. Throwing here never persists a partial state.
  const result = await store.write((state) => {
    const voucher = state.vouchers[codeHash];
    if (!voucher || voucher.redeemed || Date.parse(voucher.expiresAt) <= Date.now()) {
      throw new GatewayError("BAD_VOUCHER", "Voucher not found, expired, or already redeemed.", 400);
    }
    voucher.redeemed = true;
    const existing = state.accounts[resolvedHash];
    if (existing) {
      existing.credits += voucher.credits;
      existing.revoked = false;
    } else {
      state.accounts[resolvedHash] = {
        credits: voucher.credits,
        createdAt: new Date().toISOString(),
        expiresAt: null,
        revoked: false,
      };
    }
    return state;
  });
  return {
    accountHash: resolvedHash,
    credits: result.accounts[resolvedHash].credits,
    ...(generatedUnlock
      ? { unlockCode: generatedUnlock, notice: "Save this unlock code. It opens your account; it is not an API key." }
      : {}),
  };
}

module.exports = {
  creditsFrom, maxApiKeys, safeName,
  createAccount, listAccounts, getAccount, revokeAccount, topUpAccount,
  resolveAccountByUnlock, resolveAccountByApiKey,
  createApiKey, listApiKeys, revokeApiKey, resetApiKey, resetAllApiKeys,
  createVoucher, redeemVoucher,
};
