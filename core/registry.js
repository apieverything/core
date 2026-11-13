"use strict";

/**
 * Key and voucher registry. Vouchers are one-time bearer codes: the payment
 * system issues them, the gateway stores only their hash. There is no join key
 * between a payment and a key hash.
 */
const {
  generateKey, hashKey, assertKeyFormat, assertHashFormat,
  generateVoucherCode, hashVoucher,
} = require("./keys");
const { expiryFrom } = require("./ledger");
const { GatewayError } = require("./errors");

function creditsFrom(value, fallback = 5000) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 100000000) return fallback;
  return n;
}

async function createKey(store, { credits = 5000, expiresInDays = 365 } = {}) {
  const key = generateKey();
  const keyHash = hashKey(key);
  const record = {
    credits: creditsFrom(credits),
    createdAt: new Date().toISOString(),
    expiresAt: expiryFrom(expiresInDays),
    revoked: false,
  };
  await store.write((state) => { state.keys[keyHash] = record; return state; });
  // The raw key is returned ONCE and never stored or logged.
  return { key, keyHash, ...record };
}

async function listKeys(store) {
  const state = await store.read();
  return Object.entries(state.keys).map(([keyHash, record]) => ({ keyHash, ...record }));
}

async function getKey(store, keyHash) {
  const state = await store.read();
  return state.keys[keyHash] ?? null;
}

async function revokeKey(store, keyHash) {
  assertHashFormat(keyHash);
  const result = await store.write((state) => {
    if (!state.keys[keyHash]) return state;
    state.keys[keyHash].revoked = true;
    return state;
  });
  if (!result.keys[keyHash]) throw new GatewayError("INVALID_KEY", "Key not found.", 404);
  return { keyHash, revoked: true };
}

async function topUpKey(store, keyHash, credits) {
  assertHashFormat(keyHash);
  const amount = creditsFrom(credits, 0);
  if (!amount) throw new GatewayError("BAD_REQUEST", "credits must be a positive integer.", 400);
  const result = await store.write((state) => {
    if (!state.keys[keyHash]) return state;
    state.keys[keyHash].credits += amount;
    return state;
  });
  if (!result.keys[keyHash]) throw new GatewayError("INVALID_KEY", "Key not found.", 404);
  return { keyHash, credits: result.keys[keyHash].credits };
}

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

async function redeemVoucher(store, { code, key = null, keyHash = null } = {}) {
  if (!code) throw new GatewayError("BAD_VOUCHER", "Voucher code required.", 400);
  const codeHash = hashVoucher(code);

  let resolvedHash;
  let generatedKey = null;
  if (key) {
    assertKeyFormat(key);
    resolvedHash = hashKey(key);
  } else if (keyHash) {
    if (process.env.CORE_ALLOW_CLIENT_HASH !== "1") {
      throw new GatewayError("CLIENT_HASH_DISABLED", "Client-side key hashes are disabled.", 403);
    }
    assertHashFormat(keyHash);
    resolvedHash = keyHash;
  } else {
    // Convenience path: the gateway creates a fresh key and returns it once.
    generatedKey = generateKey();
    resolvedHash = hashKey(generatedKey);
  }

  // Validate inside the serialized write so two redeem calls cannot both
  // consume the same voucher. Throwing here never persists a partial state.
  const result = await store.write((state) => {
    const voucher = state.vouchers[codeHash];
    if (!voucher || voucher.redeemed || Date.parse(voucher.expiresAt) <= Date.now()) {
      throw new GatewayError("BAD_VOUCHER", "Voucher not found, expired, or already redeemed.", 400);
    }
    voucher.redeemed = true;
    const existing = state.keys[resolvedHash];
    if (existing) {
      existing.credits += voucher.credits;
      existing.revoked = false;
    } else {
      state.keys[resolvedHash] = {
        credits: voucher.credits,
        createdAt: new Date().toISOString(),
        expiresAt: expiryFrom(365),
        revoked: false,
      };
    }
    return state;
  });
  return {
    keyHash: resolvedHash,
    credits: result.keys[resolvedHash].credits,
    ...(generatedKey ? { key: generatedKey, note: "shown once, never stored" } : {}),
  };
}

module.exports = {
  createKey, listKeys, getKey, revokeKey, topUpKey,
  createVoucher, redeemVoucher, creditsFrom,
};
