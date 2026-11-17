"use strict";

/**
 * Two different credentials, deliberately impossible to confuse.
 *
 *  - unlock code : 16 digits. Opens the account (X-Unlock-Code). NEVER sent
 *    with an API request. Shown once, hash-only at rest.
 *  - API key     : `ae_` + 48 hex. Used for X-API-Key. Can be created,
 *    rotated and revoked independently. Shown once, hash-only at rest.
 *
 * Keeping the short, human-friendly unlock code out of client code, curl
 * examples, logs and screenshots is the whole point: a leaked API key is
 * rotated, a leaked unlock code is the account itself.
 */
const crypto = require("node:crypto");
const { GatewayError } = require("./errors");

const UNLOCK_RE = /^\d{16}$/;
const API_KEY_RE = /^ae_[a-f0-9]{48}$/;
const HASH_RE = /^[a-f0-9]{64}$/;

/** 16-digit unlock code from a CSPRNG (never Math.random, never sequential). */
function generateUnlockCode() {
  let code = "";
  for (let i = 0; i < 16; i += 1) code += String(crypto.randomInt(0, 10));
  return code;
}

/** Rotatable API key. The `ae_` prefix makes accidental leaks greppable. */
function generateApiKey() {
  return `ae_${crypto.randomBytes(24).toString("hex")}`;
}

function hashKey(value) {
  return crypto.createHash("sha256").update(String(value), "utf8").digest("hex");
}

function assertUnlockCodeFormat(value) {
  if (!UNLOCK_RE.test(String(value ?? ""))) {
    throw new GatewayError("INVALID_UNLOCK_CODE", "Invalid unlock code.", 401);
  }
}

function assertApiKeyFormat(value) {
  const raw = String(value ?? "");
  if (UNLOCK_RE.test(raw)) {
    throw new GatewayError(
      "UNLOCK_CODE_NOT_API_KEY",
      "That is your 16-digit unlock code, not an API key.",
      401
    );
  }
  if (!API_KEY_RE.test(raw)) {
    throw new GatewayError("INVALID_KEY", "Invalid API key format.", 401);
  }
}

function assertHashFormat(hash) {
  if (!HASH_RE.test(String(hash ?? ""))) {
    throw new GatewayError("BAD_KEYHASH", "Invalid key hash.", 400);
  }
}

/** A voucher code is a one-time bearer token, stored only as a hash. */
function generateVoucherCode() {
  return crypto.randomBytes(18).toString("base64url");
}

function hashVoucher(code) {
  return crypto.createHash("sha256").update(String(code), "utf8").digest("hex");
}

function timingSafeEqual(a, b) {
  const left = Buffer.from(String(a ?? ""));
  const right = Buffer.from(String(b ?? ""));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function maskUnlockCode(code) {
  const s = String(code ?? "");
  return s.length === 16 ? `•••• •••• •••• ${s.slice(-4)}` : "••••";
}

function maskApiKey(key) {
  const s = String(key ?? "");
  return s.startsWith("ae_") && s.length > 10 ? `ae_••••${s.slice(-6)}` : "ae_••••";
}

module.exports = {
  UNLOCK_RE, API_KEY_RE, HASH_RE,
  generateUnlockCode, generateApiKey, hashKey,
  assertUnlockCodeFormat, assertApiKeyFormat, assertHashFormat,
  generateVoucherCode, hashVoucher, timingSafeEqual,
  maskUnlockCode, maskApiKey,
};
