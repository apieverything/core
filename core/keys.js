"use strict";

const crypto = require("node:crypto");
const { GatewayError } = require("./errors");

const KEY_RE = /^\d{16}$/;
const HASH_RE = /^[a-f0-9]{64}$/;

/** 16-digit key from a CSPRNG (never Math.random, never sequential). */
function generateKey() {
  let key = "";
  for (let i = 0; i < 16; i += 1) key += String(crypto.randomInt(0, 10));
  return key;
}

function hashKey(key) {
  return crypto.createHash("sha256").update(String(key), "utf8").digest("hex");
}

function assertKeyFormat(key) {
  if (!KEY_RE.test(String(key ?? ""))) {
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

function maskKey(key) {
  const s = String(key ?? "");
  return s.length === 16 ? `•••• •••• •••• ${s.slice(-4)}` : "••••";
}

module.exports = {
  KEY_RE, HASH_RE,
  generateKey, hashKey, assertKeyFormat, assertHashFormat,
  generateVoucherCode, hashVoucher, timingSafeEqual, maskKey,
};
