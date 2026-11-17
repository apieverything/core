"use strict";

/**
 * Public, identity-free account creation.
 *
 * PayAsYouGo: a new key gets a small starter balance, has NO expiry, and is
 * never tied to a subscription. Credits are added only by redeeming a
 * prepaid voucher. There is no recurring billing, no reset date, no email.
 *
 * Abuse protection is deliberately transient: the client address is hashed
 * with a random per-process salt, kept in memory for one hour and never
 * written to disk. After a restart nothing is left to correlate.
 */
const crypto = require("node:crypto");
const { generateKey, hashKey } = require("./keys");
const { GatewayError } = require("./errors");

const salt = crypto.randomBytes(32);

function addressHash(req) {
  const raw =
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket?.remoteAddress ||
    "unknown";
  return crypto.createHash("sha256").update(salt).update(String(raw)).digest("hex");
}

class SignupLimiter {
  constructor(perHour = 5) {
    this.perHour = Math.max(1, Number(perHour) || 5);
    this.hits = new Map();
  }
  check(hash, now = Date.now()) {
    const windowStart = now - 3600000;
    const entries = (this.hits.get(hash) ?? []).filter((t) => t > windowStart);
    const allowed = entries.length < this.perHour;
    if (allowed) entries.push(now);
    this.hits.set(hash, entries);
    if (this.hits.size > 2000) {
      for (const [key, list] of this.hits) {
        const fresh = list.filter((t) => t > windowStart);
        if (fresh.length) this.hits.set(key, fresh);
        else this.hits.delete(key);
      }
    }
    return { allowed, retryAfter: 3600 };
  }
  reset() { this.hits.clear(); }
}

function starterCredits() {
  const n = Number(process.env.CORE_STARTER_CREDITS ?? 50);
  return Number.isInteger(n) && n >= 0 && n <= 100000 ? n : 50;
}

/**
 * Mint a key with no expiry. The raw key is returned exactly once and never
 * stored: the store only receives its SHA-256 hash.
 */
async function signup(store, limiter, req) {
  const bucket = addressHash(req);
  const gate = limiter.check(bucket);
  if (!gate.allowed) {
    throw new GatewayError("RATE_LIMITED", "Too many keys created from this network. Try later.", 429);
  }
  const key = generateKey();
  const keyHash = hashKey(key);
  const credits = starterCredits();
  const record = {
    credits,
    createdAt: new Date().toISOString(),
    expiresAt: null, // PayAsYouGo: nothing expires on a monthly cycle
    revoked: false,
  };
  await store.write((state) => { state.keys[keyHash] = record; return state; });
  return {
    key,
    keyHash,
    credits,
    expiresAt: null,
    model: "pay_as_you_go",
    notice: "Save this key now. It is shown once and cannot be recovered.",
  };
}

module.exports = { SignupLimiter, addressHash, starterCredits, signup };
