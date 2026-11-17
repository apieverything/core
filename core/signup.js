"use strict";

/**
 * Public, identity-free account creation.
 *
 * PayAsYouGo: a new account gets a small starter balance, has NO expiry, and
 * is never tied to a subscription. Credits are added only by redeeming a
 * prepaid voucher. There is no recurring billing, no reset date, no email.
 *
 * What signup returns is a 16-digit UNLOCK CODE, not an API key. The code
 * opens the account (X-Unlock-Code); API keys are created afterwards and can
 * be rotated without touching the code or the credits.
 *
 * Abuse protection is deliberately transient: the client address is hashed
 * with a random per-process salt, kept in memory for one hour and never
 * written to disk. After a restart nothing is left to correlate.
 */
const crypto = require("node:crypto");
const { generateUnlockCode, hashKey } = require("./keys");
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
 * Mint an account with no expiry. The raw unlock code is returned exactly
 * once and never stored: the store only receives its SHA-256 hash.
 */
async function signup(store, limiter, req) {
  const bucket = addressHash(req);
  const gate = limiter.check(bucket);
  if (!gate.allowed) {
    throw new GatewayError("RATE_LIMITED", "Too many accounts created from this network. Try later.", 429);
  }
  const unlockCode = generateUnlockCode();
  const accountHash = hashKey(unlockCode);
  const credits = starterCredits();
  const record = {
    credits,
    createdAt: new Date().toISOString(),
    expiresAt: null, // PayAsYouGo: nothing expires on a monthly cycle
    revoked: false,
  };
  await store.write((state) => { state.accounts[accountHash] = record; return state; });
  return {
    unlockCode,
    accountHash,
    credits,
    expiresAt: null,
    model: "pay_as_you_go",
    notice: "Save this 16-digit unlock code. It opens your account; it is NOT an API key.",
    next: "Unlock your account with this code, then create an API key to use in X-API-Key.",
  };
}

module.exports = { SignupLimiter, addressHash, starterCredits, signup };
