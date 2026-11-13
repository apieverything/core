"use strict";

/**
 * In-memory sliding window. Deliberately NOT persisted: a rate bucket is
 * transient state, never data about a person. It disappears on restart.
 */
class RateLimiter {
  constructor({ perMinute = 60, burst = 10 } = {}) {
    this.perMinute = Math.max(1, Number(perMinute) || 60);
    this.burst = Math.max(1, Number(burst) || 10);
    this.hits = new Map();
  }
  check(hash, now = Date.now()) {
    const windowStart = now - 60000;
    let entries = (this.hits.get(hash) ?? []).filter((t) => t > windowStart);
    const allowed = entries.length < this.perMinute;
    if (allowed) entries.push(now);
    this.hits.set(hash, entries);
    // Opportunistic cleanup so the map cannot grow without bound.
    if (this.hits.size > 5000) {
      for (const [key, list] of this.hits) {
        const fresh = list.filter((t) => t > windowStart);
        if (fresh.length) this.hits.set(key, fresh);
        else this.hits.delete(key);
      }
    }
    return { allowed, remaining: Math.max(0, this.perMinute - entries.length), retryAfter: 60 };
  }
  reset() { this.hits.clear(); }
}

module.exports = { RateLimiter };
