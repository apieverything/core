"use strict";

/**
 * Privacy-first in-memory response cache with in-flight request coalescing.
 *
 *  - Only GET and HEAD connector responses are cached.
 *  - Keys are SHA-256 digests of `${METHOD}:${pathname}${search}`: raw URLs,
 *    handles and query strings are NEVER stored in memory or written to disk.
 *  - Only billable responses (2xx with non-error payload) enter the cache.
 *  - Concurrent misses for the same key share one upstream promise: the leader
 *    receives X-Cache: MISS and followers receive X-Cache: COALESCED.
 */
const { hashKey } = require("./keys");
const { billable } = require("./ledger");

const DEFAULT_TTL_MS = 120_000;
const DEFAULT_MAX_ENTRIES = 500;

function envEnabled() {
  const raw = process.env.CORE_CACHE_ENABLED;
  if (raw === undefined || raw === "") return true;
  return raw !== "0" && String(raw).toLowerCase() !== "false";
}

function envTtlMs() {
  const raw = process.env.CORE_CACHE_TTL_MS;
  if (raw === undefined || raw === "") return DEFAULT_TTL_MS;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : DEFAULT_TTL_MS;
}

function envMaxEntries() {
  const raw = process.env.CORE_CACHE_MAX_ENTRIES;
  if (raw === undefined || raw === "") return DEFAULT_MAX_ENTRIES;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 1 ? n : DEFAULT_MAX_ENTRIES;
}

function cacheKey(method, pathname, search = "") {
  const m = String(method || "GET").toUpperCase();
  const s = search ? (String(search).startsWith("?") ? String(search) : `?${search}`) : "";
  return hashKey(`${m}:${pathname}${s}`);
}

function shouldBypassCache(cacheControl) {
  if (!cacheControl) return false;
  return /\b(no-cache|no-store)\b/i.test(String(cacheControl));
}

class ResponseCache {
  constructor(options = {}) {
    this._enabled = options.enabled;
    this._ttlMs = options.ttlMs;
    this._maxEntries = options.maxEntries;
    this.now = options.now ?? (() => Date.now());
    this.entries = new Map();
    this.inflight = new Map();
    this.hits = 0;
    this.misses = 0;
    this.coalesced = 0;
  }

  isEnabled() {
    return this._enabled !== undefined ? Boolean(this._enabled) : envEnabled();
  }

  ttlMs() {
    return this._ttlMs !== undefined ? Math.max(0, Math.floor(Number(this._ttlMs))) : envTtlMs();
  }

  maxEntries() {
    return this._maxEntries !== undefined ? Math.max(1, Math.floor(Number(this._maxEntries))) : envMaxEntries();
  }

  configure(options = {}) {
    this._enabled = options.enabled;
    this._ttlMs = options.ttlMs;
    this._maxEntries = options.maxEntries;
    if (!this.isEnabled()) {
      this.entries.clear();
      return;
    }
    this.purgeExpired();
    this._evictOverflow();
  }

  purgeExpired(now = this.now()) {
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(key);
    }
  }

  _evictOverflow() {
    const max = this.maxEntries();
    while (this.entries.size > max) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
  }

  get(keyHash, now = this.now()) {
    const entry = this.entries.get(keyHash);
    if (!entry) return null;
    if (entry.expiresAt <= now) {
      this.entries.delete(keyHash);
      return null;
    }
    // Refresh LRU order.
    this.entries.delete(keyHash);
    this.entries.set(keyHash, entry);
    return {
      status: entry.status,
      body: entry.body,
      contentType: entry.contentType,
    };
  }

  set(keyHash, response, now = this.now()) {
    if (!this.isEnabled()) return false;
    const ttl = this.ttlMs();
    if (ttl <= 0) return false;
    if (!/^[a-f0-9]{64}$/.test(String(keyHash))) {
      throw new Error("ResponseCache only accepts 64-char SHA-256 key hashes.");
    }
    if (this.entries.has(keyHash)) this.entries.delete(keyHash);
    if (this.entries.size >= this.maxEntries()) {
      this.purgeExpired(now);
    }
    while (this.entries.size >= this.maxEntries()) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
    this.entries.set(keyHash, {
      status: response.status,
      body: response.body,
      contentType: response.contentType,
      expiresAt: now + ttl,
    });
    return true;
  }

  async resolve({ method, pathname, search = "", cacheControl = "", loader, isBillable = billable }) {
    const upper = String(method || "GET").toUpperCase();
    if (upper !== "GET" && upper !== "HEAD") {
      const response = await loader();
      return { response, xCache: "BYPASS" };
    }
    if (!this.isEnabled()) {
      const response = await loader();
      return { response, xCache: "BYPASS" };
    }

    const key = cacheKey(upper, pathname, search);
    const bypass = shouldBypassCache(cacheControl);

    if (!bypass) {
      const hit = this.get(key);
      if (hit) {
        this.hits += 1;
        return { response: hit, xCache: "HIT" };
      }
    }

    const existing = this.inflight.get(key);
    if (existing) {
      if (!bypass) this.coalesced += 1;
      const response = await existing;
      return { response, xCache: bypass ? "BYPASS" : "COALESCED" };
    }

    if (!bypass) this.misses += 1;

    const promise = (async () => {
      const res = await loader();
      if (this.isEnabled() && isBillable(res.status, res.body)) {
        this.set(key, res);
      }
      return res;
    })();

    this.inflight.set(key, promise);
    try {
      const response = await promise;
      return { response, xCache: bypass ? "BYPASS" : "MISS" };
    } finally {
      if (this.inflight.get(key) === promise) {
        this.inflight.delete(key);
      }
    }
  }

  clear() {
    this.entries.clear();
  }

  resetStats() {
    this.hits = 0;
    this.misses = 0;
    this.coalesced = 0;
  }

  stats(now = this.now()) {
    this.purgeExpired(now);
    return {
      enabled: this.isEnabled(),
      entries: this.entries.size,
      maxEntries: this.maxEntries(),
      ttlMs: this.ttlMs(),
      hits: this.hits,
      misses: this.misses,
      coalesced: this.coalesced,
    };
  }
}

module.exports = {
  ResponseCache,
  cacheKey,
  shouldBypassCache,
  DEFAULT_TTL_MS,
  DEFAULT_MAX_ENTRIES,
};
