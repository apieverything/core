"use strict";

/**
 * Minimal persistent store.
 *
 * The on-disk record contains ONLY hashes, credit counters, timestamps and
 * revocation flags. No IP, no email, no wallet, no query history, no request
 * log. Neither the 16-digit unlock code nor any API key is ever written in
 * clear text.
 *
 * Writes are serialized through a promise chain and made atomic (write tmp,
 * then rename) so concurrent debits cannot corrupt the file.
 */
const fs = require("node:fs");
const path = require("node:path");

function emptyState() {
  return { version: 2, accounts: {}, apiKeys: {}, vouchers: {} };
}

/**
 * v1 stored `keys` (16-digit codes used directly as API keys). Those become
 * accounts on read, preserving credits: the old code is now an unlock code.
 * No API key is minted automatically — the owner unlocks the account and
 * creates one. This is a one-way, in-place migration with no data loss.
 */
function normalize(parsed) {
  if (!parsed || typeof parsed !== "object") return emptyState();
  const accounts = { ...(parsed.accounts ?? {}) };
  const apiKeys = { ...(parsed.apiKeys ?? {}) };
  const vouchers = { ...(parsed.vouchers ?? {}) };
  if (!parsed.keys) return { version: 2, accounts, apiKeys, vouchers };

  for (const [hash, rec] of Object.entries(parsed.keys)) {
    if (!accounts[hash]) {
      accounts[hash] = {
        credits: Number(rec?.credits) || 0,
        createdAt: rec?.createdAt ?? new Date().toISOString(),
        expiresAt: rec?.expiresAt ?? null,
        revoked: Boolean(rec?.revoked),
      };
    }
  }
  return { version: 2, accounts, apiKeys, vouchers };
}

class MemoryStore {
  constructor(initial = null) {
    this.state = normalize(initial);
    this.queue = Promise.resolve();
  }
  async read() { return structuredClone(this.state); }
  async write(mutator) {
    const run = async () => {
      const next = mutator(structuredClone(this.state));
      this.state = next;
      return structuredClone(next);
    };
    const result = this.queue.then(run, run);
    this.queue = result.catch(() => {});
    return result;
  }
}

class FileStore {
  constructor(file = null) {
    this.file = file ??
      process.env.CORE_DATA_FILE ??
      path.resolve(process.env.CORE_DATA_DIR ?? path.resolve(process.cwd(), ".data"), "keys.json");
    this.queue = Promise.resolve();
    if (!fs.existsSync(this.file)) {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      fs.writeFileSync(this.file, JSON.stringify(emptyState(), null, 2) + "\n", { mode: 0o600 });
    }
  }
  async read() {
    try {
      return normalize(JSON.parse(fs.readFileSync(this.file, "utf8")));
    } catch {
      return emptyState();
    }
  }
  async write(mutator) {
    const run = async () => {
      const current = await this.read();
      const next = mutator(current) ?? current;
      const tmp = `${this.file}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(next, null, 2) + "\n", { mode: 0o600 });
      fs.renameSync(tmp, this.file);
      return next;
    };
    const result = this.queue.then(run, run);
    this.queue = result.catch(() => {});
    return result;
  }
}

function createStore() {
  if (process.env.CORE_STORE === "memory") return new MemoryStore();
  return new FileStore();
}

module.exports = { MemoryStore, FileStore, createStore, emptyState, normalize };
