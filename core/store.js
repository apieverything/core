"use strict";

/**
 * Minimal persistent store.
 *
 * The on-disk record contains ONLY: key hash, credits, createdAt, expiresAt,
 * revoked. No IP, no email, no wallet, no query history, no request log.
 * Vouchers are stored as a code hash + credits + expiry + redeemed flag.
 *
 * Writes are serialized through a promise chain and made atomic (write tmp,
 * then rename) so concurrent debits cannot corrupt the file.
 */
const fs = require("node:fs");
const path = require("node:path");

function emptyState() {
  return { version: 1, keys: {}, vouchers: {} };
}

class MemoryStore {
  constructor(initial = null) {
    this.state = initial ? structuredClone(initial) : emptyState();
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
      const parsed = JSON.parse(fs.readFileSync(this.file, "utf8"));
      return { version: 1, keys: parsed.keys ?? {}, vouchers: parsed.vouchers ?? {} };
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

module.exports = { MemoryStore, FileStore, createStore, emptyState };
