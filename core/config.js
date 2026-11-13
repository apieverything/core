"use strict";

/** .env loader with hot-reload (Ctrl+R), same contract as the connectors. */
const fs = require("node:fs");
const path = require("node:path");

function parseEnvFile(text) {
  const entries = new Map();
  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const body = line.replace(/^export\s+/, "");
    const eq = body.indexOf("=");
    if (eq === -1) continue;
    const key = body.slice(0, eq).trim();
    if (!key) continue;
    let value = body.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    else value = value.replace(/\s+#.*$/, "").trim();
    entries.set(key, value);
  }
  return entries;
}

class Config {
  constructor(file = null) {
    this.file = file ?? process.env.CORE_ENV_FILE ?? path.resolve(process.cwd(), ".env");
    this.initialized = false;
    this.external = new Set();
    this.managed = new Set();
  }
  load() {
    let text = null;
    try { text = fs.readFileSync(this.file, "utf8"); } catch { text = null; }
    const entries = text === null ? new Map() : parseEnvFile(text);
    if (!this.initialized) {
      for (const [key, value] of entries) {
        if (process.env[key] !== undefined && process.env[key] !== value) this.external.add(key);
        else { process.env[key] = value; this.managed.add(key); }
      }
      this.initialized = true;
    } else {
      for (const key of this.managed) if (!entries.has(key) && !this.external.has(key)) delete process.env[key];
      for (const [key, value] of entries) if (!this.external.has(key)) process.env[key] = value;
    }
    this.managed = new Set(entries.keys());
    return { file: this.file, found: text !== null, keys: [...entries.keys()] };
  }
}

const config = new Config();
module.exports = { Config, config, parseEnvFile };
