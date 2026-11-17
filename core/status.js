"use strict";

const axios = require("axios");
const { upstreams } = require("./proxy");

const CACHE_MS = 30_000;
let cache = { at: 0, value: null };

async function probeOne(name, base) {
  const started = Date.now();
  try {
    const res = await axios.get(`${String(base).replace(/\/$/, "")}/health`, {
      timeout: 2500,
      validateStatus: () => true,
      responseType: "text",
      transformResponse: [(d) => d],
    });
    return {
      service: name,
      ok: res.status >= 200 && res.status < 300,
      status: res.status,
      latencyMs: Date.now() - started,
    };
  } catch {
    return { service: name, ok: false, status: null, latencyMs: Date.now() - started };
  }
}

/** Public status of the connectors. Never exposes internal upstream URLs. */
async function connectorStatus({ force = false } = {}) {
  if (!force && cache.value && Date.now() - cache.at < CACHE_MS) {
    return { ...cache.value, cached: true };
  }
  const map = upstreams();
  const checks = await Promise.all(Object.entries(map).map(([name, base]) => probeOne(name, base)));
  const value = {
    checkedAt: new Date().toISOString(),
    services: checks,
    healthy: checks.filter((c) => c.ok).length,
    total: checks.length,
  };
  cache = { at: Date.now(), value };
  return { ...value, cached: false };
}

function resetStatusCache() { cache = { at: 0, value: null }; }

module.exports = { connectorStatus, probeOne, resetStatusCache };
