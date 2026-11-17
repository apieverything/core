"use strict";

const axios = require("axios");
const { GatewayError } = require("./errors");

function upstreams() {
  const raw = process.env.CORE_UPSTREAMS?.trim();
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed;
    } catch { /* fall through to defaults */ }
  }
  return {
    instagram: process.env.CORE_INSTAGRAM_URL || "http://127.0.0.1:3000",
    linkedin: process.env.CORE_LINKEDIN_URL || "http://127.0.0.1:3002",
    tiktok: process.env.CORE_TIKTOK_URL || "http://127.0.0.1:3001",
  };
}

function resolveUpstream(pathname, map = upstreams()) {
  const match = /^\/v1\/([^/]+)(\/.*)?$/.exec(String(pathname));
  if (!match) return null;
  const service = match[1];
  const base = map[service];
  if (!base) return null;
  return { service, base: String(base).replace(/\/$/, ""), path: pathname };
}

const HOPLESS = new Set([
  "host", "connection", "content-length", "transfer-encoding",
  "x-api-key", "x-unlock-code", "x-admin-token", "authorization", "cookie",
]);

function forwardHeaders(req) {
  const out = {};
  for (const [key, value] of Object.entries(req.headers)) {
    if (HOPLESS.has(key.toLowerCase())) continue;
    out[key] = value;
  }
  out["X-Forwarded-By"] = "api-everything-core";
  return out;
}

async function forward({ method, url, body, headers, timeoutMs }) {
  try {
    const res = await axios.request({
      method,
      url,
      data: method === "GET" || method === "HEAD" ? undefined : body,
      headers,
      timeout: timeoutMs,
      maxRedirects: 3,
      validateStatus: () => true,
      responseType: "text",
      transformResponse: [(d) => d],
    });
    return {
      status: res.status,
      body: typeof res.data === "string" ? res.data : String(res.data ?? ""),
      contentType: res.headers["content-type"] ?? "application/json; charset=utf-8",
      headers: res.headers,
    };
  } catch (err) {
    throw new GatewayError(
      "UPSTREAM_UNAVAILABLE",
      `Upstream did not answer: ${err.message}`,
      502,
      { upstream: url.split("?")[0] }
    );
  }
}

module.exports = { upstreams, resolveUpstream, forwardHeaders, forward };
