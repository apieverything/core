"use strict";

/**
 * Weighted credits. A flat "1 request = 1 credit" would let users arbitrage
 * the margin by hammering the most expensive endpoints, so cost follows the
 * upstream work: light metadata = 1, post lists = 3, aggregates = 2.
 */
const DEFAULT_COSTS = [
  [/^\/v1\/instagram\/[^/]+\/posts/, 3],
  [/^\/v1\/tiktok\/[^/]+\/posts/, 3],
  [/^\/v1\/linkedin\/signals\//, 2],
  [/^\/v1\/linkedin\/people\//, 5],
  [/^\/v1\/linkedin\/jobs\/[^/]+/, 1],
  [/^\/v1\/instagram\//, 1],
  [/^\/v1\/tiktok\//, 1],
  [/^\/v1\/linkedin\//, 1],
];

function costTable() {
  const raw = process.env.CORE_COSTS?.trim();
  if (!raw) return DEFAULT_COSTS;
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return DEFAULT_COSTS;
    return parsed
      .filter((entry) => typeof entry?.[0] === "string" && Number.isFinite(Number(entry?.[1])))
      .map(([pattern, cost]) => [new RegExp(pattern), Math.max(0, Math.min(100, Number(cost)))]);
  } catch {
    return DEFAULT_COSTS;
  }
}

function costFor(pathname, table = costTable()) {
  const path = String(pathname).split("?")[0];
  for (const [pattern, cost] of table) if (pattern.test(path)) return cost;
  return 1;
}

/** Never debit on a failed or empty upstream response. */
function billable(status, body) {
  if (status < 200 || status >= 300) return false;
  if (!body) return false;
  const text = String(body).slice(0, 4000);
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === "object" && parsed.error) return false;
    return true;
  } catch {
    return text.trim().length > 0;
  }
}

function isActive(record, now = Date.now()) {
  if (!record || record.revoked) return false;
  if (record.credits <= 0) return false;
  if (record.expiresAt && Date.parse(record.expiresAt) <= now) return false;
  return true;
}

function expiryFrom(days) {
  const n = Math.max(1, Math.min(3650, Number(days) || 365));
  return new Date(Date.now() + n * 24 * 60 * 60 * 1000).toISOString();
}

module.exports = { DEFAULT_COSTS, costTable, costFor, billable, isActive, expiryFrom };
