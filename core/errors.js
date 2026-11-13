"use strict";

const HINTS = {
  INVALID_KEY: "Provide X-API-Key as a 16-digit key.",
  KEY_REVOKED: "This key was revoked. Redeem a new voucher.",
  KEY_EXPIRED: "This key expired. Top it up or redeem a new voucher.",
  NO_CREDITS: "No credits left. Redeem a voucher to continue.",
  RATE_LIMITED: "Slow down. See Retry-After and CORE_RATE_PER_MIN.",
  ROUTE_BLOCKED: "This route is blocked by the gateway data policy.",
  UNKNOWN_SERVICE: "No upstream configured for this service. Check CORE_UPSTREAMS.",
  UPSTREAM_UNAVAILABLE: "The upstream connector did not answer.",
  ADMIN_DISABLED: "Set CORE_ADMIN_TOKEN to enable management routes.",
  ADMIN_REQUIRED: "Provide a valid X-Admin-Token.",
  BAD_VOUCHER: "Voucher not found, expired, or already redeemed.",
  BAD_KEYHASH: "keyHash must be a 64-character lowercase SHA-256 hex digest.",
  CLIENT_HASH_DISABLED: "Set CORE_ALLOW_CLIENT_HASH=1 to redeem with a client-side key hash.",
  BAD_REQUEST: "Check the request body.",
};

class GatewayError extends Error {
  constructor(code, message, status = 400, details = null) {
    super(message);
    this.name = "GatewayError";
    this.code = code;
    this.status = status;
    this.details = details;
    this.hint = HINTS[code] ?? null;
  }
}

module.exports = { GatewayError, HINTS };
