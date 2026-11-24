"use strict";

const HINTS = {
  INVALID_UNLOCK_CODE: "Provide X-Unlock-Code as your 16-digit unlock code. It opens your account; it is NOT an API key.",
  UNLOCK_CODE_NOT_API_KEY: "Unlock your account with the 16-digit code, then create an API key and use that in X-API-Key.",
  INVALID_KEY: "Provide X-API-Key as an ae_… API key from your account. The 16-digit code is not an API key.",
  KEY_REVOKED: "This API key was revoked. Create or reset one in your account.",
  KEY_EXPIRED: "This account expired. Redeem a voucher to continue.",
  ACCOUNT_REVOKED: "This account is revoked.",
  KEY_NOT_FOUND: "That API key does not belong to this account.",
  TOO_MANY_KEYS: "Too many API keys on this account. Revoke one first.",
  NO_CREDITS: "No credits left. Redeem a voucher to continue.",
  RATE_LIMITED: "Slow down. See Retry-After and CORE_RATE_PER_MIN.",
  ROUTE_BLOCKED: "This route is blocked by the gateway data policy.",
  UNKNOWN_SERVICE: "No upstream configured for this service. Check CORE_UPSTREAMS.",
  UPSTREAM_UNAVAILABLE: "The upstream connector did not answer.",
  ADMIN_DISABLED: "Set CORE_ADMIN_TOKEN to enable management routes.",
  ADMIN_REQUIRED: "Provide a valid X-Admin-Token.",
  BAD_VOUCHER: "Voucher not found, expired, or already redeemed.",
  BAD_KEYHASH: "keyHash must be a 64-character lowercase SHA-256 hex digest.",
  CLIENT_HASH_DISABLED: "Set CORE_ALLOW_CLIENT_HASH=1 to redeem with a client-side account hash.",
  PAYMENTS_DISABLED: "Set CORE_PAYMENT_SANDBOX=1 for local testing or configure CORE_BTCPAY_URL, CORE_BTCPAY_STORE_ID and CORE_BTCPAY_API_KEY.",
  BAD_PACK: "Fetch GET /v1/payments/packs for valid packId values.",
  INVOICE_NOT_FOUND: "Check the invoiceId or create a new checkout session (invoices expire after 1 hour).",
  SANDBOX_DISABLED: "Set CORE_PAYMENT_SANDBOX=1 to allow local sandbox settlement.",
  WEBHOOK_DISABLED: "Set CORE_WEBHOOK_SECRET to enable signed BTCPay webhooks.",
  INVALID_SIGNATURE: "Verify the btcpay-sig HMAC-SHA256 header against CORE_WEBHOOK_SECRET.",
  PAYMENT_UPSTREAM_ERROR: "The payment provider did not accept the invoice request.",
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
