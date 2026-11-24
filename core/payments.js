"use strict";

/**
 * Zero-identity PayAsYouGo payment -> one-time voucher bridge.
 *
 * Supported drivers (all $0/month fixed cost):
 *  - "nowpayments": NOWPayments REST /v1/invoice + HMAC-SHA512 IPN (x-nowpayments-sig)
 *  - "btcpay":      BTCPay Server Greenfield API + HMAC-SHA256 webhook (btcpay-sig)
 *  - "sandbox":     Local simulator when CORE_PAYMENT_SANDBOX=1
 *  - "disabled":    Default fail-closed state
 *
 * Payments stay 100% decoupled from accounts:
 *  - No email, no IP, no wallet address, no accountHash is accepted or stored.
 *  - Pending/settled invoices live in a bounded in-memory Map (max 1000, 1h TTL)
 *    and are NEVER written to keys.json.
 *  - Settlement mints a standard one-time bearer voucher in `store` (stored only
 *    as its SHA-256 hash). The buyer redeems that voucher into any account — or
 *    into a brand-new account — via POST /v1/redeem.
 */
const crypto = require("node:crypto");
const axios = require("axios");
const { GatewayError } = require("./errors");
const { timingSafeEqual } = require("./keys");
const registry = require("./registry");

const DEFAULT_PACKS = [
  { id: "pack_1k", name: "Starter", credits: 1000, priceUsd: 5 },
  { id: "pack_5k", name: "Builder", credits: 5000, priceUsd: 20 },
  { id: "pack_20k", name: "Scale", credits: 20000, priceUsd: 65 },
];

const MAX_INVOICES = 1000;
const INVOICE_TTL_MS = 60 * 60 * 1000;
const POLL_COOLDOWN_MS = 4000;

function creditPacks() {
  const raw = process.env.CORE_CREDIT_PACKS?.trim();
  if (!raw) return DEFAULT_PACKS.map((p) => ({ ...p }));
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed) || !parsed.length) return DEFAULT_PACKS.map((p) => ({ ...p }));
    const valid = parsed
      .filter((p) =>
        p &&
        typeof p.id === "string" && p.id.trim() &&
        typeof p.name === "string" && p.name.trim() &&
        Number.isInteger(Number(p.credits)) && Number(p.credits) >= 1 &&
        Number.isFinite(Number(p.priceUsd)) && Number(p.priceUsd) > 0
      )
      .map((p) => ({
        id: p.id.trim(),
        name: p.name.trim(),
        credits: Number(p.credits),
        priceUsd: Number(p.priceUsd),
      }));
    return valid.length ? valid : DEFAULT_PACKS.map((p) => ({ ...p }));
  } catch {
    return DEFAULT_PACKS.map((p) => ({ ...p }));
  }
}

function paymentMode() {
  if (process.env.CORE_NOWPAYMENTS_API_KEY?.trim()) return "nowpayments";
  const url = process.env.CORE_BTCPAY_URL?.trim();
  const storeId = process.env.CORE_BTCPAY_STORE_ID?.trim();
  const apiKey = process.env.CORE_BTCPAY_API_KEY?.trim();
  if (url && storeId && apiKey) return "btcpay";
  if (process.env.CORE_PAYMENT_SANDBOX === "1") return "sandbox";
  return "disabled";
}

function generateInvoiceId() {
  return `inv_${crypto.randomBytes(12).toString("hex")}`;
}

function sortObject(value) {
  if (Array.isArray(value)) return value.map((item) => sortObject(item));
  if (value && typeof value === "object") {
    return Object.keys(value)
      .sort()
      .reduce((acc, key) => {
        acc[key] = sortObject(value[key]);
        return acc;
      }, {});
  }
  return value;
}

function verifyWebhookSignature(rawBuffer, sigHeader, secret = process.env.CORE_WEBHOOK_SECRET?.trim()) {
  if (!secret) {
    throw new GatewayError("WEBHOOK_DISABLED", "Payment webhooks are disabled.", 503);
  }
  const buf = Buffer.isBuffer(rawBuffer) ? rawBuffer : Buffer.from(String(rawBuffer ?? ""), "utf8");
  const header = String(sigHeader ?? "").trim();
  const match = /^sha256=([a-fA-F0-9]{64})$/.exec(header);
  if (!match) {
    throw new GatewayError("INVALID_SIGNATURE", "Missing or malformed btcpay-sig header.", 401);
  }
  const expected = crypto.createHmac("sha256", secret).update(buf).digest("hex");
  const provided = match[1].toLowerCase();
  if (!timingSafeEqual(provided, expected)) {
    throw new GatewayError("INVALID_SIGNATURE", "Invalid webhook signature.", 401);
  }
  return true;
}

function verifyNowPaymentsSignature(
  payloadObj,
  sigHeader,
  secret = process.env.CORE_NOWPAYMENTS_IPN_SECRET?.trim() || process.env.CORE_WEBHOOK_SECRET?.trim()
) {
  if (!secret) {
    throw new GatewayError("WEBHOOK_DISABLED", "NOWPayments IPN secret is not configured.", 503);
  }
  const header = String(sigHeader ?? "").trim();
  if (!/^[a-fA-F0-9]{128}$/.test(header)) {
    throw new GatewayError("INVALID_SIGNATURE", "Missing or malformed x-nowpayments-sig header.", 401);
  }
  const canonical = JSON.stringify(sortObject(payloadObj));
  const expected = crypto.createHmac("sha512", secret).update(canonical).digest("hex");
  const provided = header.toLowerCase();
  if (!timingSafeEqual(provided, expected)) {
    throw new GatewayError("INVALID_SIGNATURE", "Invalid NOWPayments IPN signature.", 401);
  }
  return true;
}

function isNowPaymentsSettled(status) {
  const s = String(status ?? "").toLowerCase();
  if (s === "finished") return true;
  if (s === "confirmed" && process.env.CORE_NOWPAYMENTS_ACCEPT_CONFIRMED === "1") return true;
  return false;
}

function parseCreditsFromOrderDescription(desc) {
  const m = /\((\d+)\s+credits\)/i.exec(String(desc ?? ""));
  return m ? Number(m[1]) : 0;
}

class PaymentBridge {
  constructor(options = {}) {
    this.maxInvoices = options.maxInvoices ?? MAX_INVOICES;
    this.ttlMs = options.ttlMs ?? INVOICE_TTL_MS;
    this.httpClient = options.httpClient ?? axios;
    this.now = options.now ?? (() => Date.now());
    this.invoices = new Map();
    this.settling = new Map();
  }

  purgeExpired(now = this.now()) {
    for (const [id, inv] of this.invoices) {
      if (Date.parse(inv.expiresAt) <= now) this.invoices.delete(id);
    }
  }

  _putInvoice(inv, now = this.now()) {
    if (this.invoices.has(inv.invoiceId)) this.invoices.delete(inv.invoiceId);
    if (this.invoices.size >= this.maxInvoices) {
      this.purgeExpired(now);
    }
    while (this.invoices.size >= this.maxInvoices) {
      const oldest = this.invoices.keys().next().value;
      if (oldest === undefined) break;
      this.invoices.delete(oldest);
    }
    this.invoices.set(inv.invoiceId, inv);
    return inv;
  }

  _findInvoice(id, now = this.now()) {
    const key = String(id ?? "").trim();
    if (!key) return null;
    const direct = this.invoices.get(key);
    if (direct) {
      if (Date.parse(direct.expiresAt) <= now) {
        this.invoices.delete(key);
        return null;
      }
      return direct;
    }
    for (const [invId, inv] of this.invoices) {
      if (Date.parse(inv.expiresAt) <= now) {
        this.invoices.delete(invId);
        continue;
      }
      if (inv.providerInvoiceId && String(inv.providerInvoiceId) === key) return inv;
    }
    return null;
  }

  _serializeInvoice(inv) {
    return {
      invoiceId: inv.invoiceId,
      mode: inv.mode,
      status: inv.status,
      paymentStatus: inv.paymentStatus ?? null,
      pack: inv.pack,
      checkoutUrl: inv.checkoutUrl,
      voucherCode: inv.voucherCode,
      expiresAt: inv.expiresAt,
    };
  }

  listPacks() {
    const mode = paymentMode();
    return {
      enabled: mode !== "disabled",
      mode,
      currency: "USD",
      model: "pay_as_you_go",
      packs: creditPacks(),
    };
  }

  async checkout(body = {}) {
    const mode = paymentMode();
    if (mode === "disabled") {
      throw new GatewayError("PAYMENTS_DISABLED", "Payments are disabled on this gateway.", 503);
    }
    const packId = String(body?.packId ?? "").trim();
    const pack = creditPacks().find((p) => p.id === packId);
    if (!pack) {
      throw new GatewayError("BAD_PACK", "Unknown credit pack.", 400);
    }

    const now = this.now();
    const invoiceId = generateInvoiceId();
    const expiresAt = new Date(now + this.ttlMs).toISOString();

    if (mode === "sandbox") {
      const record = this._putInvoice({
        invoiceId,
        mode: "sandbox",
        status: "pending",
        pack: { ...pack },
        checkoutUrl: null,
        voucherCode: null,
        expiresAt,
      }, now);
      return {
        invoiceId: record.invoiceId,
        mode: record.mode,
        status: record.status,
        pack: record.pack,
        checkoutUrl: record.checkoutUrl,
        expiresAt: record.expiresAt,
      };
    }

    if (mode === "nowpayments") {
      const baseUrl = (process.env.CORE_NOWPAYMENTS_URL?.trim() || "https://api.nowpayments.io").replace(/\/+$/, "");
      const apiKey = process.env.CORE_NOWPAYMENTS_API_KEY.trim();
      const payload = {
        price_amount: pack.priceUsd,
        price_currency: "usd",
        order_id: invoiceId,
        order_description: `API Everything — ${pack.name} (${pack.credits} credits)`,
        is_fee_paid_by_user: process.env.CORE_NOWPAYMENTS_FEE_BY_USER !== "0",
      };
      const callbackUrl = process.env.CORE_PUBLIC_WEBHOOK_URL?.trim();
      if (callbackUrl) payload.ipn_callback_url = callbackUrl;
      const dashUrl = process.env.CORE_PUBLIC_DASHBOARD_URL?.trim();
      if (dashUrl) {
        payload.success_url = dashUrl;
        payload.cancel_url = dashUrl;
      }

      let checkoutUrl = null;
      let providerInvoiceId = null;
      try {
        const res = await this.httpClient.post(`${baseUrl}/v1/invoice`, payload, {
          headers: {
            "x-api-key": apiKey,
            "Content-Type": "application/json",
          },
          timeout: 12_000,
          validateStatus: () => true,
        });
        if (res.status < 200 || res.status >= 300 || !res.data?.invoice_url) {
          const msg = res.data?.message || `NOWPayments returned HTTP ${res.status}`;
          throw new Error(msg);
        }
        checkoutUrl = String(res.data.invoice_url);
        providerInvoiceId = res.data.id !== undefined && res.data.id !== null ? String(res.data.id) : null;
      } catch (err) {
        if (err instanceof GatewayError) throw err;
        throw new GatewayError(
          "PAYMENT_UPSTREAM_ERROR",
          `Could not create NOWPayments invoice: ${err.message}`,
          502
        );
      }

      const record = this._putInvoice({
        invoiceId,
        providerInvoiceId,
        providerPaymentId: null,
        lastPolledAt: 0,
        mode: "nowpayments",
        status: "pending",
        paymentStatus: "waiting",
        pack: { ...pack },
        checkoutUrl,
        voucherCode: null,
        expiresAt,
      }, now);

      return {
        invoiceId: record.invoiceId,
        mode: record.mode,
        status: record.status,
        pack: record.pack,
        checkoutUrl: record.checkoutUrl,
        expiresAt: record.expiresAt,
      };
    }

    // BTCPay Greenfield API mode
    const baseUrl = process.env.CORE_BTCPAY_URL.trim().replace(/\/+$/, "");
    const storeId = process.env.CORE_BTCPAY_STORE_ID.trim();
    const apiKey = process.env.CORE_BTCPAY_API_KEY.trim();
    let checkoutUrl = null;
    let providerInvoiceId = null;

    try {
      const res = await this.httpClient.post(
        `${baseUrl}/api/v1/stores/${encodeURIComponent(storeId)}/invoices`,
        {
          amount: pack.priceUsd,
          currency: "USD",
          metadata: { invoiceId, packId: pack.id, credits: pack.credits },
        },
        {
          headers: {
            Authorization: `token ${apiKey}`,
            "Content-Type": "application/json",
          },
          timeout: 10_000,
          validateStatus: () => true,
        }
      );
      if (res.status < 200 || res.status >= 300 || !res.data) {
        throw new Error(`BTCPay returned HTTP ${res.status}`);
      }
      checkoutUrl = res.data.checkoutLink ?? null;
      providerInvoiceId = res.data.id ?? null;
    } catch (err) {
      if (err instanceof GatewayError) throw err;
      throw new GatewayError(
        "PAYMENT_UPSTREAM_ERROR",
        `Could not create payment invoice: ${err.message}`,
        502
      );
    }

    const record = this._putInvoice({
      invoiceId,
      providerInvoiceId,
      mode: "btcpay",
      status: "pending",
      pack: { ...pack },
      checkoutUrl,
      voucherCode: null,
      expiresAt,
    }, now);

    return {
      invoiceId: record.invoiceId,
      mode: record.mode,
      status: record.status,
      pack: record.pack,
      checkoutUrl: record.checkoutUrl,
      expiresAt: record.expiresAt,
    };
  }

  getInvoice(invoiceId) {
    const inv = this._findInvoice(invoiceId);
    if (!inv) {
      throw new GatewayError("INVOICE_NOT_FOUND", "Invoice not found or expired.", 404);
    }
    return this._serializeInvoice(inv);
  }

  async refreshInvoice(store, invoiceId) {
    const inv = this._findInvoice(invoiceId);
    if (!inv) {
      throw new GatewayError("INVOICE_NOT_FOUND", "Invoice not found or expired.", 404);
    }
    const now = this.now();
    const apiKey = process.env.CORE_NOWPAYMENTS_API_KEY?.trim();
    if (
      inv.mode === "nowpayments" &&
      inv.status !== "settled" &&
      inv.providerPaymentId &&
      apiKey &&
      typeof this.httpClient.get === "function" &&
      now - (inv.lastPolledAt || 0) >= POLL_COOLDOWN_MS
    ) {
      inv.lastPolledAt = now;
      const baseUrl = (process.env.CORE_NOWPAYMENTS_URL?.trim() || "https://api.nowpayments.io").replace(/\/+$/, "");
      try {
        const res = await this.httpClient.get(
          `${baseUrl}/v1/payment/${encodeURIComponent(inv.providerPaymentId)}`,
          { headers: { "x-api-key": apiKey }, timeout: 8_000, validateStatus: () => true }
        );
        if (res.status >= 200 && res.status < 300 && res.data?.payment_status) {
          inv.paymentStatus = String(res.data.payment_status);
          if (isNowPaymentsSettled(inv.paymentStatus)) {
            await this._settleRecord(store, inv);
          }
        }
      } catch {
        /* Keep current in-memory status on transient upstream network error */
      }
    }
    return this._serializeInvoice(inv);
  }

  async _settleRecord(store, inv) {
    if (inv.status === "settled" && inv.voucherCode) return inv;
    const inflight = this.settling.get(inv.invoiceId);
    if (inflight) return inflight;

    const promise = (async () => {
      if (inv.status === "settled" && inv.voucherCode) return inv;
      const voucher = await registry.createVoucher(store, { credits: inv.pack.credits });
      inv.status = "settled";
      inv.voucherCode = voucher.code;
      return inv;
    })();

    this.settling.set(inv.invoiceId, promise);
    try {
      return await promise;
    } finally {
      if (this.settling.get(inv.invoiceId) === promise) {
        this.settling.delete(inv.invoiceId);
      }
    }
  }

  async sandboxSettle(store, invoiceId) {
    if (process.env.CORE_PAYMENT_SANDBOX !== "1") {
      throw new GatewayError(
        "SANDBOX_DISABLED",
        "Sandbox settlement is disabled unless CORE_PAYMENT_SANDBOX=1.",
        403
      );
    }
    const inv = this._findInvoice(invoiceId);
    if (!inv) {
      throw new GatewayError("INVOICE_NOT_FOUND", "Invoice not found or expired.", 404);
    }
    const settled = await this._settleRecord(store, inv);
    return {
      invoiceId: settled.invoiceId,
      status: "settled",
      credits: settled.pack.credits,
      voucherCode: settled.voucherCode,
    };
  }

  async handleWebhook(store, rawBuffer, sigOrHeaders) {
    const isHeaderMap = sigOrHeaders && typeof sigOrHeaders === "object" && !Buffer.isBuffer(sigOrHeaders);
    const npSig = isHeaderMap ? sigOrHeaders["x-nowpayments-sig"] : null;
    const btcpaySig = isHeaderMap ? sigOrHeaders["btcpay-sig"] : sigOrHeaders;

    if (npSig !== undefined && npSig !== null || (isHeaderMap && !btcpaySig && paymentMode() === "nowpayments")) {
      return await this._handleNowPaymentsWebhook(store, rawBuffer, npSig);
    }
    return await this._handleBtcPayWebhook(store, rawBuffer, btcpaySig);
  }

  async _handleNowPaymentsWebhook(store, rawBuffer, sigHeader) {
    let payload;
    try {
      const text = Buffer.isBuffer(rawBuffer) ? rawBuffer.toString("utf8") : String(rawBuffer ?? "");
      payload = JSON.parse(text);
      if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("not an object");
    } catch {
      throw new GatewayError("BAD_REQUEST", "Webhook body must be valid JSON.", 400);
    }

    verifyNowPaymentsSignature(payload, sigHeader);

    const orderId = String(payload.order_id ?? "").trim();
    const providerId = payload.invoice_id !== undefined && payload.invoice_id !== null ? String(payload.invoice_id) : "";
    const paymentId = payload.payment_id !== undefined && payload.payment_id !== null ? String(payload.payment_id) : null;
    const paymentStatus = String(payload.payment_status ?? "").trim();

    const targetId = orderId || providerId;
    if (!targetId) {
      throw new GatewayError("BAD_REQUEST", "NOWPayments IPN payload is missing order_id / invoice_id.", 400);
    }

    let inv = this._findInvoice(orderId) || (providerId ? this._findInvoice(providerId) : null);
    if (inv) {
      if (paymentId) inv.providerPaymentId = paymentId;
      if (paymentStatus) inv.paymentStatus = paymentStatus;
    }

    if (!isNowPaymentsSettled(paymentStatus)) {
      return {
        received: true,
        settled: false,
        provider: "nowpayments",
        paymentStatus: paymentStatus || null,
      };
    }

    if (!inv) {
      const packs = creditPacks();
      const parsedCredits = parseCreditsFromOrderDescription(payload.order_description);
      const priceUsd = Number(payload.price_amount);
      const matchedPack =
        packs.find((p) => parsedCredits && p.credits === parsedCredits) ||
        packs.find((p) => Number.isFinite(priceUsd) && Math.abs(p.priceUsd - priceUsd) < 0.01) ||
        null;
      const credits = parsedCredits || matchedPack?.credits || 0;
      if (!Number.isInteger(credits) || credits < 1) {
        throw new GatewayError("BAD_REQUEST", "Unknown NOWPayments invoice and cannot recover credit pack.", 400);
      }
      const now = this.now();
      inv = this._putInvoice({
        invoiceId: orderId || `inv_np_${providerId}`,
        providerInvoiceId: providerId || null,
        providerPaymentId: paymentId,
        mode: "nowpayments",
        status: "pending",
        paymentStatus,
        pack: matchedPack
          ? { ...matchedPack }
          : { id: "recovered", name: "NOWPayments Pack", credits, priceUsd: Number.isFinite(priceUsd) ? priceUsd : 0 },
        checkoutUrl: null,
        voucherCode: null,
        expiresAt: new Date(now + this.ttlMs).toISOString(),
      }, now);
    }

    const settled = await this._settleRecord(store, inv);
    return {
      received: true,
      settled: true,
      provider: "nowpayments",
      invoiceId: settled.invoiceId,
      status: "settled",
      credits: settled.pack.credits,
      voucherCode: settled.voucherCode,
    };
  }

  async _handleBtcPayWebhook(store, rawBuffer, sigHeader) {
    verifyWebhookSignature(rawBuffer, sigHeader);

    let payload;
    try {
      const text = Buffer.isBuffer(rawBuffer) ? rawBuffer.toString("utf8") : String(rawBuffer ?? "");
      payload = JSON.parse(text);
      if (!payload || typeof payload !== "object") throw new Error("not an object");
    } catch {
      throw new GatewayError("BAD_REQUEST", "Webhook body must be valid JSON.", 400);
    }

    const isSettled =
      payload.type === "InvoiceSettled" ||
      payload.type === "InvoicePaymentSettled" ||
      payload.status === "Settled";

    if (!isSettled) {
      return {
        received: true,
        settled: false,
        type: payload.type ?? null,
      };
    }

    const targetId = String(payload.metadata?.invoiceId || payload.invoiceId || "").trim();
    if (!targetId) {
      throw new GatewayError("BAD_REQUEST", "Webhook payload is missing invoiceId.", 400);
    }

    let inv = this._findInvoice(targetId);
    if (!inv) {
      const packs = creditPacks();
      const matchedPack = payload.metadata?.packId
        ? packs.find((p) => p.id === payload.metadata.packId)
        : null;
      const credits = Number(payload.metadata?.credits ?? matchedPack?.credits ?? 0);
      if (!Number.isInteger(credits) || credits < 1) {
        throw new GatewayError("BAD_REQUEST", "Unknown invoice and missing valid metadata.credits.", 400);
      }
      const now = this.now();
      inv = this._putInvoice({
        invoiceId: targetId,
        providerInvoiceId: payload.invoiceId && payload.invoiceId !== targetId ? String(payload.invoiceId) : null,
        mode: "btcpay",
        status: "pending",
        pack: matchedPack
          ? { ...matchedPack }
          : {
              id: String(payload.metadata?.packId || "custom"),
              name: "Webhook Pack",
              credits,
              priceUsd: Number.isFinite(Number(payload.amount)) ? Number(payload.amount) : 0,
            },
        checkoutUrl: payload.checkoutLink ?? null,
        voucherCode: null,
        expiresAt: new Date(now + this.ttlMs).toISOString(),
      }, now);
    }

    const settled = await this._settleRecord(store, inv);
    return {
      received: true,
      settled: true,
      invoiceId: settled.invoiceId,
      status: "settled",
      credits: settled.pack.credits,
      voucherCode: settled.voucherCode,
    };
  }

  clear() {
    this.invoices.clear();
    this.settling.clear();
  }
}

module.exports = {
  DEFAULT_PACKS,
  MAX_INVOICES,
  INVOICE_TTL_MS,
  creditPacks,
  paymentMode,
  generateInvoiceId,
  sortObject,
  verifyWebhookSignature,
  verifyNowPaymentsSignature,
  PaymentBridge,
};
