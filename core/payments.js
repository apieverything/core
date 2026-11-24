"use strict";

/**
 * Zero-identity PayAsYouGo payment -> one-time voucher bridge.
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
      if (inv.providerInvoiceId && inv.providerInvoiceId === key) return inv;
    }
    return null;
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
    return {
      invoiceId: inv.invoiceId,
      mode: inv.mode,
      status: inv.status,
      pack: inv.pack,
      checkoutUrl: inv.checkoutUrl,
      voucherCode: inv.voucherCode,
      expiresAt: inv.expiresAt,
    };
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

  async handleWebhook(store, rawBuffer, sigHeader) {
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
  verifyWebhookSignature,
  PaymentBridge,
};
