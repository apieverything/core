"use strict";

/**
 * Privacy-first logger.
 * NEVER logs IP addresses, query strings, request bodies or raw keys.
 * Only method + route template + status + credit accounting.
 */
function colorEnabled() {
  if (process.env.NO_COLOR) return false;
  if (process.env.FORCE_COLOR) return true;
  return Boolean(process.stdout.isTTY);
}
const paint = (code) => (text) => colorEnabled() ? `\x1b[${code}m${text}\x1b[0m` : String(text);
const c = {
  bold: paint(1), dim: paint(2), red: paint(31), green: paint(32),
  yellow: paint(33), cyan: paint(36), gray: paint(90), white: paint(37),
};
const LEVELS = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };
const currentLevel = () => LEVELS[(process.env.LOG_LEVEL ?? "info").toLowerCase()] ?? LEVELS.info;

function emit(threshold, prefix, message) {
  const level = currentLevel();
  if (level > threshold || level === LEVELS.silent) return;
  const ts = new Date().toLocaleTimeString("en-GB", { hour12: false });
  console.log(`${c.dim(ts)} ${prefix} ${message}`);
}
const log = {
  debug: (m) => emit(LEVELS.debug, c.gray("·"), c.gray(m)),
  info: (m) => emit(LEVELS.info, c.cyan("›"), m),
  success: (m) => emit(LEVELS.info, c.green("✓"), m),
  warn: (m) => emit(LEVELS.warn, c.yellow("!"), c.yellow(m)),
  error: (m) => emit(LEVELS.error, c.red("✗"), c.red(m)),
  plain: (m) => { if (currentLevel() !== LEVELS.silent) console.log(m); },
};

/** Reduce a path to a template: strip query strings and variable segments. */
function routeTemplate(rawPath) {
  const path = String(rawPath).split("?")[0];
  // Replace only identifier segments, keeping static resource names readable.
  return path
    .replace(/\/v1\/(instagram|tiktok)\/[^/]+\/posts/g, "/v1/$1/:id/posts")
    .replace(/\/v1\/(instagram|tiktok)\/[^/]+/g, "/v1/$1/:id")
    .replace(/\/v1\/linkedin\/(jobs|company|people)\/[^/]+/g, "/v1/linkedin/$1/:id")
    .replace(/\/v1\/admin\/accounts\/[a-f0-9]{64}/g, "/v1/admin/accounts/:hash")
    .replace(/\/v1\/keys\/[a-f0-9]{64}/g, "/v1/keys/:hash")
    .replace(/\/\d{6,}/g, "/:id");
}

const BOX_WIDTH = 66;
const visibleLength = (s) => String(s).replace(/\x1b\[[0-9;]*m/g, "").length;
function boxLine(inner) {
  const content = `  ${inner}`;
  const padding = Math.max(0, BOX_WIDTH - visibleLength(content));
  return `${c.cyan("│")}${content}${" ".repeat(padding)}${c.cyan("│")}`;
}
function row(label, value) { log.plain(`  ${c.gray(label.padEnd(9))}   ${value}`); }

function banner({ port, host, version, upstreams, accounts, apiKeys, people }) {
  const title = `${c.bold(c.white("API Everything"))} ${c.gray("·")} ${c.bold(c.cyan("core gateway"))}`;
  log.plain("");
  log.plain(c.cyan(`┌${"─".repeat(BOX_WIDTH)}┐`));
  log.plain(boxLine(`${title}  ${c.gray(`v${version}`)}`));
  log.plain(boxLine(c.dim("Unlock code opens the account · rotatable API keys")));
  log.plain(c.cyan(`└${"─".repeat(BOX_WIDTH)}┘`));
  row("Listening", c.green(`http://${host}:${port}`));
  row("Upstreams", c.dim(Object.keys(upstreams).join(" · ") || "none"));
  row("Accounts", c.dim(`${accounts} active · ${apiKeys} API keys`));
  row("Policy", people
    ? `${c.yellow("!")} ${c.yellow("people routes ALLOWED")}`
    : `${c.green("✓")} ${c.green("people routes blocked")}`);
  row("Retention", c.dim("hash + credits + expiry only"));
}

function statusColor(status) {
  if (status >= 500) return c.red(String(status));
  if (status >= 400) return c.yellow(String(status));
  return c.green(String(status));
}
function request({ method, path, status, durationMs, cost, remaining }) {
  const printed = routeTemplate(path);
  const duration = c.dim(`${String(durationMs).padStart(5)}ms`);
  const bill = cost !== undefined ? `  ${c.gray(`-${cost}cr → ${remaining}`)}` : "";
  emit(LEVELS.info, statusColor(status), `${c.gray(method.padEnd(4))} ${printed.padEnd(38)} ${duration}${bill}`);
}
function ready() {
  row("Hotkeys", `${c.cyan("Ctrl+R")} ${c.dim("reload · ")}${c.cyan("Ctrl+C")} ${c.dim("stop")}`);
  log.plain("");
}
module.exports = { log, c, banner, request, ready, routeTemplate, colorEnabled };
