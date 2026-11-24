"use strict";

/**
 * Zero-dependency OpenAPI 3.0.3 merger.
 *
 * Parses the gateway's own `openapi.yaml` and dynamically discovers `/v1/<service>/*`
 * paths from each configured upstream's `/openapi.yaml`. Results are cached in
 * memory for 60 seconds, and unreachable/offline upstreams gracefully fall back
 * so `GET /v1/openapi.json` always succeeds with valid 200 JSON.
 */
const fs = require("node:fs");
const path = require("node:path");
const axios = require("axios");
const { upstreams } = require("./proxy");
const { costFor } = require("./ledger");

const OPENAPI_CACHE_MS = 60_000;
let mergedCache = { at: 0, value: null };

function stripInlineComment(line) {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === "\\" && inDouble) { i += 1; continue; }
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === "#" && !inSingle && !inDouble) {
      if (i === 0 || /\s/.test(line[i - 1])) return line.slice(0, i).trimEnd();
    }
  }
  return line.trimEnd();
}

function unquoteScalar(raw) {
  const s = raw.trim();
  if (s.startsWith('"') && s.endsWith('"') && s.length >= 2) {
    try { return JSON.parse(s); } catch { return s.slice(1, -1); }
  }
  if (s.startsWith("'") && s.endsWith("'") && s.length >= 2) {
    return s.slice(1, -1).replace(/''/g, "'");
  }
  if (s === "true") return true;
  if (s === "false") return false;
  if (s === "null" || s === "~") return null;
  if (/^-?(0|[1-9]\d*)(\.\d+)?$/.test(s)) return Number(s);
  return s;
}

function splitTopLevel(str, delimiter) {
  const parts = [];
  let depthBrace = 0;
  let depthBracket = 0;
  let inSingle = false;
  let inDouble = false;
  let start = 0;
  for (let i = 0; i < str.length; i += 1) {
    const ch = str[i];
    if (ch === "\\" && inDouble) { i += 1; continue; }
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (!inSingle && !inDouble) {
      if (ch === "{") depthBrace += 1;
      else if (ch === "}") depthBrace = Math.max(0, depthBrace - 1);
      else if (ch === "[") depthBracket += 1;
      else if (ch === "]") depthBracket = Math.max(0, depthBracket - 1);
      else if (ch === delimiter && depthBrace === 0 && depthBracket === 0) {
        parts.push(str.slice(start, i));
        start = i + 1;
      }
    }
  }
  parts.push(str.slice(start));
  return parts;
}

function findKeyColon(str) {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < str.length; i += 1) {
    const ch = str[i];
    if (ch === "\\" && inDouble) { i += 1; continue; }
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === ":" && !inSingle && !inDouble) {
      if (i + 1 === str.length || /\s/.test(str[i + 1])) return i;
    }
  }
  return -1;
}

function parseFlowValue(raw) {
  const s = raw.trim();
  if (!s) return null;
  if (s.startsWith("[") && s.endsWith("]")) {
    const inner = s.slice(1, -1).trim();
    if (!inner) return [];
    return splitTopLevel(inner, ",")
      .map((item) => item.trim())
      .filter((item) => item.length > 0)
      .map((item) => parseFlowValue(item));
  }
  if (s.startsWith("{") && s.endsWith("}")) {
    const inner = s.slice(1, -1).trim();
    if (!inner) return {};
    const out = {};
    for (const pair of splitTopLevel(inner, ",")) {
      const trimmed = pair.trim();
      if (!trimmed) continue;
      const idx = findKeyColon(trimmed);
      if (idx === -1) continue;
      const key = String(unquoteScalar(trimmed.slice(0, idx)));
      const val = parseFlowValue(trimmed.slice(idx + 1));
      out[key] = val;
    }
    return out;
  }
  return unquoteScalar(s);
}

/**
 * Parse the clean OpenAPI 3.0 YAML subset used across API Everything specs
 * (nested mappings, block sequences, inline flow objects/arrays, folded `>`
 * and literal `|` block scalars).
 */
function parseSimpleYaml(text) {
  const rawLines = String(text ?? "").split(/\r?\n/);
  const lines = rawLines.map((raw) => {
    const indent = raw.match(/^ */)[0].length;
    const cleaned = stripInlineComment(raw);
    return { raw, indent, content: cleaned.trim(), blank: cleaned.trim().length === 0 };
  });

  let pos = 0;
  function skipBlanks() {
    while (pos < lines.length && lines[pos].blank) pos += 1;
  }

  function readBlockScalar(parentIndent, style) {
    const collected = [];
    let blockIndent = null;
    while (pos < lines.length) {
      const line = lines[pos];
      if (line.blank) {
        collected.push("");
        pos += 1;
        continue;
      }
      if (line.indent <= parentIndent) break;
      if (blockIndent === null) blockIndent = line.indent;
      collected.push(line.raw.slice(Math.min(line.indent, blockIndent)));
      pos += 1;
    }
    while (collected.length && collected[collected.length - 1] === "") collected.pop();
    const folded = style.startsWith(">");
    const strip = style.endsWith("-");
    if (!folded) {
      const joined = collected.join("\n");
      return strip ? joined : joined + "\n";
    }
    const paragraphs = [];
    let current = [];
    for (const item of collected) {
      if (item === "") {
        if (current.length) { paragraphs.push(current.join(" ")); current = []; }
        paragraphs.push("");
      } else {
        current.push(item.trim());
      }
    }
    if (current.length) paragraphs.push(current.join(" "));
    const out = paragraphs.join("\n").replace(/\n{2,}/g, "\n\n");
    return strip ? out : out;
  }

  function parseNode(expectedIndent) {
    skipBlanks();
    if (pos >= lines.length || lines[pos].indent < expectedIndent) return null;
    if (lines[pos].content.startsWith("-") && (lines[pos].content === "-" || lines[pos].content.startsWith("- "))) {
      return parseSequence(lines[pos].indent);
    }
    return parseMapping(lines[pos].indent);
  }

  function parseSequence(seqIndent) {
    const arr = [];
    while (pos < lines.length) {
      skipBlanks();
      if (pos >= lines.length) break;
      const line = lines[pos];
      if (line.indent !== seqIndent) break;
      if (!(line.content === "-" || line.content.startsWith("- "))) break;

      const rest = line.content.slice(1).trim();
      pos += 1;

      if (!rest) {
        skipBlanks();
        if (pos < lines.length && lines[pos].indent > seqIndent) {
          arr.push(parseNode(lines[pos].indent));
        } else {
          arr.push(null);
        }
        continue;
      }

      const colonIdx = !rest.startsWith("{") && !rest.startsWith("[") && !rest.startsWith('"') && !rest.startsWith("'")
        ? findKeyColon(rest)
        : -1;

      if (colonIdx !== -1) {
        const itemIndent = line.indent + 2;
        const obj = {};
        const key = String(unquoteScalar(rest.slice(0, colonIdx)));
        const valText = rest.slice(colonIdx + 1).trim();
        obj[key] = resolveMappingValue(valText, itemIndent);
        while (pos < lines.length) {
          skipBlanks();
          if (pos >= lines.length || lines[pos].indent < itemIndent) break;
          if (lines[pos].indent > itemIndent) break;
          if (lines[pos].content === "-" || lines[pos].content.startsWith("- ")) break;
          const subIdx = findKeyColon(lines[pos].content);
          if (subIdx === -1) break;
          const subKey = String(unquoteScalar(lines[pos].content.slice(0, subIdx)));
          const subValText = lines[pos].content.slice(subIdx + 1).trim();
          pos += 1;
          obj[subKey] = resolveMappingValue(subValText, itemIndent);
        }
        arr.push(obj);
      } else {
        arr.push(parseFlowValue(rest));
      }
    }
    return arr;
  }

  function resolveMappingValue(valText, keyIndent) {
    if (valText === ">" || valText === ">-" || valText === "|" || valText === "|-") {
      return readBlockScalar(keyIndent, valText);
    }
    if (valText.length > 0) {
      return parseFlowValue(valText);
    }
    skipBlanks();
    if (pos < lines.length && lines[pos].indent > keyIndent) {
      return parseNode(lines[pos].indent);
    }
    return {};
  }

  function parseMapping(mapIndent) {
    const obj = {};
    while (pos < lines.length) {
      skipBlanks();
      if (pos >= lines.length) break;
      const line = lines[pos];
      if (line.indent !== mapIndent) break;
      if (line.content === "-" || line.content.startsWith("- ")) break;
      const idx = findKeyColon(line.content);
      if (idx === -1) { pos += 1; continue; }
      const key = String(unquoteScalar(line.content.slice(0, idx)));
      const valText = line.content.slice(idx + 1).trim();
      pos += 1;
      obj[key] = resolveMappingValue(valText, mapIndent);
    }
    return obj;
  }

  return parseNode(0) ?? {};
}

function capitalize(name) {
  const s = String(name ?? "");
  return s ? s[0].toUpperCase() + s.slice(1) : "";
}

function rewriteSchemaRefs(node, prefix) {
  if (Array.isArray(node)) return node.map((item) => rewriteSchemaRefs(item, prefix));
  if (!node || typeof node !== "object") return node;
  const out = {};
  for (const [k, v] of Object.entries(node)) {
    if (k === "$ref" && typeof v === "string" && v.startsWith("#/components/schemas/")) {
      const schemaName = v.slice("#/components/schemas/".length);
      out[k] = `#/components/schemas/${prefix}${schemaName}`;
    } else {
      out[k] = rewriteSchemaRefs(v, prefix);
    }
  }
  return out;
}

function parseConnectorOpenApi(rawText) {
  const text = String(rawText ?? "").trim();
  if (!text) return null;
  let parsed = null;
  if (text.startsWith("{")) {
    try { parsed = JSON.parse(text); } catch { return null; }
  } else {
    try { parsed = parseSimpleYaml(text); } catch { return null; }
  }
  if (!parsed || typeof parsed !== "object") return null;
  if (!parsed.openapi || !parsed.paths || typeof parsed.paths !== "object") return null;
  return parsed;
}

async function fetchUpstreamSpec(service, baseUrl, httpClient = axios) {
  try {
    const res = await httpClient.get(`${String(baseUrl).replace(/\/+$/, "")}/openapi.yaml`, {
      timeout: 2500,
      validateStatus: () => true,
      responseType: "text",
      transformResponse: [(d) => d],
    });
    if (res.status < 200 || res.status >= 300) return { service, ok: false, spec: null };
    const spec = parseConnectorOpenApi(res.data);
    return { service, ok: Boolean(spec), spec };
  } catch {
    return { service, ok: false, spec: null };
  }
}

function loadGatewaySpec(yamlFile = path.resolve(__dirname, "..", "openapi.yaml")) {
  const text = fs.readFileSync(yamlFile, "utf8");
  return parseSimpleYaml(text);
}

function mergeSpecs(gatewaySpec, discoveredList, { allowPeople = process.env.CORE_ALLOW_PEOPLE === "1" } = {}) {
  const doc = structuredClone(gatewaySpec);
  doc.openapi = doc.openapi || "3.0.3";
  doc.paths = doc.paths || {};
  doc.components = doc.components || {};
  doc.components.schemas = doc.components.schemas || {};

  const discoveredServices = [];
  const methods = new Set(["get", "post", "put", "delete", "head", "patch"]);

  for (const { service, ok, spec } of discoveredList) {
    if (!ok || !spec?.paths) continue;
    const prefix = capitalize(service);
    let addedForService = 0;

    if (spec.components?.schemas && typeof spec.components.schemas === "object") {
      for (const [schemaName, schemaDef] of Object.entries(spec.components.schemas)) {
        doc.components.schemas[`${prefix}${schemaName}`] = rewriteSchemaRefs(schemaDef, prefix);
      }
    }

    for (const [routePath, pathItem] of Object.entries(spec.paths)) {
      if (!routePath.startsWith(`/v1/${service}`)) continue;
      if (!allowPeople && /^\/v1\/linkedin\/people(\/|$)/.test(routePath)) continue;
      if (!pathItem || typeof pathItem !== "object") continue;

      const rewritten = rewriteSchemaRefs(pathItem, prefix);
      const samplePath = routePath.replace(/\{[^}]+\}/g, "sample");
      const creditCost = costFor(samplePath);

      for (const [verb, op] of Object.entries(rewritten)) {
        if (!methods.has(verb.toLowerCase()) || !op || typeof op !== "object") continue;
        op.tags = op.tags ?? [service];
        op.security = [{ ApiKey: [] }];
        op["x-credits-cost"] = creditCost;
      }

      doc.paths[routePath] = rewritten;
      addedForService += 1;
    }

    if (addedForService > 0) discoveredServices.push(service);
  }

  if (!Object.keys(doc.components.schemas).length) {
    delete doc.components.schemas;
  }
  doc["x-discovered-services"] = discoveredServices;
  return doc;
}

async function buildUnifiedOpenApi({
  force = false,
  yamlFile = path.resolve(__dirname, "..", "openapi.yaml"),
  upstreamMap = upstreams(),
  httpClient = axios,
} = {}) {
  const now = Date.now();
  if (!force && mergedCache.value && now - mergedCache.at < OPENAPI_CACHE_MS) {
    return structuredClone(mergedCache.value);
  }

  const baseSpec = loadGatewaySpec(yamlFile);
  const discovered = await Promise.all(
    Object.entries(upstreamMap).map(([service, baseUrl]) =>
      fetchUpstreamSpec(service, baseUrl, httpClient)
    )
  );
  const merged = mergeSpecs(baseSpec, discovered);
  mergedCache = { at: Date.now(), value: merged };
  return structuredClone(merged);
}

function resetOpenApiCache() {
  mergedCache = { at: 0, value: null };
}

module.exports = {
  OPENAPI_CACHE_MS,
  parseSimpleYaml,
  parseConnectorOpenApi,
  loadGatewaySpec,
  mergeSpecs,
  buildUnifiedOpenApi,
  resetOpenApiCache,
};
