// Log / config / HAR scrubbing on top of the shared cleanroom-ai rules.
// Everything is plain string processing so it runs in the browser and in Node tests.

import { findSpans, mergeSpans, resolveOverlaps } from "./core.js";

/** Placeholder names per detected label (stable, human-readable). */
const PLACEHOLDER = {
  URL_CREDENTIAL: "SECRET",
  EMAIL: "EMAIL", PHONE: "PHONE", IP_ADDRESS: "IP", MAC_ADDRESS: "MAC", CREDIT_CARD: "CARD", IBAN: "IBAN",
  BANK_ACCOUNT: "BANK_ACCOUNT", ROUTING_NUMBER: "ROUTING", CRYPTO_WALLET: "WALLET", US_SSN: "SSN", PASSPORT: "PASSPORT",
  DRIVER_LICENSE: "DRIVER_LICENSE", DATE_OF_BIRTH: "DOB", PERSON: "NAME", ADDRESS: "ADDRESS", CUSTOM: "REDACTED",
  JWT: "JWT", PRIVATE_KEY: "PRIVATE_KEY", AWS_ACCESS_KEY: "AWS_KEY", GITHUB_TOKEN: "GITHUB_TOKEN", AI_API_KEY: "API_KEY",
  HUGGINGFACE_TOKEN: "HF_TOKEN", SLACK_TOKEN: "SLACK_TOKEN", GOOGLE_API_KEY: "GOOGLE_KEY", STRIPE_KEY: "STRIPE_KEY",
  URL_PASSWORD: "PASSWORD", URL_TOKEN: "TOKEN", BEARER_TOKEN: "TOKEN", CONNECTION_STRING_KEY: "SECRET",
  PASSWORD_OR_SECRET: "SECRET", POSSIBLE_SECRET: "SECRET", COOKIE: "COOKIE", SENSITIVE_HEADER: "SECRET",
  SENSITIVE_FIELD: "SECRET", PRIVATE_KEY_BLOCK: "PRIVATE_KEY", IDENTIFIER: "ID", USERNAME: "USER", HOSTNAME: "HOST",
  HOME_PATH: "USER",
};

export const LOG_CATEGORIES = {
  secrets: "API keys, tokens, passwords, cookies, private keys",
  contact: "Emails and phone numbers",
  network: "IP / MAC addresses, internal hostnames",
  financial: "Card numbers, IBANs, bank accounts",
  government_id: "SSNs, passports, driver licenses",
  person: "Names, usernames, home-folder paths",
  identifiers: "User / session / request IDs, UUIDs",
};
export const DEFAULT_LOG_CATEGORIES = ["secrets", "contact", "network", "financial", "government_id", "person"];

const DEFAULT_IGNORABLE = /[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0]/g;
const SENSITIVE_KEY = /(?:^|[_\-.\s])(?:pass(?:word|wd|phrase|code)?|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|client[_\-]?(?:secret|key|certificate)(?:[_\-]?data)?|auth(?:orization|[_\-]?provider)?|credential|session(?:id)?|sid|cookie|signature|sig|otp|pin|refresh|id[_\-]?token|bearer|x[_\-]api[_\-]key|jwt|salt|hash)(?:$|[_\-.\s])/i;
const SENSITIVE_HEADERS = new Set(["authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
  "x-access-token", "x-csrf-token", "x-xsrf-token", "x-amz-security-token", "x-goog-api-key", "api-key", "x-hub-signature",
  "x-hub-signature-256", "x-slack-signature", "x-shopify-access-token", "x-github-token", "ocp-apim-subscription-key"]);
const ID_KEY = /(?:^|[_\-.])(?:user|account|customer|client|session|request|req|trace|span|correlation|device|tenant|org|order)[_\-]?id$|^(?:uid|uuid|guid|sub|oid)$/i;
const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi;
const INTERNAL_HOST = /\b(?:[a-z0-9-]+\.)+(?:internal|corp|local|lan|intranet|svc\.cluster\.local|private)\b/gi;
const HOME_PATH = /(?:[A-Za-z]:\\Users\\|\/home\/|\/Users\/)([^\\/\s"'<>|:]+)/g;
const PEM = /-----BEGIN ([A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----[\s\S]*?-----END \1-----/g;
const PLACEHOLDER_VALUE = /^(?:null|nil|none|true|false|undefined|n\/a|na|empty|changeme|change[-_ ]?me|replace[-_ ]?me|redacted|masked|example|sample|dummy|todo|your[-_ ]?(?:api[-_ ]?key|token|password|secret)|\*+|•+|x+|\[[A-Z_]+(?:_\d+)?\]|<[\w.-]+>|\$\{[\w.-]+\})$/i;
const MAX_STRUCTURAL_LINE = 32 * 1024;
const MAX_STRUCTURAL_VALUE = 8 * 1024;
const normalizeKey = (key) => String(key).normalize("NFKC").replace(DEFAULT_IGNORABLE, "").trim();
const looksSecretishJsonValue = (value) =>
  /^(?=.{24,}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z0-9._~+/=-]+$/.test(String(value));

export const isPlaceholderValue = (value) => PLACEHOLDER_VALUE.test(String(value).trim());

/** Is this key name (JSON key, header, env var, query param) one whose value is a secret? */
export function isSensitiveKey(key) {
  const k = normalizeKey(key);
  return SENSITIVE_HEADERS.has(k.toLowerCase()) || SENSITIVE_KEY.test(k) || SENSITIVE_KEY.test(k.replace(/([a-z])([A-Z])/g, "$1_$2"));
}
export const isIdKey = (key) => ID_KEY.test(normalizeKey(key).replace(/([a-z])([A-Z])/g, "$1_$2"));
/** UI-preference cookies (theme=dark, lang=en) carry no identity; keep them readable. */
export const isHarmlessCookie = (name, value) =>
  /^(?:theme|lang|language|locale|tz|timezone|dark_?mode|color_?scheme)$/i.test(name) && String(value).length <= 12;

// ------------------------------------------------------------------ structural finders

/** `KEY=value`, `key: value`, `"key": "value"`, `--password value`, `Header: value` in free text. */
export function structuralSpans(text, categories) {
  const cats = categories instanceof Set ? categories : new Set(categories);
  const want = (c) => cats.has(c);
  const spans = [];
  const add = (start, end, label, category, score = 0.95) => {
    if (end > start && want(category)) spans.push({ start, end, label, category, score, source: "structure" });
  };

  // PEM private-key blocks (multi-line).
  for (const m of text.matchAll(PEM)) add(m.index, m.index + m[0].length, "PRIVATE_KEY_BLOCK", "secrets", 1);

  for (const s of jsonStructuralSpans(text, cats)) spans.push(s);

  // YAML block/folded scalars under sensitive keys: redact marker + indented body.
  const yaml = /^([ \t-]*)(["']?)([^"'#:\n]+)\2[ \t]*:[ \t]*([|>][+-]?)/gm;
  for (const m of text.matchAll(yaml)) {
    const key = m[3].trim();
    if (!isSensitiveKey(key)) continue;
    const indent = (m[1].replace(/-\s*$/, "").match(/[ \t]*/)?.[0] ?? "").length;
    const markerStart = m.index + m[0].lastIndexOf(m[4]);
    let cursor = text.indexOf("\n", m.index);
    if (cursor < 0) cursor = text.length;
    let end = cursor;
    if (cursor < text.length) cursor++;
    while (cursor < text.length) {
      const nl = text.indexOf("\n", cursor);
      const lineEnd = nl < 0 ? text.length : nl;
      const line = text.slice(cursor, lineEnd).replace(/\r$/, "");
      if (line.trim()) {
        const nextIndent = (line.match(/^[ \t]*/)?.[0] ?? "").length;
        if (nextIndent <= indent) break;
      }
      end = lineEnd;
      cursor = nl < 0 ? text.length : nl + 1;
    }
    add(markerStart, end, "SENSITIVE_FIELD", "secrets", 1);
  }

  // key = value / key: value / "key": "value" (value quoted or bare, to end of token/line).
  // Skips "Authorization: ******"-style header lines (handled below with the auth scheme kept).
  const kv = /(["']?)([A-Za-z_][A-Za-z0-9_.\-\u200b-\u200f\u2060-\u206f\ufeff]*)\1[ \t]*(=|:)(?!\/\/)[ \t]*(?:(["'])((?:\\.|(?!\4)[^\\\n])*)\4|(\$\{[\w.-]+\}|[^\s,;&"'{\[\]}()]+))/g;
  let lineOffset = 0;
  for (const rawLine of text.split("\n")) {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (line.length <= MAX_STRUCTURAL_LINE) {
      for (const m of line.matchAll(kv)) {
        const key = m[2];
        const quoted = m[5] !== undefined;
        const value = quoted ? m[5] : m[6];
        if (!value || value.length > MAX_STRUCTURAL_VALUE || isPlaceholderValue(value)) continue;
        if (SENSITIVE_HEADERS.has(normalizeKey(key).toLowerCase()) && !quoted) continue;
        if (/^cookie$/i.test(key)) continue;
        if (m[3] === ":" && /\.(?:java|js|mjs|cjs|ts|tsx|jsx|py|go|rb|cs|cpp|cc|c|h|hpp|kt|scala)$/i.test(key) && /^\d+\)?$/.test(value)) continue;
        const vStart = lineOffset + m.index + m[0].length - value.length - (quoted ? 1 : 0);
        if (isSensitiveKey(key)) {
          if (/^https?:\/\//i.test(value) && !/[?&](?:token|key|sig)=/i.test(value)) continue; // TOKEN_URL=https://...
          if (/^\d{1,3}$/.test(value)) continue; // e.g. retry_token_count=3
          add(vStart, vStart + value.length, /cookie/i.test(key) ? "COOKIE" : "SENSITIVE_FIELD", "secrets");
        } else if (isIdKey(key) && value.length >= 4) {
          add(vStart, vStart + value.length, "IDENTIFIER", "identifiers", 0.8);
        } else if (/^(?:user(?:name)?|login|owner|author|assignee|display_?name|full_?name|name)$/i.test(normalizeKey(key)) && value.length >= 2 &&
          !/^\d+$/.test(value)) {
          add(vStart, vStart + value.length, normalizeKey(key).toLowerCase().includes("name") && !/user/i.test(key) ? "PERSON" : "USERNAME", "person", 0.85);
        }
      }
    }
    lineOffset += rawLine.length + 1;
  }

  // .netrc grammar: machine ... login NAME password SECRET account NAME.
  lineOffset = 0;
  for (const rawLine of text.split("\n")) {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (line.length <= MAX_STRUCTURAL_LINE && /\b(?:machine|default)\b/i.test(line)) {
      for (const m of line.matchAll(/\b(password|login|account)\s+([^\s]+)/gi)) {
        const value = m[2];
        if (!value || isPlaceholderValue(value)) continue;
        const start = lineOffset + m.index + m[0].length - value.length;
        add(start, start + Math.min(value.length, MAX_STRUCTURAL_VALUE), /^password$/i.test(m[1]) ? "SENSITIVE_FIELD" : "USERNAME", /^password$/i.test(m[1]) ? "secrets" : "person");
      }
    }
    lineOffset += rawLine.length + 1;
  }

  if (text.length > MAX_STRUCTURAL_LINE && !text.includes("\n")) return spans;

  // XML element text such as <password>secret</password>; attributes are handled by key=value.
  for (const m of text.matchAll(/<([A-Za-z_][\w:.-]*)(?:\s[^>]*)?>([^<]*)<\/\1>/g)) {
    const tag = m[1].split(":").pop();
    const value = m[2];
    if (isSensitiveKey(tag) && value.trim() && !isPlaceholderValue(value.trim())) {
      const start = m.index + m[0].indexOf(value);
      add(start, start + value.length, "SENSITIVE_FIELD", "secrets", 1);
    }
  }

  // Multipart form-data body parts in HAR postData.text.
  for (const m of text.matchAll(/Content-Disposition:[^\r\n]*\bname=(["'])([^"']+)\1[^\r\n]*(?:\r?\n[^\r\n]*)*\r?\n\r?\n([\s\S]*?)(?=\r?\n--[^\r\n]+|$)/gi)) {
    const value = m[3].replace(/\r?\n$/, "");
    if (isSensitiveKey(m[2]) && value && !isPlaceholderValue(value.trim())) {
      const start = m.index + m[0].lastIndexOf(m[3]);
      add(start, start + value.length, "SENSITIVE_FIELD", "secrets", 1);
    }
  }

  // HTTP header lines: "Authorization: Bearer x", "Cookie: a=b; c=d" — at line start or after a
  // log prefix ("… DEBUG [auth] Cookie: …"). Only known sensitive header names are matched mid-line.
  const headerNames = [...SENSITIVE_HEADERS].map((h) => h.replace(/[-]/g, "[-_]")).join("|");
  for (const m of text.matchAll(new RegExp(`(?:^|[\\s\\[\\]>*|])(${headerNames})[ \\t]*:[ \\t]*(.+)$`, "gim"))) {
    const name = m[1].toLowerCase().replaceAll("_", "-");
    const vStart = m.index + m[0].length - m[2].length;
    if (name === "cookie" || name === "set-cookie") {
      // redact each cookie value, keep names and attributes readable; harmless prefs stay.
      for (const c of m[2].matchAll(/(?:^|;\s*)([^=;\s]+)=([^;]*)/g)) {
        const attr = /^(?:path|domain|expires|max-age|samesite|secure|httponly|priority|partitioned)$/i.test(c[1]);
        if (attr || isHarmlessCookie(c[1], c[2]) || !c[2].trim()) continue;
        const s = vStart + c.index + c[0].length - c[2].length;
        add(s, s + c[2].length, "COOKIE", "secrets", 1);
      }
    } else {
      const scheme = /^(?:Bearer|Basic|Token|Digest|ApiKey|Key|SAPISIDHASH|AWS4-HMAC-SHA256)\s+/i.exec(m[2]);
      const off = scheme ? scheme[0].length : 0;
      const value = m[2].slice(off).trimEnd();
      if (isPlaceholderValue(value)) continue;
      add(vStart + off, vStart + m[2].trimEnd().length, "SENSITIVE_HEADER", "secrets", 1);
    }
  }

  // CLI flags: --password hunter2, -p=secret, --token=abc
  for (const m of text.matchAll(/(?:^|\s)(--?(?:password|passwd|pass|pwd|token|api-key|apikey|secret|client-secret|key|auth)|-p)(?:=|\s+)(["']?)([^\s"']{3,})\2/gi)) {
    const vStart = m.index + m[0].length - m[3].length - m[2].length;
    if (!isPlaceholderValue(m[3]) && want("secrets")) {
      spans.push({ start: vStart, end: vStart + m[3].length, label: "SENSITIVE_FIELD", category: "secrets", score: 1, source: "structure", strong: true });
    }
  }

  // Query-string parameters with sensitive names anywhere in URLs.
  for (const m of text.matchAll(/[?&]([A-Za-z_][\w.\-]*)=([^&\s#"']+)/g)) {
    if (!isSensitiveKey(m[1])) continue;
    const vStart = m.index + m[0].length - m[2].length;
    add(vStart, vStart + m[2].length, "URL_TOKEN", "secrets");
  }

  // Credentials in URL userinfo that aren't user:password (e.g. Sentry DSN "https://<key>@host").
  for (const m of text.matchAll(/[a-z][a-z0-9+.-]*:\/\/([^\s:/@]{8,})@[\w.-]+/gi)) {
    if (/\d/.test(m[1]) && /[a-z]/i.test(m[1])) {
      const s = m.index + m[0].indexOf(m[1]);
      spans.push({ start: s, end: s + m[1].length, label: "URL_CREDENTIAL", category: "secrets", score: 1, source: "structure", strong: true });
    }
  }

  for (const m of text.matchAll(UUID)) add(m.index, m.index + m[0].length, "IDENTIFIER", "identifiers", 0.7);
  for (const m of text.matchAll(INTERNAL_HOST)) add(m.index, m.index + m[0].length, "HOSTNAME", "network", 0.8);
  for (const m of text.matchAll(HOME_PATH)) {
    const s = m.index + m[0].length - m[1].length;
    if (!/^(?:Public|Default|All Users|shared|runner|root)$/i.test(m[1])) add(s, s + m[1].length, "HOME_PATH", "person", 0.85);
  }
  return spans;
}


function jsonStructuralSpans(text, cats) {
  if (!cats.has("secrets")) return [];
  const spans = [];
  const add = (start, end) => {
    if (end > start && !isPlaceholderValue(text.slice(start, end))) {
      spans.push({ start, end, label: "SENSITIVE_FIELD", category: "secrets", score: 1, source: "json" });
    }
  };
  const collect = (src, base, mapper = null) => {
    const mapStart = (i) => mapper ? mapper[i] : base + i;
    const mapEnd = (i) => mapper ? (mapper[i - 1] ?? mapper[i] ?? mapper[mapper.length - 1]) + 1 : base + i;
    const ws = (i) => { while (i < src.length && /\s/.test(src[i])) i++; return i; };
    const parseString = (i) => {
      if (src[i] !== "\"") return null;
      const start = i++;
      let out = "", map = [];
      while (i < src.length) {
        const p = i;
        const ch = src[i++];
        if (ch === "\"") return { start, end: i, contentStart: start + 1, contentEnd: i - 1, value: out, map };
        if (ch === "\\" && i < src.length) {
          const esc = src[i++];
          if (esc === "u" && i + 4 <= src.length) {
            out += String.fromCharCode(parseInt(src.slice(i, i + 4), 16));
            map.push(mapStart(p));
            i += 4;
          } else {
            out += ({ "\"": "\"", "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" }[esc] ?? esc);
            map.push(mapStart(p));
          }
        } else {
          out += ch;
          map.push(mapStart(p));
        }
      }
      return null;
    };
    const nested = (tok) => {
      for (let i = 0; i < tok.value.length; i++) {
        if (tok.value[i] !== "{" && tok.value[i] !== "[") continue;
        const sub = tok.value.slice(i);
        try { JSON.parse(sub); } catch { continue; }
        collect(sub, 0, tok.map.slice(i));
        break;
      }
    };
    const parsePrimitive = (i, sensitive) => {
      const start = i;
      while (i < src.length && !/[\s,\]}]/.test(src[i])) i++;
      if (sensitive && i > start && src[start] !== "{" && src[start] !== "[") add(mapStart(start), mapEnd(i));
      return i;
    };
    const parseValue = (i, key = "", inherited = false) => {
      i = ws(i);
      const sensitive = inherited || (key && isSensitiveKey(key));
      if (src[i] === "\"") {
        const tok = parseString(i);
        if (!tok) return i;
        if (sensitive || looksSecretishJsonValue(tok.value)) add(mapStart(tok.contentStart), mapEnd(tok.contentEnd));
        nested(tok);
        return tok.end;
      }
      if (src[i] === "{") return parseObject(i, sensitive && !/^(?:auth|authorization|auth-provider)$/i.test(normalizeKey(key)));
      if (src[i] === "[") return parseArray(i, sensitive);
      return parsePrimitive(i, sensitive);
    };
    const parseObject = (i, inherited = false) => {
      i++;
      for (;;) {
        i = ws(i);
        if (src[i] === "}") return i + 1;
        const keyTok = parseString(i);
        if (!keyTok) return i;
        nested(keyTok);
        i = ws(keyTok.end);
        if (src[i] !== ":") return i;
        i = parseValue(i + 1, keyTok.value, inherited);
        i = ws(i);
        if (src[i] === ",") { i++; continue; }
        if (src[i] === "}") return i + 1;
        return i;
      }
    };
    const parseArray = (i, inherited = false) => {
      i++;
      for (;;) {
        i = ws(i);
        if (src[i] === "]") return i + 1;
        i = parseValue(i, "", inherited);
        i = ws(i);
        if (src[i] === ",") { i++; continue; }
        if (src[i] === "]") return i + 1;
        return i;
      }
    };
    parseValue(ws(0));
  };
  const tryCollect = (src, base) => {
    try { JSON.parse(src.trim()); } catch { return; }
    const lead = src.length - src.trimStart().length;
    collect(src.trim(), base + lead);
  };
  tryCollect(text, 0);
  let offset = 0;
  for (const line of text.split("\n")) {
    if (line.trim() && line.trim() !== text.trim()) tryCollect(line, offset);
    offset += line.length + 1;
  }
  return spans;
}

// ------------------------------------------------------------------------ scrubbing

/**
 * Find sensitive spans in `text`.
 * @returns {Array<{start,end,label,category,score,source,value}>} sorted, non-overlapping
 */
export async function findLogSpans(text, { categories = DEFAULT_LOG_CATEGORIES, customTerms = [], ner = null } = {}) {
  const cats = new Set(categories);
  const ruleCats = [...cats].filter((c) => c !== "identifiers");
  const structural = structuralSpans(text, cats);
  const rules = [];
  for (const s of findSpans(text, ruleCats, customTerms)) {
    if (s.category === "secrets" && isPlaceholderValue(text.slice(s.start, s.end))) continue;
    rules.push(s);
  }
  let nerSpans = [];
  if (ner && (cats.has("person") || cats.has("financial") || cats.has("government_id"))) {
    let offset = 0;
    const nerCats = new Set([...cats].filter((c) => ["person", "location", "government_id", "financial"].includes(c)));
    for (const line of text.split("\n")) {
      // Names rarely appear in machine-looking lines; only run the model on prose-ish lines.
      if (line.length > 3 && /[a-z]{3,}\s+[A-Z][a-z]+/.test(line) && line.length < 2000) {
        for (const s of await ner.find(line, nerCats)) nerSpans.push({ ...s, start: s.start + offset, end: s.end + offset });
      }
      offset += line.length + 1;
    }
  }
  // Specific rules (keys, cards, emails…) win; structural spans fill in; names last. A structural
  // value that fully contains a shorter rule hit (quoted passphrase vs its first word) wins.
  const ruleList = rules.map((s) => ({ ...s, prio: s.label === "POSSIBLE_SECRET" ? 5 : 1 }));
  const structList = structural.map((s) => ({ ...s, prio: s.strong ? 0 : s.category === "identifiers" ? 6 : 3 }));
  for (const st of structList) {
    if (st.category === "secrets" && ruleList.some((r) => r.category === "secrets" && r.start >= st.start && r.end <= st.end && r.end - r.start < st.end - st.start)) {
      st.prio = 0;
    }
  }
  const merged = mergeSpans(resolveOverlaps([...ruleList, ...structList]), nerSpans);
  return merged.map((s) => ({ ...s, value: text.slice(s.start, s.end) }));
}

/**
 * Replace spans with consistent typed placeholders: the same value always maps to the same
 * placeholder ([EMAIL_1] everywhere), so the scrubbed log is still debuggable.
 * mode: "placeholder" | "mask" (keep length, •) | "hash" (short stable hash, same value → same tag)
 */
export function applySpans(text, spans, { mode = "placeholder", selected = null } = {}) {
  const counters = new Map();
  const assigned = new Map();
  const chosen = spans.filter((s) => !selected || selected.has(s.id ?? `${s.start}:${s.end}`)).sort((a, b) => a.start - b.start);
  let out = "";
  let last = 0;
  const mapping = [];
  const pieces = []; // [{text}|{tag, span}] — lets the UI highlight exactly what is exported
  for (const s of chosen) {
    if (s.start < last) continue;
    const kind = PLACEHOLDER[s.label] ?? "REDACTED";
    const key = `${kind}\u0000${s.value}`;
    let tag = assigned.get(key);
    if (!tag) {
      const n = (counters.get(kind) || 0) + 1;
      counters.set(kind, n);
      tag = mode === "mask" ? "•".repeat(Math.max(4, Math.min(s.value.length, 24)))
        : mode === "hash" ? `[${kind}:${shortHash(s.value)}]`
        : `[${kind}_${n}]`;
      assigned.set(key, tag);
      mapping.push({ tag, label: s.label, category: s.category });
    }
    pieces.push({ text: text.slice(last, s.start) }, { tag, span: s });
    out += text.slice(last, s.start) + tag;
    last = s.end;
  }
  pieces.push({ text: text.slice(last) });
  out += text.slice(last);
  return { text: out, mapping, pieces };
}

/** FNV-1a 32-bit, base36: stable across runs, not reversible for real secrets at this length. */
export function shortHash(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(36).padStart(7, "0").slice(0, 7);
}

// -------------------------------------------------------------------------------- HAR

/**
 * Scrub a HAR (HTTP Archive) file structurally: sensitive headers, cookies, query params,
 * auth in URLs, and request/response bodies (scrubbed as text). Returns {har, stats}.
 */
export async function scrubHar(harText, opts = {}) {
  const har = JSON.parse(harText);
  const stats = { entries: 0, headers: 0, cookies: 0, params: 0, bodies: 0 };
  const scrubText = async (t) => {
    if (typeof t !== "string" || !t) return t;
    const spans = await findLogSpans(t, opts);
    if (!spans.length) return t;
    stats.bodies++;
    return applySpans(t, spans, opts).text;
  };
  const scrubHeaders = (list = []) => {
    for (const h of list) {
      if (isSensitiveKey(h.name) || SENSITIVE_HEADERS.has(normalizeKey(h.name).toLowerCase())) {
        if (/^cookie$/i.test(h.name)) {
          h.value = String(h.value).replace(/(^|;\s*)([^=;\s]+)=([^;]*)/g, (all, sep, n, v) => (isHarmlessCookie(n, v) ? all : `${sep}${n}=[COOKIE]`));
        } else if (/^set-cookie$/i.test(h.name)) h.value = String(h.value).replace(/^([^=;\s]+)=([^;]*)/, "$1=[COOKIE]");
        else h.value = String(h.value).replace(/^((?:Bearer|Basic|Token)\s+)?.*$/i, (_, s = "") => `${s}[SECRET]`);
        stats.headers++;
      }
    }
  };
  const scrubCookies = (list = []) => {
    for (const c of list) {
      if (isHarmlessCookie(c.name, c.value)) continue;
      c.value = "[COOKIE]";
      stats.cookies++;
    }
  };
  const scrubUrl = (u) => {
    try {
      const url = new URL(u);
      if (url.password) url.password = "[PASSWORD]";
      if (url.username) url.username = "[USER]";
      for (const [k] of [...url.searchParams]) {
        if (isSensitiveKey(k)) {
          url.searchParams.set(k, "[TOKEN]");
          stats.params++;
        }
      }
      return decodeURI(url.toString());
    } catch {
      return u;
    }
  };
  const scrubAnyString = async (value, key = "") => {
    if (typeof value !== "string" || !value) return value;
    const cleaned = /(?:^|url$|URL$|title$|redirectURL$)/.test(String(key)) || /^https?:\/\//i.test(value) ? scrubUrl(value) : value;
    return scrubText(cleaned);
  };
  for (const e of har?.log?.entries ?? []) {
    stats.entries++;
    const rq = e.request ?? {}, rs = e.response ?? {};
    if (rq.url) rq.url = scrubUrl(rq.url);
    scrubHeaders(rq.headers);
    scrubHeaders(rs.headers);
    scrubCookies(rq.cookies);
    scrubCookies(rs.cookies);
    for (const q of rq.queryString ?? []) {
      if (isSensitiveKey(q.name)) {
        q.value = "[TOKEN]";
        stats.params++;
      }
    }
    if (rq.postData) {
      for (const p of rq.postData.params ?? []) if (isSensitiveKey(p.name)) p.value = "[SECRET]";
      rq.postData.text = await scrubText(rq.postData.text);
    }
    if (rs.content?.text && rs.content.encoding !== "base64") rs.content.text = await scrubText(rs.content.text);
    else if (rs.content?.encoding === "base64") {
      rs.content.text = ""; // binary bodies can't be reviewed; drop them
      rs.content.comment = "removed by cleanroom-ai log scrubber";
    }
    if (rs.redirectURL) rs.redirectURL = scrubUrl(rs.redirectURL);
  }
  for (const p of har?.log?.pages ?? []) if (p.title) p.title = scrubUrl(p.title);
  const walk = async (node, key = "", seen = new Set()) => {
    if (!node || typeof node !== "object" || seen.has(node)) return;
    seen.add(node);
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        if (typeof node[i] === "string") node[i] = await scrubAnyString(node[i], key);
        else await walk(node[i], key, seen);
      }
      return;
    }
    for (const [k, v] of Object.entries(node)) {
      if (typeof v === "string") node[k] = await scrubAnyString(v, k);
      else await walk(v, k, seen);
    }
  };
  await walk(har);
  return { har, stats };
}

export const looksLikeHar = (text) => /^\s*\{[\s\S]{0,200}"log"\s*:\s*\{[\s\S]*"entries"\s*:/.test(text.slice(0, 5000));
