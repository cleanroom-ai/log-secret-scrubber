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

const SENSITIVE_KEY = /(?:^|[_\-.\s])(?:pass(?:word|wd|phrase|code)?|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|client[_\-]?secret|auth(?:orization)?|credential|session(?:id)?|sid|cookie|signature|sig|otp|pin|refresh|bearer|x[_\-]api[_\-]key|jwt|salt|hash)(?:$|[_\-.\s])/i;
const SENSITIVE_HEADERS = new Set(["authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
  "x-access-token", "x-csrf-token", "x-xsrf-token", "x-amz-security-token", "x-goog-api-key", "api-key", "x-hub-signature",
  "x-hub-signature-256", "x-slack-signature", "x-shopify-access-token", "x-github-token", "ocp-apim-subscription-key"]);
const ID_KEY = /(?:^|[_\-.])(?:user|account|customer|client|session|request|req|trace|span|correlation|device|tenant|org|order)[_\-]?id$|^(?:uid|uuid|guid|sub|oid)$/i;
const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi;
const INTERNAL_HOST = /\b(?:[a-z0-9-]+\.)+(?:internal|corp|local|lan|intranet|svc\.cluster\.local|private)\b/gi;
const HOME_PATH = /(?:[A-Za-z]:\\Users\\|\/home\/|\/Users\/)([^\\/\s"'<>|:]+)/g;
const PEM = /-----BEGIN ([A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----[\s\S]*?-----END \1-----/g;

/** Is this key name (JSON key, header, env var, query param) one whose value is a secret? */
export function isSensitiveKey(key) {
  const k = String(key).trim();
  return SENSITIVE_HEADERS.has(k.toLowerCase()) || SENSITIVE_KEY.test(k) || SENSITIVE_KEY.test(k.replace(/([a-z])([A-Z])/g, "$1_$2"));
}
export const isIdKey = (key) => ID_KEY.test(String(key).replace(/([a-z])([A-Z])/g, "$1_$2"));
/** UI-preference cookies (theme=dark, lang=en) carry no identity; keep them readable. */
export const isHarmlessCookie = (name, value) =>
  /^(?:theme|lang|language|locale|tz|timezone|dark_?mode|color_?scheme)$/i.test(name) && String(value).length <= 12;

// ------------------------------------------------------------------ structural finders

/** `KEY=value`, `key: value`, `"key": "value"`, `--password value`, `Header: value` in free text. */
export function structuralSpans(text, categories) {
  const want = (c) => categories.has(c);
  const spans = [];
  const add = (start, end, label, category, score = 0.95) => {
    if (end > start && want(category)) spans.push({ start, end, label, category, score, source: "structure" });
  };

  // PEM private-key blocks (multi-line).
  for (const m of text.matchAll(PEM)) add(m.index, m.index + m[0].length, "PRIVATE_KEY_BLOCK", "secrets", 1);

  // key = value / key: value / "key": "value" (value quoted or bare, to end of token/line).
  // Skips "Authorization: Bearer …"-style header lines (handled below with the auth scheme kept).
  const kv = /(["']?)([A-Za-z_][\w.\-]*)\1[ \t]*(?:=|:)(?!\/\/)[ \t]*(?:(["'])((?:\\.|(?!\3)[^\\\n])*)\3|([^\s,;&"'}\]]+))/g;
  for (const m of text.matchAll(kv)) {
    const key = m[2];
    const quoted = m[4] !== undefined;
    const value = quoted ? m[4] : m[5];
    if (!value || /^(?:null|none|true|false|undefined|\*+|•+|\[\w+\]|<\w+>)$/i.test(value)) continue;
    if (SENSITIVE_HEADERS.has(key.toLowerCase()) && !quoted) continue;
    if (/^cookie$/i.test(key)) continue;
    const vStart = m.index + m[0].length - value.length - (quoted ? 1 : 0);
    if (isSensitiveKey(key)) {
      if (/^https?:\/\//i.test(value) && !/[?&](?:token|key|sig)=/i.test(value)) continue; // TOKEN_URL=https://...
      if (/^\d{1,3}$/.test(value)) continue; // e.g. retry_token_count=3
      add(vStart, vStart + value.length, /cookie/i.test(key) ? "COOKIE" : "SENSITIVE_FIELD", "secrets");
    } else if (isIdKey(key) && value.length >= 4) {
      add(vStart, vStart + value.length, "IDENTIFIER", "identifiers", 0.8);
    } else if (/^(?:user(?:name)?|login|owner|author|assignee|display_?name|full_?name|name)$/i.test(key) && value.length >= 2 &&
      !/^\d+$/.test(value)) {
      add(vStart, vStart + value.length, key.toLowerCase().includes("name") && !/user/i.test(key) ? "PERSON" : "USERNAME", "person", 0.85);
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
      if (/^(?:null|nil|none|true|false|undefined|n\/a|\*+|•+|\[\w+\]|<\w+>|\$\{\w+\})$/i.test(value)) continue;
      add(vStart + off, vStart + m[2].trimEnd().length, "SENSITIVE_HEADER", "secrets", 1);
    }
  }

  // CLI flags: --password hunter2, -p=secret, --token=abc
  for (const m of text.matchAll(/(?:^|\s)(--?(?:password|passwd|pass|pwd|token|api-key|apikey|secret|client-secret|key|auth)|-p)(?:=|\s+)(["']?)([^\s"']{3,})\2/gi)) {
    const vStart = m.index + m[0].length - m[3].length - m[2].length;
    add(vStart, vStart + m[3].length, "SENSITIVE_FIELD", "secrets");
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
  const PLACEHOLDER_VALUE = /^(?:null|nil|none|true|false|undefined|n\/a|na|empty|changeme|\*+|•+|x+|\[\w+\]|<\w+>|\$\{\w+\})$/i;
  // Rules run line-by-line (they are written for single lines); offsets are shifted back.
  let offset = 0;
  for (const line of text.split("\n")) {
    for (const s of findSpans(line, ruleCats, customTerms)) {
      if (s.category === "secrets" && PLACEHOLDER_VALUE.test(line.slice(s.start, s.end))) continue;
      rules.push({ ...s, start: s.start + offset, end: s.end + offset });
    }
    offset += line.length + 1;
  }
  let nerSpans = [];
  if (ner && (cats.has("person") || cats.has("financial") || cats.has("government_id"))) {
    offset = 0;
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
      if (isSensitiveKey(h.name) || SENSITIVE_HEADERS.has(String(h.name).toLowerCase())) {
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
  return { har, stats };
}

export const looksLikeHar = (text) => /^\s*\{[\s\S]{0,200}"log"\s*:\s*\{[\s\S]*"entries"\s*:/.test(text.slice(0, 5000));
