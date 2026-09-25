import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { applySpans, findLogSpans, isSensitiveKey, looksLikeHar, scrubHar, shortHash, structuralSpans } from "../js/scrub.js";

const here = dirname(fileURLToPath(import.meta.url));
const ex = (f) => readFileSync(join(here, "..", "examples", f), "utf8");
const ALL = ["secrets", "contact", "network", "financial", "government_id", "person", "identifiers"];
const DEFAULT = ["secrets", "contact", "network", "financial", "government_id", "person"];

async function clean(text, categories = DEFAULT, opts = {}) {
  return applySpans(text, await findLogSpans(text, { categories, ...opts }), opts).text;
}

const CASES = [
  ["Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "Authorization: Bearer [JWT_1]"],
  ["x-api-key: k_live_Q2eKz8LmN4pRtY7uVwXa9bC", "x-api-key: [SECRET_1]"],
  ["10:14 DEBUG [auth] Cookie: session=9f8e7d6c5b4a39281706f5e4d3c2b1a0; theme=dark", "10:14 DEBUG [auth] Cookie: session=[COOKIE_1]; theme=dark"],
  ["Set-Cookie: sid=abc123def456; Path=/; HttpOnly", "Set-Cookie: sid=[COOKIE_1]; Path=/; HttpOnly"],
  ['REDIS_PASSWORD="correct horse battery staple"', 'REDIS_PASSWORD="[SECRET_1]"'],
  ['{"password": "hunter2-Fall2026!", "remember": true}', '{"password": "[SECRET_1]", "remember": true}'],
  ["deploy --token=ghp_R4nd0mT0k3nV4lu3F0rT3st1ngPurp0s3s99 --env prod", "deploy --token=[GITHUB_TOKEN_1] --env prod"],
  ["mysql -u root -p=S3cretPass db", "mysql -u root -p=[SECRET_1] db"],
  ["GET /v2/users?access_token=ya29.a0AfH6SMBx3kL9mQ&page=2", "GET /v2/users?access_token=[TOKEN_1]&page=2"],
  ["SENTRY_DSN=https://4f8e2c1a9b7d4e6f@o123456.ingest.example.io/7654321", "SENTRY_DSN=https://[SECRET_1]@o123456.ingest.example.io/7654321"],
  ["postgres://admin:Pr0dP4ss!2026@db01.prod.internal:5432/payments", "postgres://admin:[PASSWORD_1]@[HOST_1]:5432/payments"],
  ["dump written to C:\\Users\\jwalsh\\AppData\\Local\\app.dmp", "dump written to C:\\Users\\[USER_1]\\AppData\\Local\\app.dmp"],
  ["open /home/priya/.ssh/id_rsa", "open /home/[USER_1]/.ssh/id_rsa"],
  ["card=4111 1111 1111 1111 amount=42.00", "card=[CARD_1] amount=42.00"],
];
for (const [input, expected] of CASES) {
  test(`scrubs: ${input.slice(0, 50)}`, async () => assert.equal(await clean(input), expected));
}

const KEEP = [
  "TOKEN_URL=https://login.example.com/oauth2/token",
  "retry_token_count=3",
  "LOG_LEVEL=info",
  "FEATURE_FLAGS=search,new-checkout",
  "at com.contoso.billing.PaymentService.charge(PaymentService.java:142)",
  "version=4.12.1 uptime=99.98% queue_depth=0",
  "password: ********",
  "api_key: null",
  "Cookie: theme=dark; lang=en",
  "C:\\Users\\Public\\Documents\\readme.txt",
];
for (const input of KEEP) {
  test(`leaves harmless text alone: ${input.slice(0, 50)}`, async () => assert.equal(await clean(input), input));
}

test("same value -> same placeholder everywhere; different values -> different numbers", async () => {
  const out = await clean("a jane@x.example b bob@y.example c jane@x.example");
  assert.equal(out, "a [EMAIL_1] b [EMAIL_2] c [EMAIL_1]");
});

test("identifiers are optional and off by default", async () => {
  const t = '{"user_id": "u_83hf72", "trace": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}';
  assert.equal(await clean(t), t);
  assert.equal(await clean(t, ALL), '{"user_id": "[ID_1]", "trace": "[ID_2]"}');
});

test("PEM private key blocks are removed as a whole", async () => {
  const t = "key:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\nAAAAAAAB\n-----END OPENSSH PRIVATE KEY-----\ndone";
  assert.equal(await clean(t), "key:\n[PRIVATE_KEY_1]\ndone");
});

test("placeholder modes: mask keeps no characters, hash is stable", async () => {
  const t = "email jane@x.example and jane@x.example";
  const masked = await clean(t, DEFAULT, { mode: "mask" });
  assert.ok(!masked.includes("jane") && masked.includes("••••"));
  const hashed = await clean(t, DEFAULT, { mode: "hash" });
  assert.equal(hashed, `email [EMAIL:${shortHash("jane@x.example")}] and [EMAIL:${shortHash("jane@x.example")}]`);
});

test("sensitive key detection handles snake, kebab, camel and headers", () => {
  for (const k of ["password", "DB_PASSWORD", "clientSecret", "x-api-key", "Authorization", "refresh_token", "sessionid", "AWS_SECRET_ACCESS_KEY"]) {
    assert.ok(isSensitiveKey(k), k);
  }
  for (const k of ["username", "passenger", "tokenizer", "author", "LOG_LEVEL", "page"]) assert.ok(!isSensitiveKey(k), k);
});

test("structural spans respect categories", () => {
  const s = structuralSpans("password=abc12345 user_id=u_83hf72", new Set(["secrets"]));
  assert.deepEqual(s.map((x) => x.label), ["SENSITIVE_FIELD"]);
});

// ---------------------------------------------------------------------------- examples

test("app.log example: every planted secret and PII item is removed", async () => {
  const out = await clean(ex("app.log"));
  for (const leak of ["jennifer.walsh@", "203.0.113.42", "eyJhbGci", "9f8e7d6c5b4a", "Zx81kLpQ", "Pr0dP4ss", "db01.prod.internal",
    "tom.oneill@", "4111 1111", "555-0187", "ya29.", "ghp_R4nd", "jwalsh"]) {
    assert.ok(!out.includes(leak), `leaked ${leak}`);
  }
  for (const keep of ["PaymentService.java:142", "theme=dark", "version=4.12.1", "retry_count\": 3", "gateway declined (code 51)"]) {
    assert.ok(out.includes(keep), `over-redacted ${keep}`);
  }
});

test(".env example: secrets removed, config kept", async () => {
  const out = await clean(ex(".env.example-leak"));
  for (const leak of ["Sup3r-S3cret", "horse battery", "sk-proj-", "sk_live_", "AKIAQ3", "wJalrXUtn", "xoxb-", "4f8e2c1a9b7d", "ops-lead@"]) {
    assert.ok(!out.includes(leak), `leaked ${leak}`);
  }
  for (const keep of ["APP_ENV=production", "TOKEN_URL=https://login.example.com/oauth2/token", "LOG_LEVEL=info", "MAX_RETRIES=5"]) {
    assert.ok(out.includes(keep), `over-redacted ${keep}`);
  }
});

test("HAR example: headers, cookies, query strings, bodies and URLs are cleaned structurally", async () => {
  const text = ex("network.har");
  assert.ok(looksLikeHar(text));
  const { har, stats } = await scrubHar(text, { categories: DEFAULT });
  const out = JSON.stringify(har);
  for (const leak of ["eyJhbGci", "9f8e7d6c5b4a", "AIzaSyA1b2", "k_live_Q2eK", "hunter2", "jennifer.walsh", "rt_9s8d7f", "0a1b2c3d4e5f", "555-0132"]) {
    assert.ok(!out.includes(leak), `HAR leaked ${leak}`);
  }
  assert.ok(out.includes("theme=dark"), "harmless cookie kept");
  assert.equal(har.log.entries.length, 2, "structure preserved");
  assert.equal(har.log.entries[1].response.content.text, "body{font-family:system}", "harmless body untouched");
  assert.ok(stats.headers >= 4 && stats.params >= 2 && stats.bodies >= 2, JSON.stringify(stats));
});
