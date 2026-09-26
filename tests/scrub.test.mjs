import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
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

const githubToken = "ghp_" + "A".repeat(24);

const CASES = [
  ["Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "Authorization: Bearer [JWT_1]"],
  ["x-api-key: k_live_Q2eKz8LmN4pRtY7uVwXa9bC", "x-api-key: [SECRET_1]"],
  ["10:14 DEBUG [auth] Cookie: session=9f8e7d6c5b4a39281706f5e4d3c2b1a0; theme=dark", "10:14 DEBUG [auth] Cookie: session=[COOKIE_1]; theme=dark"],
  ["Set-Cookie: sid=abc123def456; Path=/; HttpOnly", "Set-Cookie: sid=[COOKIE_1]; Path=/; HttpOnly"],
  ['REDIS_PASSWORD="correct horse battery staple"', 'REDIS_PASSWORD="[SECRET_1]"'],
  ['{"password": "hunter2-Fall2026!", "remember": true}', '{"password": "[SECRET_1]", "remember": true}'],
  [`deploy --token=${githubToken} --env prod`, "deploy --token=[SECRET_1] --env prod"],
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
  const t = `key:
${"-----BEGIN OPENSSH"} PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ
AAAAAAAB
${"-----END OPENSSH"} PRIVATE KEY-----
done`;
  assert.equal(await clean(t), "key:\n[PRIVATE_KEY_1]\ndone");
});

test("shared core v0.1.4 multiline phone and Basic auth fixes flow through logs", async () => {
  const basic = Buffer.from("bot:core-basic-secret").toString("base64");
  const out = await clean(`callback +1 (206)\n555-0187\nAuthorization: Basic ${basic}`);
  assert.ok(!out.includes("555-0187"));
  assert.ok(out.includes("Authorization: Basic [SECRET_1]"));
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
  for (const leak of ["Sup3r-S3cret", "horse battery", `${"sk"}-proj-`, `${"sk"}_live_`, "AKIAQ3", "wJalrXUtn", `${"xox"}b-`, "4f8e2c1a9b7d", "ops-lead@"]) {
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

test("YAML block and folded scalar secrets are removed as a whole", async () => {
  const a = "YAMLBLOCK_" + "Aa9".repeat(8) + "_END";
  const b = "YAMLFOLD_" + "Bb8".repeat(8) + "_END";
  const out = await clean(`database:\n  password: |\n    ${a}\n  user: app\nservice:\n  api_key: >\n    ${b}\n  mode: prod`, ["secrets"]);
  assert.ok(!out.includes(a) && !out.includes(b));
  assert.match(out, /password: \[SECRET_\d+\]\n  user: app/);
  assert.match(out, /api_key: \[SECRET_\d+\]\n  mode: prod/);
});

test("HAR recursive scrub covers URL headers, multipart text, websockets and initiators", async () => {
  const s = "HARSECRET_" + "Aa9".repeat(8) + "_END";
  const ws = "WSSECRET_" + "Bb8".repeat(8) + "_END";
  const har = { log: { entries: [{ request: {
    url: `https://api.example.test/path?access_token=${s}`,
    headers: [{ name: "Referer", value: `https://app.example.test/?token=${s}` }],
    queryString: [{ name: "access_token", value: s }],
    cookies: [],
    postData: { mimeType: "multipart/form-data", params: [], text: `--x\r\nContent-Disposition: form-data; name="password"\r\n\r\n${s}\r\n--x--` },
  }, response: {
    headers: [{ name: "Location", value: `https://login.example.test/cb?refresh_token=${s}` }],
    cookies: [], content: { text: "ok" }, redirectURL: `https://next.example.test/?id_token=${s}`,
  }, _webSocketMessages: [{ data: `{"token":"${ws}"}` }], _initiator: { url: `https://cdn.example.test/app.js?api_key=${s}`, stack: { callFrames: [{ url: `https://cdn.example.test/chunk.js?api_key=${s}` }] } } }] } };
  const { har: cleanHar } = await scrubHar(JSON.stringify(har), { categories: DEFAULT });
  const out = JSON.stringify(cleanHar);
  assert.ok(!out.includes(s) && !out.includes(ws), out);
  JSON.parse(out);
});

test(".netrc password/login/account, kubeconfig keys and XML sensitive element text are scrubbed", async () => {
  const net = "NETRC_" + "Aa9".repeat(8) + "_END";
  const login = "bot-user";
  const kubeKey = Buffer.from(`${"-----BEGIN"} PRIVATE KEY-----
KUBE
${"-----END"} PRIVATE KEY-----`).toString("base64");
  const xml = "XMLSECRET_" + "Cc7".repeat(8) + "_END";
  const out = await clean([
    `machine api.example.test login ${login} password ${net} account prod`,
    `users:\n- user:\n    client-key-data: ${kubeKey}\n    client-certificate-data: ${kubeKey}\n    id-token: ${net}\n    refresh-token: ${net}`,
    `<root token="${xml}"><password>${xml}</password><mode>prod</mode></root>`,
  ].join("\n"));
  for (const leak of [net, login, kubeKey, xml]) assert.ok(!out.includes(leak), `leaked ${leak}`);
  assert.ok(out.includes("<mode>prod</mode>"));
});

test("JSON parsing handles escaped JSON strings, unicode keys and auth objects without corrupting JSON", async () => {
  const a = "ESCJSON_" + "Aa9".repeat(8) + "_END";
  const b = "UNIJSON_" + "Bb8".repeat(8) + "_END";
  const c = "JSONPASS_" + "Cc7".repeat(8) + "_END";
  const one = await clean(`{"msg":"payload {\\"access_token\\":\\"${a}\\"}"}`);
  const two = await clean(`{"pass\\u0077ord":"${b}"}`);
  const three = await clean(`{"auth":{"Password":"${c}"},"ok":true}`);
  assert.ok(!one.includes(a) && !two.includes(b) && !three.includes(c));
  JSON.parse(one); JSON.parse(two); JSON.parse(three);
  assert.equal(JSON.parse(three).ok, true);
});

test("stack frame line numbers and placeholder values remain visible", async () => {
  const s = "STACKSECRET_" + "Aa9".repeat(8) + "_END";
  const out = await clean(`Error: login failed token=${s}\n    at com.example.Auth.login(Auth.java:42)`);
  assert.ok(!out.includes(s));
  assert.ok(out.includes("Auth.java:42)"));
  const placeholders = "password=changeme\napi_key=xxx\ntoken=<token>\nsecret=${VAR}\npassword=your-api-key\napi_key=REDACTED";
  assert.equal(await clean(placeholders), placeholders);
});

test("zero-width characters in sensitive key names are normalized", async () => {
  const s = "ZWSECRET_" + "Aa9".repeat(8) + "_END";
  const out = await clean(`pass\u200bword=${s}`);
  assert.ok(!out.includes(s));
});

test("structural key-value scanning is bounded on huge non-secret values", () => {
  const text = "x=" + "A".repeat(128 * 1024);
  const t0 = performance.now();
  const spans = structuralSpans(text, new Set(["secrets"]));
  const ms = performance.now() - t0;
  assert.equal(spans.length, 0);
  assert.ok(ms < 500, `structuralSpans took ${ms.toFixed(1)}ms`);
});
