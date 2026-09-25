// Real-browser check: paste/examples → clean output, no leaks, HAR structural export, and the
// page never uploads anything or contacts another host. Usage: node tests/e2e.browser.mjs [baseUrl]
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { openApp } from "@cleanroom-ai/core/testing/browser.mjs";

const base = process.argv[2] || "http://127.0.0.1:8102/";
const shotsDir = fileURLToPath(new URL("../.cache/e2e/", import.meta.url));
const app = await openApp(base, { shotsDir });
const { page } = app;
await app.assertLogo();

const done = () => page.evaluate(() => Number(document.body.dataset.scanDone || 0));
async function waitNextScan(prev) {
  await page.waitForFunction((p) => Number(document.body.dataset.scanDone || 0) > p, prev, { timeout: 120_000 });
}

async function runExample(name, leaks, keeps) {
  const prev = await done();
  await page.getByRole("button", { name, exact: true }).click();
  await waitNextScan(prev);
  const status = await page.locator("#status").innerText();
  const out = await page.locator("#output").innerText();
  console.log(`${name}: ${status}`);
  for (const l of leaks) assert.ok(!out.includes(l), `${name}: leaked ${l}`);
  for (const k of keeps) assert.ok(out.includes(k), `${name}: over-redacted ${k}`);
  await app.shot(name.replace(/\W+/g, "_"));
  return out;
}

await runExample("App log",
  ["jennifer.walsh@", "eyJhbGci", "9f8e7d6c5b4a", "Pr0dP4ss", "4111 1111", "ghp_R4nd", "jwalsh", "Priya Raman"],
  ["PaymentService.java:142", "theme=dark", "[EMAIL_1]", "[NAME_1]"]);
await runExample(".env file", ["sk-proj-", "sk_live_", "AKIAQ3", "horse battery", "xoxb-"], ["APP_ENV=production", "LOG_LEVEL=info"]);
await runExample("HAR file", ["hunter2", "rt_9s8d7f", "AIzaSyA1b2", "eyJhbGci", "9f8e7d6c5b4a"], ["\"entries\"", "theme=dark"]);

// HAR downloads as valid, structurally-cleaned JSON. (Wait for the name model's background pass on
// the previous example to settle so the page isn't re-rendering during the click.)
await page.waitForFunction(() => document.querySelector("#status")?.dataset.kind === "ok", null, { timeout: 120_000 });
const [dl] = await Promise.all([page.waitForEvent("download"), page.locator("#download").click()]);
const har = JSON.parse(readFileSync(await dl.path(), "utf8"));
assert.equal(dl.suggestedFilename(), "network.clean.har");
assert.equal(har.log.entries.length, 2);
const harText = JSON.stringify(har);
for (const l of ["eyJhbGci", "9f8e7d6c5b4a", "hunter2", "jennifer.walsh", "0a1b2c3d4e5f"]) assert.ok(!harText.includes(l), `HAR download leaked ${l}`);
console.log("HAR download: valid JSON, 2 entries, no leaks");

// Typing: untick one item -> it becomes visible; switch placeholder mode.
const prevTyped = await done();
await page.locator("#input").fill("contact jane.doe@example.org or bob@example.net, key=AKIAIOSFODNN7EXAMPLE");
await waitNextScan(prevTyped);
const shown = await page.locator("#output").innerText();
assert.equal(shown, "contact [EMAIL_1] or [EMAIL_2], key=[AWS_KEY_1]");
const [typedDl] = await Promise.all([page.waitForEvent("download"), page.locator("#download").click()]);
assert.equal(readFileSync(await typedDl.path(), "utf8"), shown, "what you see is exactly what you download");
await page.locator("#detections li", { hasText: "bo" }).locator("input").uncheck();
assert.ok((await page.locator("#output").innerText()).includes("bob@example.net"), "untick keeps value visible");
await page.locator("input[name=mode][value=mask]").check();
assert.ok(!(await page.locator("#output").innerText()).includes("jane.doe"), "mask mode hides value");
console.log("interactive: untick + mask mode OK");

await app.finish();
process.exit(0);
