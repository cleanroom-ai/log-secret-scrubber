import { CATEGORY_COLORS } from "../vendor/core/redact.js";
import { maskPreview, prettyLabel } from "../vendor/core/rules.js";
import { DEFAULT_LOG_CATEGORIES, LOG_CATEGORIES, applySpans, findLogSpans, looksLikeHar, scrubHar } from "./scrub.js";

const $ = (s) => document.querySelector(s);
const els = {
  input: $("#input"), output: $("#output"), status: $("#status"), counts: $("#counts"), list: $("#detections"),
  empty: $("#detections-empty"), cats: $("#categories"), terms: $("#terms"), useNer: $("#use-ner"), engine: $("#engine"),
  copy: $("#copy"), download: $("#download"), file: $("#file"), open: $("#open"),
};
const COLORS = { ...CATEGORY_COLORS, identifiers: "#64748b" };
const state = { fileName: "scrubbed.txt", spans: [], groups: [], off: new Set(), mode: "placeholder", har: null, run: 0, ner: null };

// ------------------------------------------------------------------ optional name model (worker)
let worker = null;
const pending = new Map();
function nerProxy() {
  if (!worker) {
    worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
    worker.onmessage = ({ data: m }) => {
      if (m.type === "download") setEngine(`Downloading the name model… ${mb(m.loaded)} / ${mb(m.total)} MB (one time)`);
      else if (m.type === "ready") setEngine("✓ Rules + name model ready — works offline", "ok");
      else if (pending.has(m.id)) {
        const p = pending.get(m.id);
        pending.delete(m.id);
        m.type === "result" ? p.resolve(m.spans) : p.reject(new Error(m.text));
      }
    };
  }
  let n = 0;
  return {
    find: (text, cats) => new Promise((resolve, reject) => {
      const id = `${Date.now()}-${n++}`;
      pending.set(id, { resolve, reject });
      worker.postMessage({ type: "ner", id, text, categories: [...cats] });
    }),
  };
}

// ------------------------------------------------------------------------------ scanning
async function scan() {
  const run = ++state.run;
  const text = els.input.value;
  state.har = null;
  if (!text.trim()) {
    state.spans = [];
    render();
    setStatus("Paste text below, drop a file anywhere, or open one.");
    return;
  }
  const categories = [...els.cats.querySelectorAll("input:checked")].map((i) => i.value);
  const customTerms = els.terms.value.split(/[,\n]/).map((t) => t.trim()).filter(Boolean);
  const withNames = els.useNer.checked;
  setStatus("Scanning…", "busy");
  const t0 = performance.now();
  try {
    if (looksLikeHar(text)) {
      // HAR: clean structurally (headers, cookies, params, nested JSON bodies); show exactly that.
      const { har, stats } = await scrubHar(text, { categories, customTerms, mode: state.mode });
      state.har = { har, stats, text: JSON.stringify(har, null, 2) };
      if (run !== state.run) return;
      state.spans = [];
      document.body.dataset.scanDone = String(run);
      const secs = ((performance.now() - t0) / 1000).toFixed(2);
      setStatus(`HAR cleaned in ${secs}s: ${stats.entries} requests; ${stats.headers} headers, ${stats.cookies} cookies, ` +
        `${stats.params} query/form params and ${stats.bodies} bodies scrubbed. Binary bodies were dropped.`, "ok");
      render();
      return;
    }
    // Pass 1: rules only (instant). Pass 2: add names from the on-device model when it's ready.
    await apply(await findLogSpans(text, { categories, customTerms }), t0, run, withNames);
    if (withNames && run === state.run) {
      const ner = (state.ner ??= nerProxy());
      await apply(await findLogSpans(text, { categories, customTerms, ner }), t0, run, false);
    }
  } catch (e) {
    if (run === state.run) setStatus(`Scan failed: ${e.message}`, "warn");
  }
}

async function apply(spans, t0, run, namesPending) {
  if (run !== state.run) return;
  state.spans = spans.map((s, i) => ({ ...s, id: i }));
  // Test hook: the run number of the last fully finished scan.
  if (!namesPending) document.body.dataset.scanDone = String(run);
  const secs = ((performance.now() - t0) / 1000).toFixed(2);
  const n = new Set(spans.map((s) => `${s.label}\u0000${s.value}`)).size;
  setStatus(state.spans.length
    ? `Found ${state.spans.length} item${state.spans.length === 1 ? "" : "s"} (${n} unique) in ${secs}s.` +
      (state.har ? ` HAR: ${state.har.stats.entries} requests; headers, cookies, query strings and bodies cleaned.` : "") +
      (namesPending ? " Checking for names…" : " Untick anything you want to keep.")
    : `Nothing sensitive found (${secs}s).${namesPending ? " Checking for names…" : ""}`, namesPending ? "busy" : "ok");
  render();
}

// ------------------------------------------------------------------------------ rendering
function selectedIds() {
  return new Set(state.spans.filter((s) => !state.off.has(groupKey(s))).map((s) => s.id));
}
const groupKey = (s) => `${s.label}\u0000${s.value}`;

function render() {
  const text = els.input.value;
  if (state.har) {
    els.output.textContent = state.har.text;
    els.list.replaceChildren();
    els.empty.hidden = false;
    els.empty.textContent = "HAR files are cleaned structurally; review the output on the left.";
    els.counts.textContent = "— structural clean";
    els.copy.disabled = els.download.disabled = false;
    return;
  }
  els.empty.textContent = "Nothing yet.";
  const sel = selectedIds();
  const { pieces } = applySpans(text, state.spans, { mode: state.mode, selected: sel });
  const frag = document.createDocumentFragment();
  for (const p of pieces) {
    if (p.tag === undefined) {
      frag.append(p.text);
      continue;
    }
    const m = document.createElement("mark");
    m.className = "hit";
    m.style.setProperty("--c", COLORS[p.span.category] || "#64748b");
    m.title = prettyLabel(p.span.label);
    m.textContent = p.tag;
    frag.append(m);
  }
  els.output.replaceChildren(frag);

  // Sidebar: one row per unique value.
  const groups = new Map();
  for (const s of state.spans) {
    const k = groupKey(s);
    if (!groups.has(k)) groups.set(k, { key: k, s, n: 0 });
    groups.get(k).n++;
  }
  state.groups = [...groups.values()];
  els.list.replaceChildren(...state.groups.map((g) => {
    const li = document.createElement("li");
    const label = document.createElement("label");
    const cb = Object.assign(document.createElement("input"), { type: "checkbox", checked: !state.off.has(g.key) });
    cb.addEventListener("change", () => {
      cb.checked ? state.off.delete(g.key) : state.off.add(g.key);
      render();
    });
    const dot = Object.assign(document.createElement("span"), { className: "dot" });
    dot.style.background = COLORS[g.s.category] || "#64748b";
    label.append(cb, dot,
      Object.assign(document.createElement("span"), { className: "name", textContent: prettyLabel(g.s.label) }),
      Object.assign(document.createElement("span"), { className: "preview", textContent: maskPreview(g.s.value) }),
      Object.assign(document.createElement("span"), { className: "count", textContent: g.n > 1 ? `×${g.n}` : "" }));
    li.append(label);
    return li;
  }));
  els.empty.hidden = state.groups.length > 0;
  const on = state.spans.filter((s) => sel.has(s.id)).length;
  els.counts.textContent = state.spans.length ? `— ${on} of ${state.spans.length} hidden` : "";
  els.copy.disabled = els.download.disabled = !text.trim();
}

function cleanOutput() {
  if (state.har) return state.har.text;
  return applySpans(els.input.value, state.spans, { mode: state.mode, selected: selectedIds() }).text;
}

// ------------------------------------------------------------------------------ input
let timer = 0;
els.input.addEventListener("input", () => {
  clearTimeout(timer);
  timer = setTimeout(scan, 250);
});
els.open.addEventListener("click", () => els.file.click());
els.file.addEventListener("change", () => els.file.files[0] && loadFile(els.file.files[0]));
document.body.addEventListener("dragover", (e) => e.preventDefault());
document.body.addEventListener("drop", (e) => {
  e.preventDefault();
  const f = e.dataTransfer?.files?.[0];
  if (f) loadFile(f);
});
document.querySelectorAll("[data-example]").forEach((b) => b.addEventListener("click", async () => {
  const res = await fetch(b.dataset.example);
  els.input.value = await res.text();
  state.fileName = b.dataset.name;
  state.off.clear();
  scan();
}));

async function loadFile(f) {
  if (f.size > 20 * 1024 * 1024) {
    setStatus("That file is over 20 MB; split it or paste the relevant part.", "warn");
    return;
  }
  els.input.value = await f.text();
  state.fileName = f.name;
  state.off.clear();
  scan();
}

els.terms.addEventListener("change", scan);
els.useNer.addEventListener("change", scan);
document.querySelectorAll("input[name=mode]").forEach((r) => r.addEventListener("change", () => {
  state.mode = r.value;
  render();
}));
$("#select-all").addEventListener("click", () => { state.off.clear(); render(); });
$("#select-none").addEventListener("click", () => { state.groups.forEach((g) => state.off.add(g.key)); render(); });

els.copy.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(cleanOutput());
    flash(els.copy, "✓ Copied");
  } catch {
    flash(els.copy, "Copy not allowed here");
  }
});
els.download.addEventListener("click", () => {
  const name = state.fileName.replace(/(\.[^.]+)?$/, (ext) => `.clean${ext || ".txt"}`);
  const blob = new Blob([cleanOutput()], { type: state.har ? "application/json" : "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
});

for (const [key, desc] of Object.entries(LOG_CATEGORIES)) {
  const label = document.createElement("label");
  const cb = Object.assign(document.createElement("input"), { type: "checkbox", value: key, checked: DEFAULT_LOG_CATEGORIES.includes(key) });
  cb.addEventListener("change", scan);
  const dot = Object.assign(document.createElement("span"), { className: "dot" });
  dot.style.background = COLORS[key] || "#64748b";
  label.append(cb, dot, Object.assign(document.createElement("span"), { textContent: desc }));
  els.cats.append(label);
}

function setStatus(t, kind = "") {
  els.status.textContent = t;
  els.status.dataset.kind = kind;
}
function setEngine(t, kind = "") {
  els.engine.textContent = t;
  els.engine.dataset.kind = kind;
}
function flash(b, t) {
  const old = b.textContent;
  b.textContent = t;
  setTimeout(() => (b.textContent = old), 1600);
}
const mb = (b) => (b / 1048576).toFixed(1);
setEngine("✓ Rules engine ready — works offline", "ok");
// Warm the name model in the background so names are ready by the first paste.
if (els.useNer.checked) {
  state.ner = nerProxy();
  worker.postMessage({ type: "warmup" });
}
