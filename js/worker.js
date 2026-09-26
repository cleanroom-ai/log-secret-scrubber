// Scanning worker: rules, structural parsing, HAR cleaning and the optional name model all run here,
// off the main thread. Everything is loaded from this app's own origin.
import * as ort from "../vendor/ort/ort.wasm.min.mjs";
import { configureOrt, createEngineCache } from "../vendor/core/engines.js";
import { findLogSpans, scrubHar } from "./scrub.js";

const WASM = new URL("../vendor/ort/", import.meta.url).href;
configureOrt(ort, WASM);
const engines = createEngineCache({
  ort, base: new URL("../", import.meta.url), wasmPath: WASM,
  importTransformers: () => import("../vendor/transformers.web.min.js"),
  onProgress: (p) => self.postMessage({ type: "download", ...p }),
});

self.onmessage = async ({ data: m }) => {
  try {
    if (m.type === "warmup") {
      await engines.ner();
      self.postMessage({ type: "ready" });
    } else if (m.type === "scan") {
      const ner = m.withNames ? await engines.ner() : null;
      const result = await findLogSpans(m.text, { categories: m.categories, customTerms: m.customTerms, ner });
      self.postMessage({ type: "result", id: m.id, result });
    } else if (m.type === "har") {
      const result = await scrubHar(m.text, { categories: m.categories, customTerms: m.customTerms, mode: m.mode });
      self.postMessage({ type: "result", id: m.id, result });
    }
  } catch (e) {
    self.postMessage({ type: "error", id: m.id, text: e?.message || String(e) });
  }
};
