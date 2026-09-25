// Optional name model (runs off the main thread). Everything is loaded from this app's own origin.
import * as ort from "../vendor/ort/ort.wasm.min.mjs";
import { configureOrt, createEngineCache } from "../vendor/core/engines.js";

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
    } else if (m.type === "ner") {
      const ner = await engines.ner();
      self.postMessage({ type: "result", id: m.id, spans: await ner.find(m.text, new Set(m.categories)) });
    }
  } catch (e) {
    self.postMessage({ type: "error", id: m.id, text: e?.message || String(e) });
  }
};
