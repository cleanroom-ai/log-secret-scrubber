// Build step: copy the shared engine + ONNX Runtime + name model into the app (no CDN at runtime).
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { vendorCore } from "@cleanroom-ai/core/scripts/vendor.mjs";

const appDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
vendorCore({ appDir, models: ["pii"], libs: ["ort", "transformers"] });
await import("./make-examples.mjs"); // examples are generated, not committed (see make-examples.mjs)
console.log("done");

