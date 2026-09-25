// Re-export the shared engine so app code imports from one place. In the browser this resolves to
// the vendored copy (vendor/core/), in Node tests to the installed @cleanroom-ai/core package.
export { findSpans, mergeSpans, resolveOverlaps, maskPreview, prettyLabel } from "../vendor/core/rules.js";
