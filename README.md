---
title: Log Scrubber
emoji: 🧽
colorFrom: green
colorTo: gray
sdk: static
app_file: index.html
pinned: true
license: apache-2.0
short_description: Mask secrets & PII in logs, .env, JSON & HAR, in-browser
thumbnail: https://huggingface.co/spaces/cleanroom-ai/log-secret-scrubber/resolve/main/assets/social-preview.png
models:
  - onnx-community/bert-small-pii-detection-ONNX
  - gravitee-io/bert-small-pii-detection
tags:
  - secrets-detection
  - secret-scanning
  - log-sanitizer
  - redaction
  - privacy
  - pii
  - pii-detection
  - anonymization
  - har
  - devtools
  - security
  - gdpr
  - onnx
  - in-browser
---

# 🧽 Log Scrubber

<p align="center"><img src="assets/icon.svg" width="112" height="112" alt="Log Scrubber logo"></p>

[![CI](https://github.com/cleanroom-ai/log-secret-scrubber/actions/workflows/ci.yml/badge.svg)](https://github.com/cleanroom-ai/log-secret-scrubber/actions/workflows/ci.yml)
[![Live demo on Hugging Face](https://img.shields.io/badge/%F0%9F%A4%97%20Live%20demo-Hugging%20Face%20Space-yellow)](https://huggingface.co/spaces/cleanroom-ai/log-secret-scrubber)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
![Runs in your browser](https://img.shields.io/badge/runs-100%25%20in%20your%20browser-111827)

**Mask API keys, tokens, cookies, passwords, emails, IPs and names in logs, stack traces, `.env`,
JSON and HAR files before you paste them into an issue, a Slack thread or an AI chat. Nothing is
uploaded.**

👉 **Try it: [huggingface.co/spaces/cleanroom-ai/log-secret-scrubber](https://huggingface.co/spaces/cleanroom-ai/log-secret-scrubber)**

```diff
- DEBUG [auth] Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N
+ DEBUG [auth] Authorization: Bearer [JWT_1]
- DEBUG [auth] Cookie: session=9f8e7d6c5b4a39281706f5e4d3c2b1a0; theme=dark
+ DEBUG [auth] Cookie: session=[COOKIE_1]; theme=dark
- INFO  [db] DATABASE_URL=postgres://admin:Pr0dP4ss!2026@db01.prod.internal:5432/payments
+ INFO  [db] DATABASE_URL=postgres://admin:[PASSWORD_1]@[HOST_1]:5432/payments
- INFO  [support] ticket opened by Priya Raman, callback +1 (206) 555-0187
+ INFO  [support] ticket opened by [NAME_1], callback [PHONE_1]
```
*(all values are fake)*

## Why

Every bug report, support ticket and "can you look at this log?" message is a chance to leak a
session cookie, a cloud key or a customer's email. HAR files, which browsers export for debugging,
contain **every cookie and auth header** of the session. Most online "log sanitizers" ask you to upload
the very file you're trying to protect. This one runs in the browser tab.

## Features

- **40+ secret formats**: OpenAI/Anthropic, AWS, GitHub, Stripe, Slack, Google and Hugging Face keys, JWTs,
  bearer/basic auth, cookies, private keys (PEM/OpenSSH), connection strings, keys in URLs and Sentry DSNs,
  `--password`/`-p` CLI flags, and any `password=`/`api_key:`/`"clientSecret": "…"` field.
- **Personal data**: emails, phones, cards (Luhn), IBANs, SSNs, IPs, MACs, internal hostnames, home-folder
  user names (`C:\Users\jwalsh`), names in prose (on-device AI model), plus optional user/session/request IDs.
- **Consistent placeholders** keep logs debuggable: the same value always becomes the same `[EMAIL_1]`.
  Or choose stable hashes (`[EMAIL:3k9xq2a]`) or plain masking (`••••`).
- **HAR files cleaned structurally**: auth headers, cookies (harmless UI prefs like `theme=dark` are kept),
  query strings, form fields, nested JSON bodies, redirects, WebSocket messages, initiator URLs and every
  secret-looking string field. Binary bodies are dropped. Output stays valid HAR.
- **Log/config grammar coverage** includes YAML block/folded scalars, kubeconfig credentials, `.netrc`,
  sensitive XML element text, escaped JSON-in-JSON strings and zero-width-obfuscated key names.
- **Review everything**: untick false positives. What you see is exactly what you copy or download.
- **Private and offline**: the rules are instant; the 28 MB name model loads once in the background and is
  cached.

## How it works

```
text / file ─► structure-aware finders (key=value, JSON, headers, cookies, CLI flags, URLs, PEM, HAR)
            ├─► shared secret/PII rules from @cleanroom-ai/core (checksums, entropy, chat-name rules)
            └─► on-device PII model for names in prose (ONNX Runtime Web, Web Worker)
                          ─► non-overlapping spans ─► consistent placeholders ─► review ─► copy / download
```

The shared engine is [`@cleanroom-ai/core`](https://github.com/cleanroom-ai/cleanroom-core), and every
library and model is bundled with the app. The CI browser test **fails if the page makes an upload or
contacts any other host**.

## Run it locally

```bash
npm ci
npm run vendor      # copy the engine, ONNX Runtime and the name model into vendor/ and models/
npm run serve       # http://127.0.0.1:8080
npm test            # rules, structure finders, HAR scrubbing and the three examples
node tests/e2e.browser.mjs http://127.0.0.1:8080/   # real browser (Edge/Chrome); E2E_BROWSER=chromium for Playwright's
```

## CI/CD

- **[CI](.github/workflows/ci.yml)**: unit tests and a real-browser test in Chromium, which asserts no leaks,
  that the download matches the screen, and zero uploads or third-party requests.
- **[Deploy](.github/workflows/deploy-space.yml)**: pushes to `main` build the app and upload it to the
  Hugging Face Space (requires an `HF_TOKEN` repository secret).

## Limitations

- Custom in-house token formats without a telling key name (`password=`, `token:`…) or high randomness can be missed.
  Add them as custom words, and always review before sharing.
- Name detection is tuned for English prose; names inside machine fields are handled by field names (`name`, `user`, `author`…).
- For responsiveness, very large single-line non-JSON values are skipped by the structural key/value scanner, and
  the findings sidebar initially renders the first 250 unique values with a "show more" control. Very large
  scrubbed outputs show a bounded preview in the page; copy/download still exports the full scrubbed log.

<!-- cleanroom-ai:family:start -->
## Part of cleanroom-ai

**Clean it before you share it.** Six free privacy tools built on one shared engine. Every model runs
in your browser, so nothing you open is ever uploaded.

| | Tool | Cleans | Demo | Code |
|---|---|---|---|---|
| 🕶️ | **Screenshot Redactor** | API keys, passwords, emails, card numbers, names, faces & QR codes in screenshots | [▶ Try it](https://huggingface.co/spaces/cleanroom-ai/pii-privacy-redaction) | [GitHub](https://github.com/cleanroom-ai/screenshot-redactor) |
| 🧽 | **Log Scrubber** 📍 *you are here* | tokens, cookies, passwords & PII in logs, `.env`, JSON and HAR files | [▶ Try it](https://huggingface.co/spaces/cleanroom-ai/log-secret-scrubber) | [GitHub](https://github.com/cleanroom-ai/log-secret-scrubber) |
| 📄 | **PDF Redactor** | PII & secrets in PDFs, flattened and verified so no text survives | [▶ Try it](https://huggingface.co/spaces/cleanroom-ai/pdf-redaction) | [GitHub](https://github.com/cleanroom-ai/pdf-redaction) |
| 🔊 | **Audio Redactor** | bleeps names, phone & card numbers and secrets in recordings | [▶ Try it](https://huggingface.co/spaces/cleanroom-ai/audio-pii-redaction) | [GitHub](https://github.com/cleanroom-ai/audio-pii-redaction) |
| 📷 | **Photo Share-Safe** | GPS & hidden EXIF metadata; blurs faces and license plates | [▶ Try it](https://huggingface.co/spaces/cleanroom-ai/photo-exif-privacy) | [GitHub](https://github.com/cleanroom-ai/photo-exif-privacy) |
| 🎬 | **Video Redactor** | keys, names, emails & faces tracked through screen recordings | [▶ Try it](https://huggingface.co/spaces/cleanroom-ai/video-redaction) | [GitHub](https://github.com/cleanroom-ai/video-redaction) |
| ⚙️ | **@cleanroom-ai/core** | the shared on-device engine: OCR, secret/PII rules, NER, face detection | — | [GitHub](https://github.com/cleanroom-ai/cleanroom-core) |

All tools: [Hugging Face](https://huggingface.co/cleanroom-ai) · [GitHub](https://github.com/cleanroom-ai)
<!-- cleanroom-ai:family:end -->

## Author

Built by **Parag Sawant**: [@paragpsawant](https://github.com/paragpsawant) ·
[parags.dev](https://parags.dev) · [LinkedIn](https://www.linkedin.com/in/paragsawant/)

## Credits & licenses

Apache-2.0. Bundled: bert-small-pii-detection (Apache-2.0), ONNX Runtime Web (MIT), transformers.js
(Apache-2.0). License texts are in [`licenses/`](licenses/) and `models/LICENSES/` after `npm run vendor`.
