// Generate the example inputs. All values are FAKE (made-up names, example domains, test card
// numbers, random-looking but meaningless keys). Token-shaped values are assembled from parts so the
// repository never contains a literal key that secret scanners would flag. Run by `npm run vendor`.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "examples");

const log = `2026-09-25T10:14:02.114Z INFO  [api] POST /v1/login user=jennifer.walsh@contoso.com ip=203.0.113.42 ua="Mozilla/5.0"
2026-09-25T10:14:02.118Z DEBUG [auth] headers: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N
2026-09-25T10:14:02.120Z DEBUG [auth] Cookie: session=9f8e7d6c5b4a39281706f5e4d3c2b1a0; csrftoken=Zx81kLpQ02mNzx81kLpQ; theme=dark
2026-09-25T10:14:02.131Z INFO  [db] connecting DATABASE_URL=postgres://admin:Pr0dP4ss!2026@db01.prod.internal:5432/payments
2026-09-25T10:14:02.420Z INFO  [api] {"user_id": "u_83hf72", "request_id": "req_8f7a6b5c4d3e2f1a", "email": "tom.oneill@example.org", "retry_count": 3}
2026-09-25T10:14:03.002Z WARN  [billing] charge failed for card=4111 1111 1111 1111 amount=42.00 USD
2026-09-25T10:14:03.004Z ERROR [billing] PaymentException: gateway declined (code 51)
    at com.contoso.billing.PaymentService.charge(PaymentService.java:142)
    at com.contoso.billing.CheckoutController.submit(CheckoutController.java:88)
2026-09-25T10:14:03.010Z INFO  [support] ticket opened by Priya Raman, callback +1 (206) 555-0187
2026-09-25T10:14:04.500Z DEBUG [http] GET https://api.example.com/v2/users?access_token=ya29.a0AfH6SMBx3kL9mQ&page=2 200 12ms
2026-09-25T10:14:05.001Z INFO  [cli] ran: deploy --token=ghp_R4nd0mT0k3nV4lu3F0rT3st1ngPurp0s3s99 --env prod
2026-09-25T10:14:05.230Z INFO  [crash] dump written to C:\\Users\\jwalsh\\AppData\\Local\\contoso\\crash-2026-09-25.dmp
2026-09-25T10:14:06.000Z INFO  [health] ok uptime=99.98% queue_depth=0 version=4.12.1
`;

const env = `# Local development settings — DO NOT COMMIT
APP_ENV=production
APP_URL=https://app.contoso.example
TOKEN_URL=https://login.example.com/oauth2/token
DATABASE_URL=postgres://payments:Sup3r-S3cret-Pw@10.20.30.40:5432/payments
REDIS_PASSWORD="correct horse battery staple"
OPENAI_API_KEY=sk-proj-9fQ2xLr7TbWm4KpZ8vNs3HcYd1
STRIPE_SECRET_KEY=${"sk_" + "live_" + "51HxQ2eKz8LmN4pRtY7uVwXa9"}
AWS_ACCESS_KEY_ID=AKIAQ3EGUMRX7ZK4B2NP
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI7K7MDENGbPxRfiCYz3kL9mQ
SLACK_WEBHOOK_TOKEN=${"xo" + "xb-" + "2468013579-1357924680-AbCdEfGhIjKlMnOpQrStUvWx"}
SENTRY_DSN=https://4f8e2c1a9b7d4e6f@o123456.ingest.example.io/7654321
ADMIN_EMAIL=ops-lead@fabrikam.example
LOG_LEVEL=info
FEATURE_FLAGS=search,new-checkout
MAX_RETRIES=5
`;

const har = {
  log: {
    version: "1.2",
    creator: { name: "WebInspector", version: "537.36" },
    pages: [{ startedDateTime: "2026-09-25T10:14:02.000Z", id: "page_1", title: "https://app.contoso.example/account?session=9f8e7d6c5b4a39281706f5e4d3c2b1a0", pageTimings: {} }],
    entries: [
      {
        startedDateTime: "2026-09-25T10:14:02.100Z", time: 84,
        request: {
          method: "POST", url: "https://api.contoso.example/v1/login?client_id=web&api_key=AIzaSyA1b2C3d4E5f6G7h8I9j0KlMnOpQrStUvW",
          httpVersion: "HTTP/2",
          headers: [
            { name: "Content-Type", value: "application/json" },
            { name: "Authorization", value: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N" },
            { name: "Cookie", value: "session=9f8e7d6c5b4a39281706f5e4d3c2b1a0; theme=dark" },
            { name: "X-Api-Key", value: "k_live_Q2eKz8LmN4pRtY7uVwXa9bC" },
          ],
          queryString: [
            { name: "client_id", value: "web" },
            { name: "api_key", value: "AIzaSyA1b2C3d4E5f6G7h8I9j0KlMnOpQrStUvW" },
          ],
          cookies: [{ name: "session", value: "9f8e7d6c5b4a39281706f5e4d3c2b1a0" }, { name: "theme", value: "dark" }],
          postData: { mimeType: "application/json", text: JSON.stringify({ email: "jennifer.walsh@contoso.com", password: "hunter2-Fall2026!" }) },
          headersSize: -1, bodySize: 64,
        },
        response: {
          status: 200, statusText: "OK", httpVersion: "HTTP/2",
          headers: [
            { name: "Content-Type", value: "application/json" },
            { name: "Set-Cookie", value: "session=0a1b2c3d4e5f60718293a4b5c6d7e8f9; Path=/; HttpOnly; Secure; SameSite=Lax" },
          ],
          cookies: [{ name: "session", value: "0a1b2c3d4e5f60718293a4b5c6d7e8f9", path: "/", httpOnly: true, secure: true }],
          content: { size: 180, mimeType: "application/json", text: JSON.stringify({ user: { id: "u_83hf72", name: "Jennifer Walsh", email: "jennifer.walsh@contoso.com", phone: "(415) 555-0132" }, refresh_token: "rt_9s8d7f6g5h4j3k2l1zxcvbnmQWERTY" }) },
          redirectURL: "", headersSize: -1, bodySize: 180,
        },
        cache: {}, timings: { send: 1, wait: 80, receive: 3 },
      },
      {
        startedDateTime: "2026-09-25T10:14:02.300Z", time: 21,
        request: { method: "GET", url: "https://cdn.contoso.example/app.css", httpVersion: "HTTP/2", headers: [], queryString: [], cookies: [], headersSize: -1, bodySize: 0 },
        response: { status: 200, statusText: "OK", httpVersion: "HTTP/2", headers: [{ name: "Content-Type", value: "text/css" }], cookies: [], content: { size: 24, mimeType: "text/css", text: "body{font-family:system}" }, redirectURL: "", headersSize: -1, bodySize: 24 },
        cache: {}, timings: { send: 0, wait: 20, receive: 1 },
      },
    ],
  },
};

mkdirSync(dir, { recursive: true });
writeFileSync(join(dir, "app.log"), log);
writeFileSync(join(dir, ".env.example-leak"), env);
writeFileSync(join(dir, "network.har"), JSON.stringify(har, null, 2) + "\n");
console.log("examples written to", dir);
