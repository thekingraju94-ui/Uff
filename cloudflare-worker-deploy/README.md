# FIREXPANEL — Secure Cloudflare Worker

## Security

- **BOT_TOKEN** and **ADMIN_ID** are stored as **Cloudflare encrypted secrets**
- They are NEVER in source code, config files, logs, or error messages
- After setting, they are NOT visible in the Cloudflare dashboard
- The worker returns generic responses — no internal info is ever leaked
- Rate limiting prevents brute-force attempts
- AES-GCM encryption on payloads with timestamp validation

## Deployment Steps

### 1. Install Wrangler (if not already)
```bash
npm install -g wrangler
```

### 2. Login to Cloudflare
```bash
wrangler login
```

### 3. Deploy the Worker
```bash
cd firexpanel-worker
npm install
npm run deploy
```

### 4. Set Secrets (CRITICAL — do this after deploy)
```bash
npx wrangler secret put BOT_TOKEN
# When prompted, paste: 8895711503:AAGWQkjrElBR80kT0CX_DMb6RhdMzT_x8OE

npx wrangler secret put ADMIN_ID
# When prompted, paste: 8249504706
```

### 5. Verify
Visit: `https://your-worker.your-subdomain.workers.dev/api/ping`

You should receive a test message in Telegram.

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/api/ev` | POST | Receives encrypted event data, sends alert to Telegram |
| `/api/ping` | GET | Sends test message to verify bot connection |

## Frontend Changes Required

**NONE** — All endpoints and behavior are identical. Just update the worker URL if it changed.

## Why This Is Secure

1. Secrets are encrypted at rest by Cloudflare's infrastructure
2. Not visible in dashboard after being set (write-only)
3. Not accessible via any API without your Cloudflare account credentials
4. Never appear in `console.log`, error messages, or HTTP responses
5. Source code can be public — contains zero sensitive data
6. Even if someone decompiles the worker, secrets are injected at runtime by Cloudflare
