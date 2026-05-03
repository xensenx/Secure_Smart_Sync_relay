# sss-relay

One-time encrypted credential relay for [Secure-Smart-Sync](https://github.com/xensenx/Secure-Smart-Sync) device pairing.

## What this is

When you want to pair a second device (e.g. your phone) to the same R2 bucket, re-entering all credentials manually is error-prone. `sss-relay` is a tiny Cloudflare Worker that acts as a short-lived, encrypted drop box — the desktop plugin posts an encrypted blob, the mobile device retrieves it once using a short code, and the blob is immediately deleted.

**The relay never sees your credentials in plaintext.** All encryption and decryption happens inside the plugin on your devices. The Worker stores an opaque encrypted blob and nothing else.

## Security model

| Property | Detail |
|---|---|
| Encryption | AES-GCM 256-bit, performed entirely client-side in the plugin |
| Key | Derived from a random 6-character PIN via PBKDF2 (never sent to the server) |
| One-time read | Blob is deleted from KV immediately on first retrieval |
| Auto-expiry | KV TTL of 10 minutes — blobs vanish even if never retrieved |
| Rate limiting | Store endpoint limited to 5 requests per IP per minute |
| Blob validation | Size-capped at 4 KB; character set validated; format checked |
| CORS | Locked to Obsidian origins only |

## Endpoints

```
POST /store
  Body:     { "blob": "<base64url-encoded AES-GCM ciphertext>" }
  Response: { "token": "<8-char token>" }

GET /retrieve/:token
  Response: { "blob": "<base64url-encoded AES-GCM ciphertext>" }
  (blob is deleted from KV immediately after this call)

GET /health
  Response: { "ok": true }
```

## Self-hosting (recommended)

You are encouraged to deploy your own instance so you remain in full control of the relay infrastructure.

### Prerequisites

- A [Cloudflare account](https://dash.cloudflare.com/sign-up) (free tier is more than enough)
- [Node.js](https://nodejs.org/) 18 or later
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)

### Steps

**1. Clone and install**

```bash
git clone https://github.com/xensenx/sss-relay
cd sss-relay
npm install
```

**2. Log in to Cloudflare**

```bash
npx wrangler login
```

**3. Create a KV namespace**

```bash
npx wrangler kv namespace create PAIRING_KV
```

Copy the `id` from the output. Then create a preview namespace for local dev:

```bash
npx wrangler kv namespace create PAIRING_KV --preview
```

Copy the `preview_id` from that output.

**4. Update `wrangler.toml`**

Open `wrangler.toml` and replace the placeholder values:

```toml
[[kv_namespaces]]
binding = "PAIRING_KV"
id = "YOUR_KV_NAMESPACE_ID"
preview_id = "YOUR_KV_PREVIEW_NAMESPACE_ID"
```

**5. Deploy**

```bash
npm run deploy
```

Wrangler will print your Worker URL, e.g.:
```
https://sss-relay.<your-subdomain>.workers.dev
```

**6. Configure the plugin**

In Secure-Smart-Sync settings → Advanced → Relay URL, paste your Worker URL. Done.

### Local development

```bash
npm run dev
```

This starts a local server at `http://localhost:8787`. You can test with curl:

```bash
# Store
curl -X POST http://localhost:8787/store \
  -H "Content-Type: application/json" \
  -d '{"blob":"dGVzdA=="}'

# Retrieve (replace TOKEN with value from above response)
curl http://localhost:8787/retrieve/TOKEN

# Health
curl http://localhost:8787/health
```

## Configuration reference (`wrangler.toml`)

| Variable | Default | Description |
|---|---|---|
| `MAX_BLOB_BYTES` | `4096` | Maximum accepted blob size in bytes |
| `TTL_SECONDS` | `600` | KV entry lifetime (seconds) |
| `RATE_LIMIT_STORE_RPM` | `5` | Max store requests per IP per minute |

## License

MIT — see [LICENSE](LICENSE).
