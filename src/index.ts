/**
 * sss-relay — src/index.ts
 *
 * One-time encrypted credential relay for Secure-Smart-Sync device pairing.
 *
 * Endpoints
 * ─────────
 *   POST /store
 *     Body (JSON): { blob: string }
 *       blob — AES-GCM ciphertext, base64url encoded, produced by the plugin.
 *              The Worker never sees plaintext; it is opaque bytes to us.
 *     Response 200 (JSON): { token: string }
 *       token — 8-character random alphanumeric, used to retrieve the blob.
 *     Response 400 — missing or oversized blob.
 *     Response 429 — rate limit exceeded.
 *
 *   GET /retrieve/:token
 *     Response 200 (JSON): { blob: string }
 *       Returns the blob and immediately deletes it from KV (one-time read).
 *     Response 404 — token not found or already consumed.
 *
 *   GET /health
 *     Response 200 (JSON): { ok: true }
 *     Simple liveness check — useful for the plugin to verify the relay URL.
 *
 * Security notes
 * ──────────────
 *   • The Worker stores only the encrypted blob. The decryption PIN never
 *     reaches the server — it exists only in the plugin on both devices.
 *   • Blobs are deleted immediately on first retrieval (one-time read).
 *   • KV TTL is 10 minutes — blobs expire automatically even if never read.
 *   • store is rate-limited per IP to prevent abuse.
 *   • CORS is locked to the Obsidian desktop origin (app://obsidian.md) and
 *     capacitor://localhost (Obsidian mobile). Browsers cannot abuse the relay.
 *   • No logging of blob contents anywhere in this file — keep it that way.
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export interface Env {
  PAIRING_KV: KVNamespace;
  MAX_BLOB_BYTES: string;
  TTL_SECONDS: string;
  RATE_LIMIT_STORE_RPM: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

// Characters used for token generation — unambiguous (no 0/O, 1/l/I).
const TOKEN_CHARS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz";
const TOKEN_LENGTH = 8;

// KV key prefix for pairing blobs.
const KV_BLOB_PREFIX = "blob:";

// KV key prefix for rate-limit counters.
const KV_RL_PREFIX = "rl:";

// Allowed origins — Obsidian desktop (Electron) and Obsidian mobile (Capacitor).
const ALLOWED_ORIGINS = new Set([
  "app://obsidian.md",
  "capacitor://localhost",
  // Allow local dev / wrangler dev
  "http://localhost",
]);

// ─── Entry point ──────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") ?? "";

    // ── CORS preflight ────────────────────────────────────────────────────────
    if (request.method === "OPTIONS") {
      return corsPreflightResponse(origin);
    }

    // ── Route ─────────────────────────────────────────────────────────────────
    let response: Response;

    try {
      if (request.method === "GET" && url.pathname === "/health") {
        response = handleHealth();
      } else if (request.method === "POST" && url.pathname === "/store") {
        response = await handleStore(request, env);
      } else if (request.method === "GET" && url.pathname.startsWith("/retrieve/")) {
        const token = url.pathname.slice("/retrieve/".length);
        response = await handleRetrieve(token, env);
      } else {
        response = jsonError(404, "Not found.");
      }
    } catch (err) {
      console.error("[sss-relay] Unhandled error:", err);
      response = jsonError(500, "Internal server error.");
    }

    // Attach CORS headers to every real response.
    return withCors(response, origin);
  },
} satisfies ExportedHandler<Env>;

// ─── Handlers ─────────────────────────────────────────────────────────────────

function handleHealth(): Response {
  return jsonOk({ ok: true });
}

async function handleStore(request: Request, env: Env): Promise<Response> {
  const maxBytes = parseInt(env.MAX_BLOB_BYTES, 10) || 4096;
  const ttl      = parseInt(env.TTL_SECONDS, 10)    || 600;
  const rpm      = parseInt(env.RATE_LIMIT_STORE_RPM, 10) || 5;

  // ── Rate limit ────────────────────────────────────────────────────────────
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const rlKey = KV_RL_PREFIX + ip;
  const rlRaw = await env.PAIRING_KV.get(rlKey);
  const rlCount = rlRaw ? parseInt(rlRaw, 10) : 0;

  if (rlCount >= rpm) {
    return jsonError(429, "Too many requests. Try again in a minute.");
  }

  // Increment counter; expire in 60 s regardless of blob TTL.
  await env.PAIRING_KV.put(rlKey, String(rlCount + 1), { expirationTtl: 60 });

  // ── Parse body ────────────────────────────────────────────────────────────
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "Invalid JSON body.");
  }

  if (!body || typeof body !== "object") {
    return jsonError(400, "Body must be a JSON object.");
  }

  const { blob } = body as Record<string, unknown>;

  if (typeof blob !== "string" || blob.length === 0) {
    return jsonError(400, "Missing or empty 'blob' field.");
  }

  // Guard against oversized payloads (base64url is ~4/3 × raw bytes).
  if (blob.length > maxBytes * 2) {
    return jsonError(400, `Blob too large. Maximum is ${maxBytes} bytes.`);
  }

  // Validate that blob is at least plausible base64url (no spaces, sane chars).
  if (!/^[A-Za-z0-9+/=_-]+$/.test(blob)) {
    return jsonError(400, "Blob contains invalid characters.");
  }

  // ── Store ─────────────────────────────────────────────────────────────────
  const token = generateToken();
  const kvKey = KV_BLOB_PREFIX + token;

  await env.PAIRING_KV.put(kvKey, blob, { expirationTtl: ttl });

  return jsonOk({ token });
}

async function handleRetrieve(token: string, env: Env): Promise<Response> {
  // Validate token format before touching KV.
  if (!token || token.length !== TOKEN_LENGTH || !/^[A-Za-z0-9]+$/.test(token)) {
    return jsonError(404, "Token not found or already used.");
  }

  const kvKey = KV_BLOB_PREFIX + token;
  const blob  = await env.PAIRING_KV.get(kvKey);

  if (blob === null) {
    return jsonError(404, "Token not found or already used.");
  }

  // One-time read — delete immediately before returning.
  await env.PAIRING_KV.delete(kvKey);

  return jsonOk({ blob });
}

// ─── Token generation ─────────────────────────────────────────────────────────

/**
 * Generates a cryptographically random TOKEN_LENGTH-character token using only
 * characters from TOKEN_CHARS (unambiguous alphanumeric set).
 *
 * Uses rejection sampling to avoid modulo bias.
 */
function generateToken(): string {
  const result: string[] = [];
  const charCount = TOKEN_CHARS.length; // 56

  // We need TOKEN_LENGTH random chars. Pull random bytes in batches and
  // reject values that would introduce bias (rejection sampling).
  // 56 chars → accept byte values 0–223 (4 * 56 = 224), reject 224–255.
  const ACCEPT_THRESHOLD = Math.floor(256 / charCount) * charCount; // 224

  while (result.length < TOKEN_LENGTH) {
    const bytes = crypto.getRandomValues(new Uint8Array(TOKEN_LENGTH * 2));
    for (const byte of bytes) {
      if (result.length >= TOKEN_LENGTH) break;
      if (byte < ACCEPT_THRESHOLD) {
        result.push(TOKEN_CHARS[byte % charCount]);
      }
    }
  }

  return result.join("");
}

// ─── CORS ─────────────────────────────────────────────────────────────────────

function corsHeaders(origin: string): Record<string, string> {
  // Only reflect the origin if it's in our allowlist; otherwise omit header
  // so browsers reject the response (doesn't affect the plugin since it uses
  // the Fetch API from Electron/Capacitor without strict CORS enforcement,
  // but good hygiene for open-source inspection).
  const allowOrigin = ALLOWED_ORIGINS.has(origin) ? origin : "null";
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };
}

function corsPreflightResponse(origin: string): Response {
  return new Response(null, { status: 204, headers: corsHeaders(origin) });
}

function withCors(response: Response, origin: string): Response {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(corsHeaders(origin))) {
    headers.set(k, v);
  }
  return new Response(response.body, {
    status:  response.status,
    headers,
  });
}

// ─── Response helpers ─────────────────────────────────────────────────────────

function jsonOk(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function jsonError(status: number, message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
