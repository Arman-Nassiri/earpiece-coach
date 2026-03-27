const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const ROOT = __dirname;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const ALLOW_SERVER_KEY_LIVE = /^(1|true|yes)$/i.test(process.env.ALLOW_SERVER_KEY_LIVE || '');
const REALTIME_MODEL = process.env.OPENAI_REALTIME_MODEL || 'gpt-realtime';
const TRANSCRIBE_MODEL = process.env.OPENAI_TRANSCRIBE_MODEL || 'gpt-4o-mini-transcribe';
const liveCallWindows = new Map();
const ALLOWED_REALTIME_MODELS = new Set(['gpt-realtime', 'gpt-realtime-mini']);

const MIME_TYPES = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml; charset=utf-8'
};

function buildSecurityHeaders(extra = {}) {
  return {
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Permissions-Policy': 'camera=(), geolocation=(), microphone=(self)',
    ...extra
  };
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  res.writeHead(statusCode, buildSecurityHeaders({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders
  }));
  res.end(JSON.stringify(payload));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.setEncoding('utf8');
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 2_000_000) {
        reject(new Error('Request body too large'));
        req.destroy();
      }
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

async function serveFile(filePath, res) {
  try {
    const data = await fs.promises.readFile(filePath);
    const ext = path.extname(filePath).toLowerCase();
    const isHtml = ext === '.html';
    res.writeHead(200, buildSecurityHeaders({
      'Content-Type': MIME_TYPES[ext] || 'application/octet-stream',
      'Cache-Control': isHtml ? 'no-store' : 'public, max-age=300'
    }));
    res.end(data);
  } catch (_) {
    sendJson(res, 404, { error: 'Not found' });
  }
}

function resolveStaticPath(urlPath) {
  const cleanPath = decodeURIComponent(urlPath.split('?')[0]);
  const relative = cleanPath === '/' ? '/index.html' : cleanPath;
  const normalized = path.normalize(relative).replace(/^(\.\.[/\\])+/, '');
  return path.join(ROOT, normalized);
}

function getExpectedOrigin(req) {
  const proto = (req.headers['x-forwarded-proto'] || (HOST === '127.0.0.1' ? 'http' : 'https')).split(',')[0].trim();
  const host = (req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  return host ? `${proto}://${host}` : '';
}

function isAllowedLiveRequest(req) {
  const secFetchSite = String(req.headers['sec-fetch-site'] || '').toLowerCase();
  if (secFetchSite && !['same-origin', 'same-site', 'none'].includes(secFetchSite)) return false;
  const origin = String(req.headers.origin || '').trim();
  if (!origin) return true;
  return origin === getExpectedOrigin(req);
}

function consumeLiveRateLimit(req) {
  const forwardedFor = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const ip = forwardedFor || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const windowMs = 10 * 60 * 1000;
  const maxCalls = 12;
  const recent = (liveCallWindows.get(ip) || []).filter(ts => ts > now - windowMs);
  if (recent.length >= maxCalls) return false;
  recent.push(now);
  liveCallWindows.set(ip, recent);
  return true;
}

async function createRealtimeCall(offerSdp, apiKey, realtimeModel = REALTIME_MODEL) {
  const form = new FormData();
  form.set('sdp', offerSdp);
  form.set('session', JSON.stringify({
    type: 'realtime',
    model: realtimeModel,
    audio: {
      input: {
        transcription: {
          model: TRANSCRIBE_MODEL
        },
        turn_detection: {
          type: 'server_vad',
          create_response: true,
          interrupt_response: true,
          idle_timeout_ms: 6000
        }
      }
    }
  }));

  const response = await fetch('https://api.openai.com/v1/realtime/calls', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`
    },
    body: form
  });

  if (!response.ok) {
    let message = `OpenAI realtime error ${response.status}`;
    try {
      const data = await response.json();
      message = data?.error?.message || message;
    } catch (_) {}
    throw new Error(message);
  }

  return response.text();
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'POST' && req.url === '/api/live/call') {
      if (!isAllowedLiveRequest(req)) {
        sendJson(res, 403, { error: 'Cross-site live requests are not allowed.' });
        return;
      }
      if (!consumeLiveRateLimit(req)) {
        sendJson(res, 429, { error: 'Too many live session attempts. Try again shortly.' });
        return;
      }
      const byokHeader = typeof req.headers['x-openai-key'] === 'string' ? req.headers['x-openai-key'].trim() : '';
      const requestedRealtimeModel = typeof req.headers['x-openai-realtime-model'] === 'string'
        ? req.headers['x-openai-realtime-model'].trim()
        : '';
      const serverKey = ALLOW_SERVER_KEY_LIVE ? OPENAI_API_KEY : '';
      const apiKey = byokHeader || serverKey;
      if (!apiKey) {
        sendJson(res, 503, { error: 'Live mode needs an OpenAI BYOK session or an explicitly enabled server key.' });
        return;
      }
      if (byokHeader && !apiKey.startsWith('sk-')) {
        sendJson(res, 400, { error: 'Invalid OpenAI key format for live mode.' });
        return;
      }

      const offerSdp = await readBody(req);
      if (!offerSdp.trim()) {
        sendJson(res, 400, { error: 'Missing SDP offer.' });
        return;
      }

      const realtimeModel = ALLOWED_REALTIME_MODELS.has(requestedRealtimeModel) ? requestedRealtimeModel : REALTIME_MODEL;
      const answerSdp = await createRealtimeCall(offerSdp, apiKey, realtimeModel);
      res.writeHead(200, buildSecurityHeaders({
        'Content-Type': 'application/sdp; charset=utf-8',
        'Cache-Control': 'no-store'
      }));
      res.end(answerSdp);
      return;
    }

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      sendJson(res, 405, { error: 'Method not allowed' });
      return;
    }

    const filePath = resolveStaticPath(req.url || '/');
    const safePath = path.resolve(filePath);
    if (!safePath.startsWith(ROOT)) {
      sendJson(res, 403, { error: 'Forbidden' });
      return;
    }

    let stat;
    try {
      stat = await fs.promises.stat(safePath);
    } catch (_) {
      await serveFile(path.join(ROOT, 'index.html'), res);
      return;
    }

    const finalPath = stat.isDirectory() ? path.join(safePath, 'index.html') : safePath;
    await serveFile(finalPath, res);
  } catch (error) {
    sendJson(res, 500, { error: error.message || 'Server error' });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Gibsel Cue running at http://${HOST === '127.0.0.1' ? 'localhost' : HOST}:${PORT}`);
});
