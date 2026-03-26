const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const ROOT = __dirname;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const REALTIME_MODEL = process.env.OPENAI_REALTIME_MODEL || 'gpt-realtime';
const TRANSCRIBE_MODEL = process.env.OPENAI_TRANSCRIBE_MODEL || 'gpt-4o-mini-transcribe';

const MIME_TYPES = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml; charset=utf-8'
};

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
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
    res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
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

async function createRealtimeCall(offerSdp, apiKey) {
  const form = new FormData();
  form.set('sdp', offerSdp);
  form.set('session', JSON.stringify({
    type: 'realtime',
    model: REALTIME_MODEL,
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
      const byokHeader = typeof req.headers['x-openai-key'] === 'string' ? req.headers['x-openai-key'].trim() : '';
      const apiKey = OPENAI_API_KEY || byokHeader;
      if (!apiKey) {
        sendJson(res, 503, { error: 'Live mode needs OPENAI_API_KEY on the server or an OpenAI BYOK session in the app.' });
        return;
      }

      const offerSdp = await readBody(req);
      if (!offerSdp.trim()) {
        sendJson(res, 400, { error: 'Missing SDP offer.' });
        return;
      }

      const answerSdp = await createRealtimeCall(offerSdp, apiKey);
      res.writeHead(200, { 'Content-Type': 'application/sdp; charset=utf-8' });
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
