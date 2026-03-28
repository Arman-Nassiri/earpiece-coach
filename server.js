const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

loadEnvFile(path.join(__dirname, '.env.local'));
loadEnvFile(path.join(__dirname, '.env'));

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const ROOT = __dirname;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const ALLOW_SERVER_KEY_LIVE = /^(1|true|yes)$/i.test(process.env.ALLOW_SERVER_KEY_LIVE || '');
const REALTIME_MODEL = process.env.OPENAI_REALTIME_MODEL || 'gpt-realtime';
const TRANSCRIBE_MODEL = process.env.OPENAI_TRANSCRIBE_MODEL || 'gpt-4o-mini-transcribe';
const SUPABASE_URL = String(process.env.SUPABASE_URL || '').trim().replace(/\/+$/, '');
const SUPABASE_ANON_KEY = String(process.env.SUPABASE_ANON_KEY || '').trim();
const SUPABASE_SERVICE_ROLE_KEY = String(process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();
const CUE_KEY_ENCRYPTION_SECRET = String(process.env.CUE_KEY_ENCRYPTION_SECRET || '').trim();
const STRIPE_SECRET_KEY = String(process.env.STRIPE_SECRET_KEY || '').trim();
const STRIPE_WEBHOOK_SECRET = String(process.env.STRIPE_WEBHOOK_SECRET || '').trim();
const STRIPE_PRICE_PRO = String(process.env.STRIPE_PRICE_PRO || '').trim();
const STRIPE_PRICE_EXOTIC = String(process.env.STRIPE_PRICE_EXOTIC || process.env.STRIPE_PRICE_DEAL || '').trim();
const liveCallWindows = new Map();
const stripeSubscriptionCache = new Map();
const ALLOWED_REALTIME_MODELS = new Set(['gpt-realtime', 'gpt-realtime-mini']);
const ACCESS_COOKIE = 'cue_sb_at';
const REFRESH_COOKIE = 'cue_sb_rt';
const REFRESH_COOKIE_MAX_AGE = 60 * 60 * 24 * 30;
const STRIPE_SUBSCRIPTION_CACHE_TTL_MS = 60 * 1000;

const STRIPE_PLAN_CONFIG = Object.freeze({
  free: {
    code: 'free',
    label: 'Free',
    tier: 'free',
    priceId: ''
  },
  pro: {
    code: 'pro',
    label: 'Pro',
    tier: 'private',
    priceId: STRIPE_PRICE_PRO
  },
  exotic: {
    code: 'exotic',
    label: 'Exotic',
    tier: 'private',
    priceId: STRIPE_PRICE_EXOTIC
  }
});
const STRIPE_PRICE_PLAN_INDEX = new Map(
  Object.values(STRIPE_PLAN_CONFIG)
    .filter(plan => plan.priceId)
    .map(plan => [plan.priceId, plan])
);
const FREE_SCENARIO_IDS = Object.freeze(['salary', 'rent', 'car']);
const PRO_SCENARIO_IDS = Object.freeze([
  'salary', 'rent', 'car', 'freelance', 'joboffer', 'biz', 'severance', 'medical',
  'realestate', 'equity', 'agency', 'raise'
]);
const EXOTIC_SCENARIO_IDS = Object.freeze([...PRO_SCENARIO_IDS, 'custom']);
const PLAN_RULES = Object.freeze({
  free: {
    code: 'free',
    label: 'Free',
    sessionLimit: 3,
    allowedScenarioIds: FREE_SCENARIO_IDS,
    features: {
      byok: true,
      hostedKey: false,
      fullLibrary: false,
      sessionHistory: false,
      debriefs: false,
      strategyBrief: false,
      customScenarios: false,
      winLossAnalysis: false,
      earlyAccess: false,
      dedicatedSupport: false
    }
  },
  pro: {
    code: 'pro',
    label: 'Pro',
    sessionLimit: null,
    allowedScenarioIds: PRO_SCENARIO_IDS,
    features: {
      byok: true,
      hostedKey: true,
      fullLibrary: true,
      sessionHistory: true,
      debriefs: true,
      strategyBrief: false,
      customScenarios: false,
      winLossAnalysis: false,
      earlyAccess: true,
      dedicatedSupport: false
    }
  },
  exotic: {
    code: 'exotic',
    label: 'Exotic',
    sessionLimit: null,
    allowedScenarioIds: EXOTIC_SCENARIO_IDS,
    features: {
      byok: true,
      hostedKey: true,
      fullLibrary: true,
      sessionHistory: true,
      debriefs: true,
      strategyBrief: true,
      customScenarios: true,
      winLossAnalysis: true,
      earlyAccess: true,
      dedicatedSupport: true
    }
  }
});

const MIME_TYPES = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml; charset=utf-8'
};

function loadEnvFile(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    raw.split(/\r?\n/).forEach(line => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) return;
      const eq = trimmed.indexOf('=');
      if (eq <= 0) return;
      const key = trimmed.slice(0, eq).trim();
      if (!key || process.env[key] !== undefined) return;
      let value = trimmed.slice(eq + 1).trim();
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      process.env[key] = value;
    });
  } catch (_) {}
}

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

function hasSupabaseAuth() {
  return !!(SUPABASE_URL && SUPABASE_ANON_KEY);
}

function hasSupabaseAdmin() {
  return !!(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY);
}

function hasStripeBilling() {
  return !!(STRIPE_SECRET_KEY && STRIPE_PRICE_PRO && STRIPE_PRICE_EXOTIC);
}

function hasStripeWebhookSupport() {
  return !!(STRIPE_SECRET_KEY && STRIPE_WEBHOOK_SECRET);
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

async function readJsonBody(req) {
  const raw = await readBody(req);
  if (!raw.trim()) return {};
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (_) {
    throw new Error('Invalid JSON body');
  }
}

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
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

function sanitizeNextPath(input, fallback = '/#auth') {
  const value = String(input || '').trim();
  if (!value.startsWith('/')) return fallback;
  if (value.startsWith('//')) return fallback;
  return value;
}

function getCookieDomain(req) {
  const host = (req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  return host && !host.includes('localhost') && !host.startsWith('127.0.0.1') ? host.split(':')[0] : '';
}

function isAllowedLiveRequest(req) {
  const secFetchSite = String(req.headers['sec-fetch-site'] || '').toLowerCase();
  if (secFetchSite && !['same-origin', 'same-site', 'none'].includes(secFetchSite)) return false;
  const origin = String(req.headers.origin || '').trim();
  if (!origin) return true;
  return origin === getExpectedOrigin(req);
}

function isAllowedSameOriginRequest(req) {
  const secFetchSite = String(req.headers['sec-fetch-site'] || '').toLowerCase();
  if (secFetchSite && !['same-origin', 'same-site', 'none'].includes(secFetchSite)) return false;
  const origin = String(req.headers.origin || '').trim();
  if (!origin) return true;
  return origin === getExpectedOrigin(req);
}

function parseCookies(req) {
  const header = String(req.headers.cookie || '');
  if (!header) return {};
  return Object.fromEntries(
    header
      .split(';')
      .map(part => {
        const idx = part.indexOf('=');
        if (idx <= 0) return null;
        const key = part.slice(0, idx).trim();
        const value = part.slice(idx + 1).trim();
        return [key, decodeURIComponent(value)];
      })
      .filter(Boolean)
  );
}

function serializeCookie(name, value, req, options = {}) {
  const segments = [`${name}=${encodeURIComponent(value)}`];
  segments.push('Path=/');
  segments.push('HttpOnly');
  segments.push('SameSite=Lax');
  if (HOST !== '127.0.0.1' || (req.headers['x-forwarded-proto'] || '').includes('https')) {
    segments.push('Secure');
  }
  const domain = getCookieDomain(req);
  if (domain) segments.push(`Domain=${domain}`);
  if (typeof options.maxAge === 'number') segments.push(`Max-Age=${Math.max(0, Math.floor(options.maxAge))}`);
  if (options.expires instanceof Date) segments.push(`Expires=${options.expires.toUTCString()}`);
  return segments.join('; ');
}

function clearAuthCookies(req) {
  const expires = new Date(0);
  return [
    serializeCookie(ACCESS_COOKIE, '', req, { maxAge: 0, expires }),
    serializeCookie(REFRESH_COOKIE, '', req, { maxAge: 0, expires })
  ];
}

function setAuthCookies(req, session) {
  const accessTtl = Number(session?.expires_in || 3600);
  const accessToken = String(session?.access_token || '').trim();
  const refreshToken = String(session?.refresh_token || '').trim();
  const now = Date.now();
  return [
    serializeCookie(ACCESS_COOKIE, accessToken, req, {
      maxAge: Math.max(60, accessTtl),
      expires: new Date(now + Math.max(60, accessTtl) * 1000)
    }),
    serializeCookie(REFRESH_COOKIE, refreshToken, req, {
      maxAge: REFRESH_COOKIE_MAX_AGE,
      expires: new Date(now + REFRESH_COOKIE_MAX_AGE * 1000)
    })
  ];
}

function mapAuthUser(user) {
  if (!user || typeof user !== 'object') return null;
  return {
    id: String(user.id || ''),
    email: String(user.email || ''),
    emailConfirmedAt: user.email_confirmed_at || null,
    createdAt: user.created_at || null,
    displayName: String(user.user_metadata?.display_name || user.user_metadata?.full_name || '').trim()
  };
}

async function supabaseAuthFetch(pathname, options = {}) {
  if (!hasSupabaseAuth()) throw new Error('Supabase auth is not configured.');
  const headers = {
    apikey: SUPABASE_ANON_KEY,
    Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };
  const response = await fetch(`${SUPABASE_URL}${pathname}`, {
    method: options.method || 'GET',
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch (_) {
      data = { raw: text };
    }
  }
  return { response, data };
}

async function fetchSupabaseUser(accessToken) {
  if (!accessToken) return null;
  const { response, data } = await supabaseAuthFetch('/auth/v1/user', {
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  });
  if (!response.ok) return null;
  return mapAuthUser(data);
}

async function refreshSupabaseSession(refreshToken) {
  if (!refreshToken) return null;
  const { response, data } = await supabaseAuthFetch('/auth/v1/token?grant_type=refresh_token', {
    method: 'POST',
    body: {
      refresh_token: refreshToken
    }
  });
  if (!response.ok) return null;
  return data;
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validatePassword(password) {
  return typeof password === 'string' && password.length >= 8 && password.length <= 128;
}

function validateOpenAIKey(apiKey) {
  return typeof apiKey === 'string' && apiKey.startsWith('sk-') && apiKey.length >= 20;
}

function getStripePlanConfig(planCode) {
  const value = String(planCode || '').trim().toLowerCase();
  if (value === 'deal') return STRIPE_PLAN_CONFIG.exotic;
  return STRIPE_PLAN_CONFIG[value] || null;
}

function getStripePlanByPriceId(priceId) {
  return STRIPE_PRICE_PLAN_INDEX.get(String(priceId || '').trim()) || null;
}

function getPlanRule(planCode) {
  return PLAN_RULES[String(planCode || '').trim().toLowerCase()] || PLAN_RULES.free;
}

function getMonthStartIso(reference = new Date()) {
  return new Date(Date.UTC(reference.getUTCFullYear(), reference.getUTCMonth(), 1, 0, 0, 0, 0)).toISOString();
}

function hasHostedOpenAIKeyAvailable() {
  return ALLOW_SERVER_KEY_LIVE && validateOpenAIKey(OPENAI_API_KEY || '');
}

function buildAccessState(billing, options = {}) {
  const effectivePlanCode = billing?.isPaid ? (billing?.planCode || 'free') : 'free';
  const planCode = getPlanRule(effectivePlanCode).code;
  const rule = getPlanRule(planCode);
  const savedKey = !!options.savedKey;
  const sessionsUsed = Math.max(0, Number(options.sessionsUsedThisMonth || 0));
  const sessionLimit = rule.sessionLimit;
  const sessionsRemaining = sessionLimit === null ? null : Math.max(0, sessionLimit - sessionsUsed);
  const hostedKeyEligible = !!rule.features.hostedKey;
  const hostedKeyAvailable = hostedKeyEligible && hasHostedOpenAIKeyAvailable();
  const requiresSavedKey = !hostedKeyAvailable && !savedKey;
  return {
    planCode: rule.code,
    planLabel: rule.label,
    sessionLimit,
    sessionsUsedThisMonth: sessionsUsed,
    sessionsRemaining,
    allowedScenarioIds: [...rule.allowedScenarioIds],
    features: {
      ...rule.features,
      hostedKeyEligible,
      hostedKeyAvailable
    },
    canStartSession: sessionLimit === null || sessionsRemaining > 0,
    requiresSavedKey,
    hasSavedKey: savedKey
  };
}

function canAccessScenario(access, scenarioId) {
  return !!access && access.allowedScenarioIds.includes(String(scenarioId || '').trim());
}

function getScenarioGatePlanLabel(scenarioId) {
  const id = String(scenarioId || '').trim();
  if (EXOTIC_SCENARIO_IDS.includes(id) && !PRO_SCENARIO_IDS.includes(id)) return 'Exotic';
  if (PRO_SCENARIO_IDS.includes(id) && !FREE_SCENARIO_IDS.includes(id)) return 'Pro';
  return 'Free';
}

function getManualBillingPlanCode(subscriptionId) {
  const match = String(subscriptionId || '').trim().toLowerCase().match(/^(manual|comp):(pro|exotic|deal)$/);
  if (!match) return '';
  return match[2] === 'deal' ? 'exotic' : match[2];
}

function normalizeBillingStatus(status) {
  const value = String(status || '').trim().toLowerCase();
  if (value === 'trialing') return 'trialing';
  if (value === 'active') return 'active';
  if (value === 'past_due') return 'past_due';
  if (value === 'canceled' || value === 'unpaid' || value === 'incomplete_expired') return 'canceled';
  return 'inactive';
}

function isPaidBillingStatus(status) {
  return ['trialing', 'active', 'past_due'].includes(normalizeBillingStatus(status));
}

function toIsoFromUnixSeconds(value) {
  const seconds = Number(value || 0);
  if (!Number.isFinite(seconds) || seconds <= 0) return null;
  return new Date(seconds * 1000).toISOString();
}

function appendStripeFormValue(form, key, value) {
  if (value === undefined || value === null || value === '') return;
  form.append(key, String(value));
}

async function stripeApiFetch(pathname, options = {}) {
  if (!STRIPE_SECRET_KEY) throw new Error('Stripe billing is not configured.');
  const headers = {
    Authorization: `Bearer ${STRIPE_SECRET_KEY}`,
    ...(options.headers || {})
  };
  let body;
  if (options.form) {
    const form = options.form instanceof URLSearchParams ? options.form : buildStripeForm(options.form);
    body = form.toString();
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
  } else if (options.body) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(options.body);
  }

  const response = await fetch(`https://api.stripe.com/v1${pathname}`, {
    method: options.method || 'GET',
    headers,
    body
  });
  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch (_) {
      data = { raw: text };
    }
  }
  if (!response.ok) {
    const message = data?.error?.message || data?.message || `Stripe request failed (${response.status}).`;
    throw new Error(message);
  }
  return data;
}

function verifyStripeWebhookSignature(payload, signatureHeader) {
  if (!STRIPE_WEBHOOK_SECRET) throw new Error('Stripe webhook secret is not configured.');
  const header = String(signatureHeader || '').trim();
  if (!header) throw new Error('Missing Stripe signature header.');

  const pairs = header.split(',').map(part => part.trim()).filter(Boolean);
  const timestamp = pairs.find(part => part.startsWith('t='))?.slice(2) || '';
  const signatures = pairs
    .filter(part => part.startsWith('v1='))
    .map(part => part.slice(3))
    .filter(Boolean);
  if (!timestamp || !signatures.length) {
    throw new Error('Stripe signature header is invalid.');
  }

  const ageSeconds = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
  if (!Number.isFinite(ageSeconds) || ageSeconds > 300) {
    throw new Error('Stripe signature timestamp is too old.');
  }

  const expected = crypto
    .createHmac('sha256', STRIPE_WEBHOOK_SECRET)
    .update(`${timestamp}.${payload}`, 'utf8')
    .digest('hex');
  const expectedBuffer = Buffer.from(expected, 'utf8');
  const valid = signatures.some(signature => {
    const actualBuffer = Buffer.from(signature, 'utf8');
    return actualBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(actualBuffer, expectedBuffer);
  });
  if (!valid) throw new Error('Stripe signature verification failed.');
}

function getEncryptionKey() {
  if (!CUE_KEY_ENCRYPTION_SECRET) return null;
  return crypto.createHash('sha256').update(CUE_KEY_ENCRYPTION_SECRET).digest();
}

function encryptStoredSecret(plainText) {
  const key = getEncryptionKey();
  if (!key) throw new Error('Key encryption secret is not configured.');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(String(plainText), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1.${iv.toString('base64url')}.${tag.toString('base64url')}.${encrypted.toString('base64url')}`;
}

function decryptStoredSecret(payload) {
  const key = getEncryptionKey();
  if (!key) throw new Error('Key encryption secret is not configured.');
  const [version, ivEncoded, tagEncoded, encryptedEncoded] = String(payload || '').split('.');
  if (version !== 'v1' || !ivEncoded || !tagEncoded || !encryptedEncoded) {
    throw new Error('Stored secret format is invalid.');
  }
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(ivEncoded, 'base64url')
  );
  decipher.setAuthTag(Buffer.from(tagEncoded, 'base64url'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encryptedEncoded, 'base64url')),
    decipher.final()
  ]);
  return decrypted.toString('utf8');
}

function buildSupabaseRestPath(table, params = {}) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return;
    query.set(key, String(value));
  });
  return `/rest/v1/${table}${query.toString() ? `?${query}` : ''}`;
}

async function supabaseAdminFetch(pathname, options = {}) {
  if (!hasSupabaseAdmin()) throw new Error('Supabase admin access is not configured.');
  const headers = {
    apikey: SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };
  const response = await fetch(`${SUPABASE_URL}${pathname}`, {
    method: options.method || 'GET',
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch (_) {
      data = { raw: text };
    }
  }
  return { response, data };
}

async function fetchSingleBillingAccount(filters = {}) {
  if (!hasSupabaseAdmin()) return null;
  const { data } = await supabaseAdminFetch(buildSupabaseRestPath('billing_accounts', {
    ...filters,
    select: 'user_id,plan_tier,plan_status,stripe_customer_id,stripe_subscription_id,current_period_end',
    limit: 1
  }));
  return Array.isArray(data) ? (data[0] || null) : null;
}

async function fetchBillingAccountForUser(userId) {
  if (!userId) return null;
  return fetchSingleBillingAccount({ user_id: `eq.${userId}` });
}

async function fetchBillingAccountByStripeCustomer(customerId) {
  if (!customerId) return null;
  return fetchSingleBillingAccount({ stripe_customer_id: `eq.${customerId}` });
}

async function fetchBillingAccountByStripeSubscription(subscriptionId) {
  if (!subscriptionId) return null;
  return fetchSingleBillingAccount({ stripe_subscription_id: `eq.${subscriptionId}` });
}

async function upsertBillingAccountRecord(userId, patch = {}) {
  if (!userId || !hasSupabaseAdmin()) return null;
  const payload = {
    user_id: userId,
    ...patch
  };
  const { response, data } = await supabaseAdminFetch(
    buildSupabaseRestPath('billing_accounts', { on_conflict: 'user_id' }),
    {
      method: 'POST',
      headers: {
        Prefer: 'resolution=merge-duplicates,return=representation'
      },
      body: payload
    }
  );
  if (!response.ok) {
    throw new Error(data?.message || 'Could not update billing account.');
  }
  return Array.isArray(data) ? (data[0] || null) : data;
}

function buildStripeForm(entries = {}) {
  const form = new URLSearchParams();
  Object.entries(entries).forEach(([key, value]) => {
    appendStripeFormValue(form, key, value);
  });
  return form;
}

async function createStripeCustomer(user) {
  const form = buildStripeForm({
    email: user?.email || '',
    name: user?.displayName || '',
    'metadata[user_id]': user?.id || ''
  });
  const data = await stripeApiFetch('/customers', {
    method: 'POST',
    form
  });
  return String(data?.id || '').trim();
}

function mapStripeSubscriptionPlan(subscription) {
  const metadataPlanCode = String(subscription?.metadata?.plan_code || '').trim().toLowerCase();
  const metadataPlan = getStripePlanConfig(metadataPlanCode);
  if (metadataPlan) return metadataPlan;
  const priceId = String(subscription?.items?.data?.[0]?.price?.id || '').trim();
  return getStripePlanByPriceId(priceId);
}

function mapStripeSubscriptionSummary(subscription, billingFallback = null) {
  const normalizedStatus = normalizeBillingStatus(subscription?.status);
  const plan = mapStripeSubscriptionPlan(subscription);
  const paid = !!plan && isPaidBillingStatus(normalizedStatus);
  return {
    planCode: plan?.code || '',
    planName: plan?.label || (paid ? 'Cue Private' : 'Free'),
    planTier: paid ? plan.tier : 'free',
    planStatus: normalizedStatus || String(billingFallback?.plan_status || 'inactive'),
    currentPeriodEnd: toIsoFromUnixSeconds(subscription?.current_period_end) || billingFallback?.current_period_end || null,
    stripeCustomerId: String(subscription?.customer || billingFallback?.stripe_customer_id || '').trim(),
    stripeSubscriptionId: String(subscription?.id || billingFallback?.stripe_subscription_id || '').trim(),
    priceId: String(subscription?.items?.data?.[0]?.price?.id || '').trim(),
    isPaid: paid
  };
}

async function fetchStripeSubscription(subscriptionId, { force = false } = {}) {
  const cacheKey = String(subscriptionId || '').trim();
  if (!cacheKey) return null;
  const cached = stripeSubscriptionCache.get(cacheKey);
  if (!force && cached && Date.now() - cached.fetchedAt < STRIPE_SUBSCRIPTION_CACHE_TTL_MS) {
    return cached.subscription;
  }
  const data = await stripeApiFetch(`/subscriptions/${encodeURIComponent(cacheKey)}?expand[]=items.data.price`);
  stripeSubscriptionCache.set(cacheKey, {
    fetchedAt: Date.now(),
    subscription: data
  });
  return data;
}

async function resolveBillingUserIdFromStripeRefs({ userId = '', customerId = '', subscriptionId = '' } = {}) {
  if (userId) return userId;
  const bySubscription = subscriptionId ? await fetchBillingAccountByStripeSubscription(subscriptionId) : null;
  if (bySubscription?.user_id) return bySubscription.user_id;
  const byCustomer = customerId ? await fetchBillingAccountByStripeCustomer(customerId) : null;
  return byCustomer?.user_id || '';
}

async function syncBillingAccountFromStripeSubscriptionObject(subscription, userIdHint = '') {
  if (!subscription) return null;
  const customerId = String(subscription.customer || '').trim();
  const subscriptionId = String(subscription.id || '').trim();
  const userId = await resolveBillingUserIdFromStripeRefs({
    userId: String(subscription?.metadata?.user_id || userIdHint || '').trim(),
    customerId,
    subscriptionId
  });
  if (!userId) return null;

  stripeSubscriptionCache.set(subscriptionId, {
    fetchedAt: Date.now(),
    subscription
  });

  const summary = mapStripeSubscriptionSummary(subscription);
  const paid = isPaidBillingStatus(summary.planStatus) && summary.planTier !== 'free';
  await upsertBillingAccountRecord(userId, {
    plan_tier: paid ? summary.planTier : 'free',
    plan_status: summary.planStatus,
    stripe_customer_id: summary.stripeCustomerId || null,
    stripe_subscription_id: summary.stripeSubscriptionId || null,
    current_period_end: summary.currentPeriodEnd
  });
  return summary;
}

async function syncBillingAccountFromSubscriptionId(subscriptionId, context = {}) {
  const subscription = await fetchStripeSubscription(subscriptionId, { force: true });
  if (!subscription) return null;
  return syncBillingAccountFromStripeSubscriptionObject(subscription, context.userId || '');
}

async function ensureStripeCustomerForUser(user, billingAccount = null) {
  const existingCustomerId = String(billingAccount?.stripe_customer_id || '').trim();
  if (existingCustomerId) return existingCustomerId;
  const customerId = await createStripeCustomer(user);
  await upsertBillingAccountRecord(user.id, {
    stripe_customer_id: customerId
  });
  return customerId;
}

async function countMonthlyNegotiationRuns(userId) {
  if (!userId || !hasSupabaseAdmin()) return 0;
  const { data } = await supabaseAdminFetch(buildSupabaseRestPath('negotiation_runs', {
    user_id: `eq.${userId}`,
    started_at: `gte.${getMonthStartIso()}`,
    status: 'neq.failed',
    select: 'id'
  }));
  return Array.isArray(data) ? data.length : 0;
}

async function fetchRecentRunHistory(userId) {
  if (!userId || !hasSupabaseAdmin()) return [];
  const { data: runsData } = await supabaseAdminFetch(buildSupabaseRestPath('negotiation_runs', {
    user_id: `eq.${userId}`,
    select: 'id,mode,scenario_name,status,created_at,ended_at,metadata',
    order: 'created_at.desc',
    limit: 6
  }));
  const runs = Array.isArray(runsData) ? runsData : [];
  if (!runs.length) return [];
  const runIds = runs.map(run => run.id).filter(Boolean);
  const inClause = runIds.length ? `in.(${runIds.join(',')})` : '';
  const { data: reportsData } = inClause
    ? await supabaseAdminFetch(buildSupabaseRestPath('analysis_reports', {
        user_id: `eq.${userId}`,
        run_id: inClause,
        select: 'run_id,score,verdict,summary,payload'
      }))
    : { data: [] };
  const reportsByRunId = new Map(
    (Array.isArray(reportsData) ? reportsData : []).map(report => [report.run_id, report])
  );
  return runs.map(run => {
    const report = reportsByRunId.get(run.id) || null;
    return {
      id: run.id,
      mode: run.mode || '',
      scenarioName: run.scenario_name || 'Session',
      createdAt: run.created_at || null,
      endedAt: run.ended_at || null,
      status: run.status || 'completed',
      summary: report?.summary || run?.metadata?.reviewSummary || '',
      verdict: report?.verdict || '',
      score: report?.score || '',
      outcome: report?.payload?.outcome || run?.metadata?.outcome || '',
      planCode: run?.metadata?.planCode || '',
      scenarioId: run?.metadata?.scenarioId || ''
    };
  });
}

async function createNegotiationRun(userId, payload = {}) {
  if (!userId || !hasSupabaseAdmin()) throw new Error('Supabase admin access is not configured.');
  const { response, data } = await supabaseAdminFetch('/rest/v1/negotiation_runs', {
    method: 'POST',
    headers: {
      Prefer: 'return=representation'
    },
    body: {
      user_id: userId,
      mode: payload.mode,
      scenario_name: String(payload.scenarioName || 'Session').trim().slice(0, 120),
      status: payload.status || 'in_progress',
      metadata: payload.metadata || {},
      started_at: payload.startedAt || new Date().toISOString(),
      ended_at: payload.endedAt || null
    }
  });
  if (!response.ok) {
    throw new Error(data?.message || 'Could not create negotiation run.');
  }
  return Array.isArray(data) ? (data[0] || null) : data;
}

async function fetchNegotiationRunById(userId, runId) {
  if (!userId || !runId || !hasSupabaseAdmin()) return null;
  const { data } = await supabaseAdminFetch(buildSupabaseRestPath('negotiation_runs', {
    user_id: `eq.${userId}`,
    id: `eq.${runId}`,
    select: 'id,user_id,mode,scenario_name,status,metadata,started_at,ended_at',
    limit: 1
  }));
  return Array.isArray(data) ? (data[0] || null) : null;
}

async function updateNegotiationRun(userId, runId, patch = {}) {
  if (!userId || !runId || !hasSupabaseAdmin()) return null;
  const { response, data } = await supabaseAdminFetch(buildSupabaseRestPath('negotiation_runs', {
    user_id: `eq.${userId}`,
    id: `eq.${runId}`
  }), {
    method: 'PATCH',
    headers: {
      Prefer: 'return=representation'
    },
    body: patch
  });
  if (!response.ok) {
    throw new Error(data?.message || 'Could not update negotiation run.');
  }
  return Array.isArray(data) ? (data[0] || null) : data;
}

async function upsertAnalysisReport(userId, runId, payload = {}) {
  if (!userId || !runId || !hasSupabaseAdmin()) return null;
  const { response, data } = await supabaseAdminFetch(
    buildSupabaseRestPath('analysis_reports', { on_conflict: 'run_id' }),
    {
      method: 'POST',
      headers: {
        Prefer: 'resolution=merge-duplicates,return=representation'
      },
      body: {
        user_id: userId,
        run_id: runId,
        score: payload.score || null,
        verdict: payload.verdict || null,
        summary: payload.summary || null,
        payload: payload.payload || {}
      }
    }
  );
  if (!response.ok) {
    throw new Error(data?.message || 'Could not save session analysis.');
  }
  return Array.isArray(data) ? (data[0] || null) : data;
}

async function fetchBillingStateForUser(userId) {
  const billing = await fetchBillingAccountForUser(userId);
  if (!billing) {
    return {
      enabled: hasStripeBilling(),
      planTier: 'free',
      planStatus: 'inactive',
      planName: 'Free',
      planCode: 'free',
      currentPeriodEnd: null,
      canManage: false,
      isPaid: false
    };
  }

  let summary = null;
  const manualPlanCode = getManualBillingPlanCode(billing.stripe_subscription_id);
  if (manualPlanCode) {
    const manualPlan = getStripePlanConfig(manualPlanCode);
    const manualStatus = normalizeBillingStatus(billing.plan_status || 'active');
    const manualPaid = !!manualPlan && isPaidBillingStatus(manualStatus);
    summary = {
      planCode: manualPaid ? manualPlan.code : 'free',
      planName: manualPaid ? manualPlan.label : 'Free',
      planTier: manualPaid ? manualPlan.tier : 'free',
      planStatus: manualStatus,
      currentPeriodEnd: billing.current_period_end || null,
      stripeCustomerId: '',
      stripeSubscriptionId: String(billing.stripe_subscription_id || '').trim(),
      priceId: '',
      isPaid: manualPaid
    };
  } else if (hasStripeBilling() && billing.stripe_subscription_id) {
    try {
      const subscription = await fetchStripeSubscription(billing.stripe_subscription_id);
      summary = mapStripeSubscriptionSummary(subscription, billing);
    } catch (_) {}
  }

  const planTier = String(summary?.planTier || billing.plan_tier || 'free');
  const planStatus = normalizeBillingStatus(summary?.planStatus || billing.plan_status || 'inactive');
  const isPaid = planTier !== 'free' && isPaidBillingStatus(planStatus);
  return {
    enabled: hasStripeBilling(),
    planTier,
    planStatus,
    planName: isPaid ? (summary?.planName || 'Cue Private') : 'Free',
    planCode: isPaid ? (summary?.planCode || 'free') : 'free',
    currentPeriodEnd: summary?.currentPeriodEnd || billing.current_period_end || null,
    canManage: hasStripeBilling() && !manualPlanCode && !!String(summary?.stripeCustomerId || billing.stripe_customer_id || '').trim(),
    isPaid
  };
}

async function handleStripeWebhookEvent(event) {
  const type = String(event?.type || '').trim();
  if (type === 'checkout.session.completed') {
    const session = event?.data?.object || {};
    if (session.mode === 'subscription' && session.subscription) {
      await syncBillingAccountFromSubscriptionId(session.subscription, {
        userId: String(session?.metadata?.user_id || session?.client_reference_id || '').trim()
      });
    }
    return;
  }
  if (type === 'customer.subscription.updated' || type === 'customer.subscription.deleted') {
    await syncBillingAccountFromStripeSubscriptionObject(event?.data?.object || {});
    return;
  }
  if (type === 'invoice.paid' || type === 'invoice.payment_failed') {
    const invoice = event?.data?.object || {};
    if (invoice.subscription) {
      await syncBillingAccountFromSubscriptionId(invoice.subscription, {
        userId: String(invoice?.lines?.data?.[0]?.metadata?.user_id || '').trim()
      });
    }
  }
}

async function getAuthenticatedRequestState(req) {
  if (!hasSupabaseAuth()) return { user: null, setCookies: [] };
  const cookies = parseCookies(req);
  let accessToken = cookies[ACCESS_COOKIE] || '';
  const refreshToken = cookies[REFRESH_COOKIE] || '';
  let user = await fetchSupabaseUser(accessToken);
  let setCookies = [];
  if (!user && refreshToken) {
    const refreshed = await refreshSupabaseSession(refreshToken);
    if (refreshed?.access_token && refreshed?.refresh_token) {
      accessToken = refreshed.access_token;
      setCookies = setAuthCookies(req, refreshed);
      user = await fetchSupabaseUser(accessToken);
    }
  }
  return { user, setCookies };
}

async function fetchAccountStateForUser(user) {
  const fallback = {
    displayName: String(user?.displayName || '').trim(),
    email: String(user?.email || '').trim(),
    onboardingComplete: false,
    savedKey: null,
    billing: {
      enabled: hasStripeBilling(),
      planTier: 'free',
      planStatus: 'inactive',
      planName: 'Free',
      planCode: 'free',
      currentPeriodEnd: null,
      canManage: false,
      isPaid: false
    },
    access: buildAccessState({ planCode: 'free' }, { savedKey: false, sessionsUsedThisMonth: 0 }),
    history: {
      available: false,
      entries: []
    }
  };
  if (!user?.id || !hasSupabaseAdmin()) return fallback;

  const profilePath = buildSupabaseRestPath('profiles', {
    id: `eq.${user.id}`,
    select: 'id,email,display_name,onboarding_complete',
    limit: 1
  });
  const keyPath = buildSupabaseRestPath('user_api_keys', {
    user_id: `eq.${user.id}`,
    provider: 'eq.openai',
    is_active: 'eq.true',
    select: 'id,provider,key_last4,label,updated_at',
    order: 'updated_at.desc',
    limit: 1
  });

  const [{ data: profileData }, { data: keyData }, billing, sessionsUsedThisMonth] = await Promise.all([
    supabaseAdminFetch(profilePath),
    supabaseAdminFetch(keyPath),
    fetchBillingStateForUser(user.id),
    countMonthlyNegotiationRuns(user.id)
  ]);

  const profile = Array.isArray(profileData) ? profileData[0] : null;
  const savedKey = Array.isArray(keyData) && keyData[0]
    ? {
        id: keyData[0].id,
        provider: keyData[0].provider,
        last4: keyData[0].key_last4,
        label: keyData[0].label || '',
        updatedAt: keyData[0].updated_at || null
      }
    : null;
  const access = buildAccessState(billing, {
    savedKey: !!savedKey,
    sessionsUsedThisMonth
  });
  const historyEntries = access.features.sessionHistory ? await fetchRecentRunHistory(user.id) : [];

  return {
    displayName: String(profile?.display_name || fallback.displayName).trim(),
    email: String(profile?.email || fallback.email).trim(),
    onboardingComplete: !!profile?.onboarding_complete,
    savedKey,
    billing: billing || fallback.billing,
    access,
    history: {
      available: access.features.sessionHistory,
      entries: historyEntries
    }
  };
}

async function fetchStoredOpenAIKey(userId) {
  if (!userId || !hasSupabaseAdmin()) return '';
  const keyPath = buildSupabaseRestPath('user_api_keys', {
    user_id: `eq.${userId}`,
    provider: 'eq.openai',
    is_active: 'eq.true',
    select: 'encrypted_key',
    order: 'updated_at.desc',
    limit: 1
  });
  const { data } = await supabaseAdminFetch(keyPath);
  const row = Array.isArray(data) ? data[0] : null;
  if (!row?.encrypted_key) return '';
  return decryptStoredSecret(row.encrypted_key);
}

async function resolveAccountForUser(user) {
  if (!user?.id) throw new Error('Sign in first.');
  return fetchAccountStateForUser(user);
}

async function resolveApiKeyForAccount(account, userId) {
  const savedKey = await fetchStoredOpenAIKey(userId);
  if (validateOpenAIKey(savedKey)) {
    return { apiKey: savedKey, source: 'saved' };
  }
  if (account?.access?.features?.hostedKeyAvailable && validateOpenAIKey(OPENAI_API_KEY || '')) {
    return { apiKey: OPENAI_API_KEY, source: 'hosted' };
  }
  return { apiKey: '', source: '' };
}

async function verifyOpenAIKeyServer(apiKey) {
  const response = await fetch('https://api.openai.com/v1/models', {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${apiKey}`
    }
  });
  if (!response.ok) {
    let message = 'OpenAI rejected that API key.';
    try {
      const data = await response.json();
      message = data?.error?.message || message;
    } catch (_) {}
    throw new Error(message);
  }
}

async function upsertAccountProfile(user, displayName) {
  const payload = {
    id: user.id,
    email: user.email,
    display_name: String(displayName || '').trim().slice(0, 80),
    onboarding_complete: true
  };
  const { response, data } = await supabaseAdminFetch(
    buildSupabaseRestPath('profiles', { on_conflict: 'id' }),
    {
      method: 'POST',
      headers: {
        Prefer: 'resolution=merge-duplicates,return=representation'
      },
      body: payload
    }
  );
  if (!response.ok) {
    throw new Error(data?.message || 'Could not update account profile.');
  }
  return Array.isArray(data) ? data[0] : data;
}

async function replaceStoredOpenAIKey(user, apiKey, label = '') {
  if (!hasSupabaseAdmin()) throw new Error('Supabase admin access is not configured.');
  if (!validateOpenAIKey(apiKey)) throw new Error('That does not look like a valid OpenAI key.');
  await verifyOpenAIKeyServer(apiKey);

  await supabaseAdminFetch(buildSupabaseRestPath('user_api_keys', {
    user_id: `eq.${user.id}`,
    provider: 'eq.openai',
    is_active: 'eq.true'
  }), {
    method: 'PATCH',
    headers: {
      Prefer: 'return=minimal'
    },
    body: {
      is_active: false
    }
  });

  const { response, data } = await supabaseAdminFetch('/rest/v1/user_api_keys', {
    method: 'POST',
    headers: {
      Prefer: 'return=representation'
    },
    body: {
      user_id: user.id,
      provider: 'openai',
      label: String(label || '').trim().slice(0, 80),
      encrypted_key: encryptStoredSecret(apiKey),
      key_last4: apiKey.slice(-4),
      is_active: true
    }
  });
  if (!response.ok) {
    throw new Error(data?.message || 'Could not save your OpenAI key.');
  }
  return Array.isArray(data) ? data[0] : data;
}

async function deleteStoredOpenAIKey(userId) {
  if (!userId || !hasSupabaseAdmin()) return;
  const { response, data } = await supabaseAdminFetch(buildSupabaseRestPath('user_api_keys', {
    user_id: `eq.${userId}`,
    provider: 'eq.openai'
  }), {
    method: 'DELETE',
    headers: {
      Prefer: 'return=minimal'
    }
  });
  if (!response.ok) {
    throw new Error(data?.message || 'Could not delete saved key.');
  }
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

function buildGoogleOAuthCallbackPage(req) {
  const next = sanitizeNextPath(new URL(req.url, getExpectedOrigin(req) || 'http://localhost').searchParams.get('next'));
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Google Sign-In</title>
  <style>
    body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:#f5f3ef;color:#18170f;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px}
    .card{width:min(440px,100%);background:#fff;border:1px solid #e0ddd6;border-radius:18px;padding:28px}
    h1{margin:0 0 8px;font-size:28px}
    p{margin:0 0 14px;line-height:1.6;color:#46443c}
    .muted{color:#8c8980;font-size:14px}
    .spinner{width:28px;height:28px;border:2px solid #c8c4ba;border-top-color:#18170f;border-radius:999px;animation:spin .8s linear infinite;margin-bottom:16px}
    .error{color:#d4380d}
    a{color:#18170f}
    @keyframes spin{to{transform:rotate(360deg)}}
  </style>
</head>
<body>
  <div class="card">
    <div class="spinner" id="spinner"></div>
    <h1 id="title">Finishing Google sign-in</h1>
    <p id="body">Verifying the Google session and attaching it to Cue.</p>
    <p class="muted" id="meta">You will be redirected automatically.</p>
  </div>
  <script>
    const next = ${JSON.stringify(next)};
    const title = document.getElementById('title');
    const body = document.getElementById('body');
    const meta = document.getElementById('meta');
    const spinner = document.getElementById('spinner');
    const query = new URLSearchParams(window.location.search);
    const hash = new URLSearchParams(window.location.hash.replace(/^#/, ''));
    const queryError = query.get('error_description') || query.get('error');
    const hashError = hash.get('error_description') || hash.get('error');
    const accessToken = hash.get('access_token');
    const refreshToken = hash.get('refresh_token');
    const expiresIn = hash.get('expires_in');

    function fail(message) {
      spinner.style.display = 'none';
      title.textContent = 'Google sign-in failed';
      body.textContent = message;
      body.classList.add('error');
      meta.innerHTML = '<a href="/#auth">Back to account</a>';
    }

    async function complete() {
      if (queryError || hashError) {
        fail(queryError || hashError);
        return;
      }
      if (!accessToken || !refreshToken) {
        fail('Missing Google session tokens from Supabase.');
        return;
      }
      try {
        const res = await fetch('/api/auth/oauth/google/complete', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            accessToken,
            refreshToken,
            expiresIn
          })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || 'Could not complete Google sign-in.');
        window.location.replace(next);
      } catch (error) {
        fail(error.message || 'Could not complete Google sign-in.');
      }
    }

    complete();
  </script>
</body>
</html>`;
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'POST' && req.url === '/api/webhook/stripe') {
      if (!hasStripeWebhookSupport()) {
        sendJson(res, 503, { error: 'Stripe webhooks are not configured.' });
        return;
      }
      const payload = await readBody(req);
      try {
        verifyStripeWebhookSignature(payload, req.headers['stripe-signature']);
        const event = JSON.parse(payload);
        await handleStripeWebhookEvent(event);
      } catch (error) {
        sendJson(res, 400, { error: error.message || 'Invalid Stripe webhook.' });
        return;
      }
      sendJson(res, 200, { received: true });
      return;
    }

    if (req.method === 'GET' && req.url.startsWith('/api/auth/google/start')) {
      if (!hasSupabaseAuth()) {
        sendJson(res, 503, { error: 'Supabase auth is not configured.' });
        return;
      }
      const currentUrl = new URL(req.url, getExpectedOrigin(req) || 'http://localhost');
      const next = sanitizeNextPath(currentUrl.searchParams.get('next'));
      const origin = getExpectedOrigin(req);
      const redirectTo = `${origin}/auth/google/callback?next=${encodeURIComponent(next)}`;
      const location = `${SUPABASE_URL}/auth/v1/authorize?provider=google&redirect_to=${encodeURIComponent(redirectTo)}`;
      res.writeHead(302, buildSecurityHeaders({
        'Cache-Control': 'no-store',
        Location: location
      }));
      res.end();
      return;
    }

    if (req.method === 'GET' && req.url === '/api/auth/session') {
      if (!hasSupabaseAuth()) {
        sendJson(res, 200, { authenticated: false, configured: false });
        return;
      }
      const { user, setCookies } = await getAuthenticatedRequestState(req);
      if (!user) {
        sendJson(res, 200, { authenticated: false, configured: true }, {
          'Set-Cookie': clearAuthCookies(req)
        });
        return;
      }
      const account = await fetchAccountStateForUser(user);
      sendJson(res, 200, {
        authenticated: true,
        configured: true,
        user,
        account
      }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
      return;
    }

    if (req.method === 'POST' && req.url === '/api/auth/signup') {
      if (!isAllowedSameOriginRequest(req)) {
        sendJson(res, 403, { error: 'Cross-site auth requests are not allowed.' });
        return;
      }
      if (!hasSupabaseAuth()) {
        sendJson(res, 503, { error: 'Supabase auth is not configured.' });
        return;
      }
      const body = await readJsonBody(req);
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');
      const displayName = String(body.displayName || '').trim().slice(0, 80);
      if (!validateEmail(email)) {
        sendJson(res, 400, { error: 'Enter a valid email address.' });
        return;
      }
      if (!validatePassword(password)) {
        sendJson(res, 400, { error: 'Password must be at least 8 characters.' });
        return;
      }
      const { response, data } = await supabaseAuthFetch('/auth/v1/signup', {
        method: 'POST',
        body: {
          email,
          password,
          data: displayName ? { display_name: displayName } : {}
        }
      });
      if (!response.ok) {
        sendJson(res, response.status, { error: data?.msg || data?.error_description || data?.message || 'Could not create account.' });
        return;
      }
      const session = data?.session || null;
      const user = mapAuthUser(data?.user);
      const account = user ? await fetchAccountStateForUser(user) : null;
      sendJson(res, 200, {
        ok: true,
        requiresEmailVerification: !session,
        user,
        account
      }, session ? { 'Set-Cookie': setAuthCookies(req, session) } : {});
      return;
    }

    if (req.method === 'POST' && req.url === '/api/auth/signin') {
      if (!isAllowedSameOriginRequest(req)) {
        sendJson(res, 403, { error: 'Cross-site auth requests are not allowed.' });
        return;
      }
      if (!hasSupabaseAuth()) {
        sendJson(res, 503, { error: 'Supabase auth is not configured.' });
        return;
      }
      const body = await readJsonBody(req);
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');
      if (!validateEmail(email) || !password) {
        sendJson(res, 400, { error: 'Enter your email and password.' });
        return;
      }
      const { response, data } = await supabaseAuthFetch('/auth/v1/token?grant_type=password', {
        method: 'POST',
        body: {
          email,
          password
        }
      });
      if (!response.ok) {
        sendJson(res, response.status, { error: data?.msg || data?.error_description || data?.message || 'Could not sign in.' });
        return;
      }
      const user = mapAuthUser(data?.user);
      const account = user ? await fetchAccountStateForUser(user) : null;
      sendJson(res, 200, {
        ok: true,
        user,
        account
      }, { 'Set-Cookie': setAuthCookies(req, data) });
      return;
    }

    if (req.method === 'POST' && req.url === '/api/auth/signout') {
      if (!isAllowedSameOriginRequest(req)) {
        sendJson(res, 403, { error: 'Cross-site auth requests are not allowed.' });
        return;
      }
      const cookies = parseCookies(req);
      const accessToken = cookies[ACCESS_COOKIE] || '';
      if (accessToken && hasSupabaseAuth()) {
        try {
          await supabaseAuthFetch('/auth/v1/logout', {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${accessToken}`
            }
          });
        } catch (_) {}
      }
      sendJson(res, 200, { ok: true }, {
        'Set-Cookie': clearAuthCookies(req)
      });
      return;
    }

    if (req.method === 'POST' && req.url === '/api/auth/oauth/google/complete') {
      if (!isAllowedSameOriginRequest(req)) {
        sendJson(res, 403, { error: 'Cross-site auth requests are not allowed.' });
        return;
      }
      const body = await readJsonBody(req);
      const accessToken = String(body.accessToken || '').trim();
      const refreshToken = String(body.refreshToken || '').trim();
      const expiresIn = Math.max(60, Number(body.expiresIn || 3600));
      if (!accessToken || !refreshToken) {
        sendJson(res, 400, { error: 'Missing OAuth session tokens.' });
        return;
      }
      const user = await fetchSupabaseUser(accessToken);
      if (!user) {
        sendJson(res, 401, { error: 'Supabase rejected the Google session.' });
        return;
      }
      const account = await fetchAccountStateForUser(user);
      sendJson(res, 200, {
        ok: true,
        user,
        account
      }, {
        'Set-Cookie': setAuthCookies(req, {
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_in: expiresIn
        })
      });
      return;
    }

    if (req.method === 'POST' && req.url === '/api/account/profile') {
      if (!isAllowedSameOriginRequest(req)) {
        sendJson(res, 403, { error: 'Cross-site account requests are not allowed.' });
        return;
      }
      const { user, setCookies } = await getAuthenticatedRequestState(req);
      if (!user) {
        sendJson(res, 401, { error: 'Sign in first.' }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }
      const body = await readJsonBody(req);
      const displayName = String(body.displayName || '').trim().slice(0, 80);
      await upsertAccountProfile(user, displayName);
      const account = await fetchAccountStateForUser({
        ...user,
        displayName
      });
      sendJson(res, 200, { ok: true, account }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
      return;
    }

    if (req.method === 'POST' && req.url === '/api/account/api-key') {
      if (!isAllowedSameOriginRequest(req)) {
        sendJson(res, 403, { error: 'Cross-site account requests are not allowed.' });
        return;
      }
      const { user, setCookies } = await getAuthenticatedRequestState(req);
      if (!user) {
        sendJson(res, 401, { error: 'Sign in first.' }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }
      const body = await readJsonBody(req);
      const apiKey = String(body.apiKey || '').trim();
      const label = String(body.label || '').trim();
      await replaceStoredOpenAIKey(user, apiKey, label);
      const account = await fetchAccountStateForUser(user);
      sendJson(res, 200, { ok: true, account }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
      return;
    }

    if (req.method === 'POST' && req.url === '/api/account/api-key/delete') {
      if (!isAllowedSameOriginRequest(req)) {
        sendJson(res, 403, { error: 'Cross-site account requests are not allowed.' });
        return;
      }
      const { user, setCookies } = await getAuthenticatedRequestState(req);
      if (!user) {
        sendJson(res, 401, { error: 'Sign in first.' }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }
      await deleteStoredOpenAIKey(user.id);
      const account = await fetchAccountStateForUser(user);
      sendJson(res, 200, { ok: true, account }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
      return;
    }

    if (req.method === 'POST' && req.url === '/api/runs/start') {
      if (!isAllowedSameOriginRequest(req)) {
        sendJson(res, 403, { error: 'Cross-site run requests are not allowed.' });
        return;
      }
      const { user, setCookies } = await getAuthenticatedRequestState(req);
      if (!user) {
        sendJson(res, 401, { error: 'Sign in first.' }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }
      const body = await readJsonBody(req);
      const mode = String(body.mode || '').trim();
      const scenarioId = String(body.scenarioId || '').trim();
      const scenarioName = String(body.scenarioName || '').trim();
      if (!['practice_text', 'practice_voice', 'live'].includes(mode)) {
        sendJson(res, 400, { error: 'Choose a valid session mode.' }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }
      const account = await resolveAccountForUser(user);
      const access = account.access || buildAccessState({ planCode: 'free' }, { savedKey: false, sessionsUsedThisMonth: 0 });
      if (!canAccessScenario(access, scenarioId)) {
        sendJson(res, 403, {
          error: `${getScenarioGatePlanLabel(scenarioId)} plan required for that scenario.`
        }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }
      if (access.requiresSavedKey) {
        sendJson(res, 403, {
          error: 'Save your OpenAI key on this account before starting sessions.'
        }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }
      if (!access.canStartSession) {
        sendJson(res, 403, {
          error: `Free includes ${access.sessionLimit} sessions per month. Upgrade to Pro for unlimited sessions.`
        }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }
      const run = await createNegotiationRun(user.id, {
        mode,
        scenarioName: scenarioName || scenarioId || 'Session',
        status: 'in_progress',
        metadata: {
          scenarioId,
          planCode: access.planCode,
          planLabel: access.planLabel
        }
      });
      const refreshedAccount = await fetchAccountStateForUser(user);
      sendJson(res, 200, {
        ok: true,
        runId: run?.id || '',
        account: refreshedAccount
      }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
      return;
    }

    if (req.method === 'POST' && req.url === '/api/runs/complete') {
      if (!isAllowedSameOriginRequest(req)) {
        sendJson(res, 403, { error: 'Cross-site run requests are not allowed.' });
        return;
      }
      const { user, setCookies } = await getAuthenticatedRequestState(req);
      if (!user) {
        sendJson(res, 401, { error: 'Sign in first.' }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }
      const body = await readJsonBody(req);
      const runId = String(body.runId || '').trim();
      if (!runId) {
        sendJson(res, 400, { error: 'Missing run id.' }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }
      const run = await fetchNegotiationRunById(user.id, runId);
      if (!run) {
        sendJson(res, 404, { error: 'Session run not found.' }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }
      const account = await resolveAccountForUser(user);
      const review = body.review && typeof body.review === 'object' ? body.review : null;
      const metadata = {
        ...(run.metadata && typeof run.metadata === 'object' ? run.metadata : {}),
        ...(review?.summary ? { reviewSummary: String(review.summary).trim().slice(0, 300) } : {}),
        ...(review?.outcome ? { outcome: String(review.outcome).trim().slice(0, 40) } : {})
      };
      await updateNegotiationRun(user.id, runId, {
        status: 'completed',
        ended_at: new Date().toISOString(),
        metadata
      });
      if (review && account.access?.features?.debriefs) {
        await upsertAnalysisReport(user.id, runId, {
          score: String(review.score || '').trim(),
          verdict: String(review.verdict || '').trim(),
          summary: String(review.summary || '').trim(),
          payload: {
            strengths: Array.isArray(review.strengths) ? review.strengths : [],
            misses: Array.isArray(review.misses) ? review.misses : [],
            reps: Array.isArray(review.reps) ? review.reps : [],
            outcome: String(review.outcome || '').trim()
          }
        });
      }
      const refreshedAccount = await fetchAccountStateForUser(user);
      sendJson(res, 200, {
        ok: true,
        account: refreshedAccount
      }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
      return;
    }

    if (req.method === 'POST' && req.url === '/api/billing/checkout') {
      if (!isAllowedSameOriginRequest(req)) {
        sendJson(res, 403, { error: 'Cross-site billing requests are not allowed.' });
        return;
      }
      if (!hasStripeBilling()) {
        sendJson(res, 503, { error: 'Stripe billing is not configured.' });
        return;
      }
      const { user, setCookies } = await getAuthenticatedRequestState(req);
      if (!user) {
        sendJson(res, 401, { error: 'Sign in first.' }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }
      const body = await readJsonBody(req);
      const plan = getStripePlanConfig(body.plan);
      if (!plan || !plan.priceId) {
        sendJson(res, 400, { error: 'Choose a valid plan.' }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }

      const billingAccount = await fetchBillingAccountForUser(user.id);
      if (
        billingAccount?.stripe_subscription_id &&
        !getManualBillingPlanCode(billingAccount.stripe_subscription_id) &&
        isPaidBillingStatus(billingAccount.plan_status) &&
        billingAccount?.stripe_customer_id
      ) {
        const origin = getExpectedOrigin(req);
        const portal = await stripeApiFetch('/billing_portal/sessions', {
          method: 'POST',
          form: buildStripeForm({
            customer: billingAccount.stripe_customer_id,
            return_url: `${origin}/#plans`
          })
        });
        sendJson(res, 200, {
          ok: true,
          mode: 'portal',
          url: portal?.url || ''
        }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }

      const customerId = await ensureStripeCustomerForUser(user, billingAccount);
      const origin = getExpectedOrigin(req);
      const session = await stripeApiFetch('/checkout/sessions', {
        method: 'POST',
        form: buildStripeForm({
          mode: 'subscription',
          customer: customerId,
          allow_promotion_codes: 'true',
          client_reference_id: user.id,
          success_url: `${origin}/#plans`,
          cancel_url: `${origin}/#plans`,
          'metadata[user_id]': user.id,
          'metadata[plan_code]': plan.code,
          'subscription_data[metadata][user_id]': user.id,
          'subscription_data[metadata][plan_code]': plan.code,
          'line_items[0][price]': plan.priceId,
          'line_items[0][quantity]': 1
        })
      });
      sendJson(res, 200, {
        ok: true,
        mode: 'checkout',
        url: session?.url || ''
      }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
      return;
    }

    if (req.method === 'POST' && req.url === '/api/billing/portal') {
      if (!isAllowedSameOriginRequest(req)) {
        sendJson(res, 403, { error: 'Cross-site billing requests are not allowed.' });
        return;
      }
      if (!hasStripeBilling()) {
        sendJson(res, 503, { error: 'Stripe billing is not configured.' });
        return;
      }
      const { user, setCookies } = await getAuthenticatedRequestState(req);
      if (!user) {
        sendJson(res, 401, { error: 'Sign in first.' }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }
      const billingAccount = await fetchBillingAccountForUser(user.id);
      if (!billingAccount?.stripe_customer_id) {
        sendJson(res, 400, { error: 'No Stripe billing profile exists on this account yet.' }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }
      const origin = getExpectedOrigin(req);
      const portal = await stripeApiFetch('/billing_portal/sessions', {
        method: 'POST',
        form: buildStripeForm({
          customer: billingAccount.stripe_customer_id,
          return_url: `${origin}/#plans`
        })
      });
      sendJson(res, 200, {
        ok: true,
        url: portal?.url || ''
      }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
      return;
    }

    if (req.method === 'POST' && req.url === '/api/openai/chat') {
      if (!isAllowedSameOriginRequest(req)) {
        sendJson(res, 403, { error: 'Cross-site chat requests are not allowed.' });
        return;
      }
      const { user, setCookies } = await getAuthenticatedRequestState(req);
      if (!user) {
        sendJson(res, 401, { error: 'Sign in first.' }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }
      const account = await resolveAccountForUser(user);
      const { apiKey, source } = await resolveApiKeyForAccount(account, user.id);
      if (!validateOpenAIKey(apiKey)) {
        const message = account.access?.features?.hostedKeyEligible
          ? 'No saved OpenAI key is available, and Gibsel hosted usage is not configured yet.'
          : 'Save your OpenAI key on this account first.';
        sendJson(res, 403, { error: message }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }
      const body = await readJsonBody(req);
      const messages = Array.isArray(body.messages) ? body.messages : [];
      const model = String(body.model || 'gpt-4.1-mini').trim();
      const maxTokens = Math.max(1, Math.min(4000, Number(body.maxTokens || 200)));
      const jsonMode = !!body.jsonMode;
      if (!messages.length) {
        sendJson(res, 400, { error: 'Missing messages.' }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }

      const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model,
          max_tokens: maxTokens,
          temperature: 0.7,
          messages,
          ...(jsonMode ? { response_format: { type: 'json_object' } } : {})
        })
      });

      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        sendJson(res, response.status, {
          error: data?.error?.message || 'OpenAI chat request failed.'
        }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }
      sendJson(res, 200, {
        content: data?.choices?.[0]?.message?.content || '',
        source
      }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
      return;
    }

    if (req.method === 'POST' && req.url === '/api/live/call') {
      if (!isAllowedLiveRequest(req)) {
        sendJson(res, 403, { error: 'Cross-site live requests are not allowed.' });
        return;
      }
      if (!consumeLiveRateLimit(req)) {
        sendJson(res, 429, { error: 'Too many live session attempts. Try again shortly.' });
        return;
      }
      const requestedRealtimeModel = typeof req.headers['x-openai-realtime-model'] === 'string'
        ? req.headers['x-openai-realtime-model'].trim()
        : '';
      const { user, setCookies } = await getAuthenticatedRequestState(req);
      if (!user) {
        sendJson(res, 401, { error: 'Sign in first.' }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }
      const account = await resolveAccountForUser(user);
      const { apiKey } = await resolveApiKeyForAccount(account, user.id);
      if (!validateOpenAIKey(apiKey)) {
        const message = account.access?.features?.hostedKeyEligible
          ? 'Live mode needs a saved OpenAI key or Gibsel hosted usage configured on the server.'
          : 'Save your OpenAI key on this account before starting live mode.';
        sendJson(res, 403, { error: message }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }

      const offerSdp = await readBody(req);
      if (!offerSdp.trim()) {
        sendJson(res, 400, { error: 'Missing SDP offer.' }, setCookies.length ? { 'Set-Cookie': setCookies } : {});
        return;
      }

      const realtimeModel = ALLOWED_REALTIME_MODELS.has(requestedRealtimeModel) ? requestedRealtimeModel : REALTIME_MODEL;
      const answerSdp = await createRealtimeCall(offerSdp, apiKey, realtimeModel);
      res.writeHead(200, buildSecurityHeaders({
        'Content-Type': 'application/sdp; charset=utf-8',
        'Cache-Control': 'no-store',
        ...(setCookies.length ? { 'Set-Cookie': setCookies } : {})
      }));
      res.end(answerSdp);
      return;
    }

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      sendJson(res, 405, { error: 'Method not allowed' });
      return;
    }

    if (req.method === 'GET' && req.url.startsWith('/auth/google/callback')) {
      res.writeHead(200, buildSecurityHeaders({
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store'
      }));
      res.end(buildGoogleOAuthCallbackPage(req));
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
