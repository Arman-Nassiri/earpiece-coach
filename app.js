// ─────────────────────────────────────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────────────────────────────────────
const SUPABASE_URL  = 'https://doesazgmozprijuwdeod.supabase.co';
const SUPABASE_ANON = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRvZXNhemdtb3pwcmlqdXdkZW9kIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI4Mzc3NDAsImV4cCI6MjA4ODQxMzc0MH0.48BUIFJ-Gj_3v4iPuacdKWHrq9grXn8tqQBtOopIMzQ';
const STRIPE_KEY    = 'pk_live_51SlkakQ7H6bsl24k19Z26WwJbSA6yeiL7FapiXQaTThkvc6FbtctK8CUnwOZVqfK9WUZioTMCaSrrRcSyR7YBQMG005Pp6noS1';
const STRIPE_PRICE  = 'price_1T88nWQ7H6bsl24kcGcZsQfU';
// When hosted: replace with 'https://cue.gibsel.com'
const APP_URL       = window.location.origin || 'https://cue.gibsel.com';

// ─────────────────────────────────────────────────────────────────────────────
// SUPABASE CLIENT
// ─────────────────────────────────────────────────────────────────────────────
const { createClient } = supabase;
const sb = createClient(SUPABASE_URL, SUPABASE_ANON);

// ─────────────────────────────────────────────────────────────────────────────
// AUTH STATE
// ─────────────────────────────────────────────────────────────────────────────
let currentUser    = null;
let currentProfile = null;
let authMode       = 'signup'; // 'signup' | 'login'

async function loadProfile(userId) {
  try {
    const { data } = await sb.from('profiles').select('*').eq('id', userId).single();
    currentProfile = data;
  } catch(e) { currentProfile = null; }
}

// On load: check if user is already logged in (Supabase persists session)
(async function checkSession() {
  const { data: { session } } = await sb.auth.getSession();
  if (session?.user) {
    currentUser = session.user;
    await loadProfile(session.user.id);
    go('s-home');
  }
  // Also handle Stripe redirect back
  handleCheckoutReturn();
})();

// Listen for auth state changes (e.g. email confirmation)
sb.auth.onAuthStateChange(async (event, session) => {
  if (event === 'SIGNED_IN' && session?.user) {
    currentUser = session.user;
    await loadProfile(session.user.id);
  }
  if (event === 'SIGNED_OUT') {
    currentUser = null;
    currentProfile = null;
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// AUTH SCREEN LOGIC
// ─────────────────────────────────────────────────────────────────────────────
function showLogin() {
  authMode = 'login';
  renderAuthMode();
  go('s-auth');
}

function toggleAuthMode() {
  authMode = authMode === 'signup' ? 'login' : 'signup';
  renderAuthMode();
}

function renderAuthMode() {
  const isLogin = authMode === 'login';
  document.getElementById('authTitle').textContent    = isLogin ? 'Welcome back'    : 'Create account';
  document.getElementById('authSub').textContent      = isLogin ? 'Log in to your account.' : 'Sign up free. No credit card required.';
  document.getElementById('authBtn').textContent      = isLogin ? 'Log in'          : 'Create account';
  document.getElementById('authNameWrap').style.display  = isLogin ? 'none' : 'block';
  document.getElementById('authForgotRow').style.display = isLogin ? 'block' : 'none';
  document.getElementById('authToggleText').textContent  = isLogin ? "Don't have an account?" : 'Already have an account?';
  document.getElementById('authToggleLink').textContent  = isLogin ? 'Sign up'       : 'Log in';
  setAuthStatus('', '');
}

function setAuthStatus(msg, type) {
  const el = document.getElementById('authStatus');
  el.textContent = msg;
  el.className = 'auth-status' + (type ? ' ' + type : '');
}

async function handleAuth() {
  const email    = (document.getElementById('authEmail').value    || '').trim();
  const password = (document.getElementById('authPassword').value || '').trim();
  const btn      = document.getElementById('authBtn');

  if (!email || !password) { setAuthStatus('Enter your email and password.', 'fail'); return; }
  if (password.length < 8) { setAuthStatus('Password must be at least 8 characters.', 'fail'); return; }

  btn.disabled = true;
  btn.textContent = authMode === 'signup' ? 'Creating account…' : 'Logging in…';
  setAuthStatus('', '');

  try {
    if (authMode === 'signup') {
      const { error } = await sb.auth.signUp({ email, password });
      if (error) throw error;
      setAuthStatus('Check your email to confirm your account, then come back to log in.', 'ok');
      // Switch to login mode after signup
      setTimeout(() => { authMode = 'login'; renderAuthMode(); }, 2800);
    } else {
      const { data, error } = await sb.auth.signInWithPassword({ email, password });
      if (error) throw error;
      currentUser = data.user;
      await loadProfile(data.user.id);
      setAuthStatus('', '');
      go('s-home');
    }
  } catch(err) {
    let msg = err.message || 'Something went wrong.';
    if (msg.includes('Invalid login')) msg = 'Incorrect email or password.';
    if (msg.includes('already registered')) msg = 'This email is already registered. Try logging in.';
    if (msg.includes('Email not confirmed')) msg = 'Please confirm your email first.';
    setAuthStatus(msg, 'fail');
  } finally {
    btn.disabled = false;
    btn.textContent = authMode === 'signup' ? 'Create account' : 'Log in';
  }
}

async function handleForgotPassword() {
  const email = (document.getElementById('authEmail').value || '').trim();
  if (!email) { setAuthStatus('Enter your email above first.', 'fail'); return; }
  setAuthStatus('Sending reset link…', 'info');
  const { error } = await sb.auth.resetPasswordForEmail(email, {
    redirectTo: APP_URL + '/?reset=true'
  });
  if (error) { setAuthStatus(error.message, 'fail'); return; }
  setAuthStatus('Reset link sent — check your email.', 'ok');
}

async function handleSignOut() {
  await sb.auth.signOut();
  currentUser = null; currentProfile = null;
  SecureStore.clear();
  go('s-launch');
  toast('Signed out');
}

// ─────────────────────────────────────────────────────────────────────────────
// STRIPE CHECKOUT
// ─────────────────────────────────────────────────────────────────────────────
const stripe = Stripe(STRIPE_KEY);

async function startProCheckout() {
  if (!currentUser) {
    // Must be logged in to subscribe
    toast('Create a free account first');
    setTimeout(() => { authMode = 'signup'; renderAuthMode(); go('s-auth'); }, 600);
    return;
  }

  const btn = document.getElementById('proCheckoutBtn');
  btn.disabled = true;
  btn.textContent = 'Opening checkout…';

  try {
    const { error } = await stripe.redirectToCheckout({
      lineItems: [{ price: STRIPE_PRICE, quantity: 1 }],
      mode: 'subscription',
      successUrl: APP_URL + '/?checkout=success&session_id={CHECKOUT_SESSION_ID}',
      cancelUrl:  APP_URL + '/?checkout=cancelled',
      customerEmail: currentUser.email,
      clientReferenceId: currentUser.id
    });
    if (error) throw error;
  } catch(err) {
    toast('Checkout error — try again');
    btn.disabled = false;
    btn.textContent = 'Get Pro — $19/mo';
  }
}

function handleCheckoutReturn() {
  const params = new URLSearchParams(window.location.search);
  const status = params.get('checkout');
  if (!status) return;

  // Clean URL
  window.history.replaceState({}, '', window.location.pathname);

  if (status === 'success') {
    // Payment went through — show home, profile will update via webhook
    setTimeout(() => {
      showModal({
        title: 'Welcome to Pro 🎉',
        body: 'Your subscription is active. Your account will reflect Pro status within a minute.',
        confirmText: 'Let\'s go'
      });
    }, 800);
  } else if (status === 'cancelled') {
    setTimeout(() => toast('Checkout cancelled'), 400);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ACCOUNT SCREEN
// ─────────────────────────────────────────────────────────────────────────────
function goAccount() {
  if (!currentUser) {
    // BYOK user — take them to sign up
    authMode = 'signup'; renderAuthMode(); go('s-auth');
    return;
  }
  renderAccountScreen();
  go('s-account');
}

function renderAccountScreen() {
  if (!currentUser) return;

  document.getElementById('acctEmail').textContent = currentUser.email || '—';
  const since = currentUser.created_at
    ? 'Member since ' + new Date(currentUser.created_at).toLocaleDateString('en-US', { month: 'long', year: 'numeric' })
    : '';
  document.getElementById('acctSince').textContent = since;

  const plan    = currentProfile?.plan || 'free';
  const isPro   = plan === 'pro';
  const nameEl  = document.getElementById('acctPlanName');
  const descEl  = document.getElementById('acctPlanDesc');
  const badgeEl = document.getElementById('acctPlanBadge');
  const actEl   = document.getElementById('acctPlanActions');

  nameEl.textContent = isPro ? 'Pro' : 'Free';
  descEl.textContent = isPro
    ? (currentProfile?.valid_until ? 'Renews ' + new Date(currentProfile.valid_until).toLocaleDateString() : 'Active')
    : 'Using your own API key';
  badgeEl.innerHTML  = isPro ? '<span class="pro-badge">Pro</span>' : '';

  actEl.innerHTML = isPro
    ? `<button class="btn-ghost" onclick="openBillingPortal()">Manage billing &amp; cancel</button>`
    : `<button class="btn" onclick="go('s-pricing')">Upgrade to Pro — $19/mo</button>`;

  // Theme label
  document.getElementById('acctThemeLabel').textContent = darkMode ? 'Dark mode' : 'Light mode';
}

function openBillingPortal() {
  // Once your backend is live, this should call /api/billing-portal
  // For now, open Stripe customer portal directly
  window.open('https://billing.stripe.com/p/login/test_placeholder', '_blank');
  toast('Opening billing portal…');
}

// ─────────────────────────────────────────────────────────────────────────────
// SECURITY: key lives only in a closure, never on window
// ─────────────────────────────────────────────────────────────────────────────
const SecureStore = (() => {
  let _mask = null, _masked = null;
  function _encode(str) {
    const enc = new TextEncoder().encode(str);
    const out = new Uint8Array(enc.length);
    for (let i = 0; i < enc.length; i++) out[i] = enc[i] ^ _mask[i % _mask.length];
    return out;
  }
  function _decode(arr) {
    const out = new Uint8Array(arr.length);
    for (let i = 0; i < arr.length; i++) out[i] = arr[i] ^ _mask[i % _mask.length];
    return new TextDecoder().decode(out);
  }
  return {
    set(key)  { _mask = crypto.getRandomValues(new Uint8Array(32)); _masked = _encode(key); },
    get()     { if (!_masked) return ''; return _decode(_masked); },
    clear()   { _masked = null; _mask = null; },
    has()     { return !!_masked; }
  };
})();

// ─────────────────────────────────────────────────────────────────────────────
// RATE LIMITING
// ─────────────────────────────────────────────────────────────────────────────
const RateLimit = (() => {
  const calls = []; let sessionCount = 0;
  const MAX_PER_MINUTE = 20, MAX_PER_SESSION = 120;
  return {
    check() {
      const now = Date.now();
      while (calls.length && calls[0] < now - 60000) calls.shift();
      if (calls.length >= MAX_PER_MINUTE) return { ok: false, reason: 'Too many requests — slow down.' };
      if (sessionCount >= MAX_PER_SESSION) return { ok: false, reason: 'Session limit reached. Reload to continue.' };
      return { ok: true };
    },
    record() { calls.push(Date.now()); sessionCount++; }
  };
})();

// ─────────────────────────────────────────────────────────────────────────────
// PROVIDERS
// ─────────────────────────────────────────────────────────────────────────────
const PROVIDERS = {
  openai: {
    name: 'OpenAI', placeholder: 'sk-proj-... or sk-...',
    note: 'Key sent directly to api.openai.com — never stored or logged.',
    endpoint: () => 'https://api.openai.com/v1/chat/completions',
    authHeader: key => ({ 'Authorization': 'Bearer ' + key }),
    buildBody: (maxTokens, jsonMode, systemContent, userMessages) => ({
      model: 'gpt-4.1-mini', max_tokens: maxTokens, temperature: 0.7,
      messages: [...(systemContent ? [{role:'system',content:systemContent}] : []), ...userMessages],
      ...(jsonMode ? { response_format: { type: 'json_object' } } : {})
    }),
    extractContent: data => data?.choices?.[0]?.message?.content,
    validateKey: key => key.startsWith('sk-') && key.length >= 20
  },
  anthropic: {
    name: 'Anthropic', placeholder: 'sk-ant-api03-...',
    note: 'Key sent directly to api.anthropic.com — never stored or logged.',
    endpoint: () => 'https://api.anthropic.com/v1/messages',
    authHeader: key => ({
      'x-api-key': key,
      'anthropic-version': '2023-06-01',
      'anthropic-dangerous-direct-browser-access': 'true'
    }),
    buildBody: (maxTokens, jsonMode, systemContent, userMessages) => ({
      model: 'claude-haiku-4-5-20251001', max_tokens: maxTokens,
      ...(systemContent ? { system: systemContent } : {}),
      messages: userMessages
    }),
    extractContent: data => data?.content?.[0]?.text,
    validateKey: key => key.startsWith('sk-ant-')
  },
  google: {
    name: 'Google', placeholder: 'AIzaSy...',
    note: 'Key sent directly to generativelanguage.googleapis.com.',
    endpoint: key => `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${key}`,
    authHeader: () => ({}),
    buildBody: (maxTokens, jsonMode, systemContent, userMessages) => ({
      ...(systemContent ? { system_instruction: { parts: [{ text: systemContent }] } } : {}),
      contents: userMessages.map(m => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }] })),
      generationConfig: { maxOutputTokens: maxTokens, temperature: 0.7, ...(jsonMode ? { responseMimeType: 'application/json' } : {}) }
    }),
    extractContent: data => data?.candidates?.[0]?.content?.parts?.[0]?.text,
    validateKey: key => key.startsWith('AIza')
  },
  azure: {
    name: 'Azure OpenAI', placeholder: '',
    note: 'Endpoint and key sent directly to your Azure resource.',
    endpoint: key => key.split('|||')[0],
    authHeader: key => ({ 'api-key': key.split('|||')[1] }),
    buildBody: (maxTokens, jsonMode, systemContent, userMessages) => ({
      max_tokens: maxTokens, temperature: 0.7,
      messages: [...(systemContent ? [{role:'system',content:systemContent}] : []), ...userMessages],
      ...(jsonMode ? { response_format: { type: 'json_object' } } : {})
    }),
    extractContent: data => data?.choices?.[0]?.message?.content,
    validateKey: key => key.includes('openai.azure.com') && key.split('|||')[1]?.length >= 10
  },
  meta: {
    name: 'Meta', placeholder: 'Your Llama API key',
    note: 'Key sent directly to api.llama.com — never stored or logged.',
    endpoint: () => 'https://api.llama.com/v1/chat/completions',
    authHeader: key => ({ 'Authorization': 'Bearer ' + key }),
    buildBody: (maxTokens, jsonMode, systemContent, userMessages) => ({
      model: 'Llama-4-Scout-17B-16E-Instruct', max_tokens: maxTokens,
      messages: [...(systemContent ? [{role:'system',content:systemContent}] : []), ...userMessages]
    }),
    extractContent: data =>
      data?.choices?.[0]?.message?.content ??
      data?.completion_message?.content?.text ?? null,
    validateKey: key => key.length >= 20
  }
};

let currentProvider = 'openai';

// ─────────────────────────────────────────────────────────────────────────────
// SANITIZE
// ─────────────────────────────────────────────────────────────────────────────
function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>]/g,'').replace(/javascript:/gi,'').replace(/on\w+=/gi,'').trim().slice(0,500);
}

// ─────────────────────────────────────────────────────────────────────────────
// SECURE API CALL — routes to server for Pro, direct for BYOK
// ─────────────────────────────────────────────────────────────────────────────
const isPro = () => currentProfile?.plan === 'pro' && currentProfile?.subscription_status === 'active';

async function secureAPICall(messages, maxTokens = 200, jsonMode = false) {
  const rl = RateLimit.check();
  if (!rl.ok) throw new Error(rl.reason);

  // Pro users: route through server
  if (isPro() && currentUser) {
    const { data: { session } } = await sb.auth.getSession();
    const jwt = session?.access_token;
    if (!jwt) throw new Error('Session expired — please log in again.');

    RateLimit.record();
    let res;
    try {
      res = await fetch(APP_URL + '/api/coach', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + jwt },
        body: JSON.stringify({ messages, maxTokens, jsonMode })
      });
    } catch(e) { throw new Error('Network error — check your connection.'); }

    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      throw new Error(d?.error || 'Server error ' + res.status);
    }
    const d = await res.json();
    return d.content;
  }

  // BYOK: direct call
  const key = SecureStore.get();
  if (!key) throw new Error('No API key — reload and enter your key.');

  const p = PROVIDERS[currentProvider];
  if (!p) throw new Error('Unknown provider.');

  let systemContent = null, userMessages = messages;
  if (messages.length && messages[0].role === 'system') {
    systemContent = messages[0].content;
    userMessages = messages.slice(1);
  }

  const endpoint = typeof p.endpoint === 'function' ? p.endpoint(key) : p.endpoint;
  const body = p.buildBody(maxTokens, jsonMode, systemContent, userMessages);
  const authHeaders = p.authHeader(key);

  RateLimit.record();
  let res;
  try {
    res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders },
      body: JSON.stringify(body)
    });
  } catch(e) { throw new Error('Network error — check your connection.'); }

  if (!res.ok) {
    let errMsg = `API error ${res.status}`;
    try { const d = await res.json(); errMsg = d?.error?.message || d?.error?.status || errMsg; } catch(_) {}
    if (res.status === 401 || res.status === 403) { SecureStore.clear(); throw new Error('Invalid API key — reload and try again.'); }
    if (res.status === 429) throw new Error('Rate limited — wait a moment.');
    throw new Error(errMsg);
  }

  const data = await res.json();
  const content = p.extractContent(data);
  if (!content) throw new Error('Empty response from API.');
  return content;
}

// ─────────────────────────────────────────────────────────────────────────────
// KEY VERIFICATION
// ─────────────────────────────────────────────────────────────────────────────
async function verifyKey(key, provider) {
  const p = PROVIDERS[provider];
  if (!p.validateKey(key)) throw new Error('Key format looks wrong for ' + p.name + '.');
  const testMessages = [{ role: 'user', content: 'Reply with the single word: ready' }];
  const endpoint = typeof p.endpoint === 'function' ? p.endpoint(key) : p.endpoint;
  const body = p.buildBody(10, false, null, testMessages);
  const authHeaders = p.authHeader(key);
  let res;
  try {
    res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders },
      body: JSON.stringify(body)
    });
  } catch(netErr) {
    throw new Error('Could not reach ' + p.name + '. Try opening this file in your browser.');
  }
  if (!res.ok) {
    let errMsg = 'Error ' + res.status;
    try { const d = await res.json(); errMsg = d?.error?.message || d?.error?.status || errMsg; } catch(_) {}
    if (res.status === 401 || res.status === 403) throw new Error('Key rejected by ' + p.name + ' — double-check it.');
    if (res.status === 429) throw new Error('Rate limited — wait a moment.');
    throw new Error(errMsg);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SCENARIO LIBRARY
// ─────────────────────────────────────────────────────────────────────────────
const LIBRARY = [
  { id:'salary',    icon:'💼', iconSel:'💼', name:'Salary',           sub:'Job offer, raise, or promotion',
    anchors:[{l:'High',v:'$148,000'},{l:'Mid',v:'$142,000'},{l:'Floor',v:'$135,000'}],
    batna:'Competing offer at $128,000 from another company', zopa:'Their likely range: $130,000 – $150,000' },
  { id:'rent',      icon:'🏠', iconSel:'🏠', name:'Rent',              sub:'Apartment or lease negotiation',
    anchors:[{l:'High',v:'$2,100/mo'},{l:'Mid',v:'$2,200/mo'},{l:'Floor',v:'$2,350/mo'}],
    batna:'Comparable unit nearby listed at $2,150/mo', zopa:'Landlord likely flexible between $2,200 – $2,400' },
  { id:'car',       icon:'🚗', iconSel:'🚗', name:'Car Dealer',        sub:'New or used vehicle price',
    anchors:[{l:'High',v:'$31,500 OTD'},{l:'Mid',v:'$33,000 OTD'},{l:'Floor',v:'$34,500 OTD'}],
    batna:'Same trim at competing dealer: $33,200 out the door', zopa:'Dealer invoice ~$30,800 — meaningful room exists' },
  { id:'freelance', icon:'💻', iconSel:'💻', name:'Freelance Rate',    sub:'Hourly or project rate with a client',
    anchors:[{l:'High',v:'$150/hr'},{l:'Mid',v:'$130/hr'},{l:'Floor',v:'$110/hr'}],
    batna:'Another client offering $105/hr for similar work', zopa:'Client likely has budget for $120–$145/hr' },
  { id:'joboffer',  icon:'📋', iconSel:'📋', name:'Job Offer Counter', sub:'Push back on an existing offer',
    anchors:[{l:'High',v:'$155,000'},{l:'Mid',v:'$148,000'},{l:'Floor',v:'$140,000'}],
    batna:'Current offer on the table: $132,000', zopa:'Recruiter hinted budget can stretch to $145–$150K' },
  { id:'biz',       icon:'🤝', iconSel:'🤝', name:'Business Deal',     sub:'Partnership, contract, or vendor',
    anchors:[{l:'High',v:'$50,000'},{l:'Mid',v:'$42,000'},{l:'Floor',v:'$35,000'}],
    batna:'Alternative vendor quoted $34,000 for same scope', zopa:"Other party's budget appears to be $38,000–$48,000" },
  { id:'severance', icon:'📄', iconSel:'📄', name:'Severance',         sub:'Negotiate exit terms with employer',
    anchors:[{l:'High',v:'6 months pay'},{l:'Mid',v:'4 months pay'},{l:'Floor',v:'2 months pay'}],
    batna:'Standard policy offers 2 weeks per year of service', zopa:'Company has offered 6–8 weeks in similar departures' },
  { id:'medical',   icon:'🏥', iconSel:'🏥', name:'Medical Bill',      sub:'Negotiate a hospital or provider bill',
    anchors:[{l:'High',v:'50% reduction'},{l:'Mid',v:'35% reduction'},{l:'Floor',v:'20% reduction'}],
    batna:"Can set up a 12-month payment plan if they won't reduce", zopa:'Hospitals routinely settle for 40–60% of billed amount' },
  { id:'custom',    icon:'＋', iconSel:'✕', name:'Custom',            sub:'Any negotiation, your terms',
    anchors:[{l:'High',v:''},{l:'Mid',v:''},{l:'Floor',v:''}], batna:'', zopa:'' }
];

// ─────────────────────────────────────────────────────────────────────────────
// APP STATE
// ─────────────────────────────────────────────────────────────────────────────
let currentSC = null;
let rec = null, audioCtx = null, analyser = null, animId = null;
let silenceTimer = null, finalBuf = '', sessionHistory = [];
let processing = false, earOn = true, darkMode = false;
let generatedOpener = '', micActive = false;

// ─────────────────────────────────────────────────────────────────────────────
// INIT
// ─────────────────────────────────────────────────────────────────────────────
(function init() {
  const saved = localStorage.getItem('gc-theme');
  if (saved === 'dark') applyTheme(true, false);

  const list = document.getElementById('cardList');
  LIBRARY.forEach(sc => {
    const div = document.createElement('div');
    div.className = 'scenario-card';
    div.innerHTML = `
      <div class="sc-icon">
        <span class="sc-icon-text">${sc.icon}</span>
        <span class="sc-icon-sel">${sc.iconSel}</span>
      </div>
      <div class="sc-text">
        <div class="sc-name">${sc.name}</div>
        <div class="sc-sub">${sc.sub}</div>
      </div>
      <div class="sc-arr">›</div>`;
    div.addEventListener('click', () => pickSC(div, sc));
    list.appendChild(div);
  });
})();

// ─────────────────────────────────────────────────────────────────────────────
// THEME
// ─────────────────────────────────────────────────────────────────────────────
function applyTheme(dark, save = true) {
  darkMode = dark;
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
  const btn = document.getElementById('themeBtn');
  if (btn) btn.textContent = dark ? '🌙' : '☀️';
  if (save) localStorage.setItem('gc-theme', dark ? 'dark' : 'light');
}
function toggleTheme() {
  applyTheme(!darkMode);
  // Refresh account screen label if open
  const lbl = document.getElementById('acctThemeLabel');
  if (lbl) lbl.textContent = darkMode ? 'Dark mode' : 'Light mode';
}

// ─────────────────────────────────────────────────────────────────────────────
// INLINE CONFIRM
// ─────────────────────────────────────────────────────────────────────────────
function inlineConfirm(btn, onConfirm, opts = {}) {
  if (!btn || btn.dataset.confirming) return;
  btn.dataset.confirming = '1';
  const origHTML = btn.innerHTML, origClass = btn.className;
  const origStyle = btn.getAttribute('style') || '', origOnClick = btn.getAttribute('onclick');

  const yes = document.createElement('button');
  yes.className = 'ic-yes' + (opts.yesClass === 'danger' ? ' danger' : '');
  yes.textContent = opts.yesLabel || 'Yes'; yes.type = 'button';

  const no = document.createElement('button');
  no.className = 'ic-no'; no.textContent = 'Cancel'; no.type = 'button';

  btn.innerHTML = '';
  btn.classList.add('ic-host');
  btn.removeAttribute('onclick');
  btn.style.cssText = origStyle + '; padding:4px 6px; background:var(--bg2); border:1.5px solid var(--border); cursor:default; display:inline-flex; align-items:center; gap:5px;';
  btn.appendChild(yes); btn.appendChild(no);

  function restore() {
    btn.innerHTML = origHTML; btn.className = origClass;
    btn.classList.remove('ic-host'); btn.setAttribute('style', origStyle);
    if (origOnClick) btn.setAttribute('onclick', origOnClick); else btn.removeAttribute('onclick');
    delete btn.dataset.confirming;
  }

  yes.addEventListener('click', e => { e.preventDefault(); e.stopPropagation(); restore(); onConfirm(); });
  no.addEventListener('click',  e => { e.preventDefault(); e.stopPropagation(); restore(); });
  [yes, no].forEach(b => { b.style.animation = 'icIn 0.18s var(--ease) forwards'; });
  setTimeout(() => { if (btn.dataset.confirming) restore(); }, 5000);
}

// ─────────────────────────────────────────────────────────────────────────────
// MODAL
// ─────────────────────────────────────────────────────────────────────────────
let _modalResolve = null;
function showModal({ title, body, confirmText = 'Confirm', danger = false }) {
  return new Promise(resolve => {
    _modalResolve = resolve;
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalBody').innerHTML = body;
    const btn = document.getElementById('modalConfirm');
    btn.textContent = confirmText;
    btn.className = 'btn-confirm' + (danger ? ' btn-danger' : '');
    btn.onclick = () => { closeModal(); resolve(true); };
    document.getElementById('modalOverlay').classList.add('show');
  });
}
function closeModal() {
  document.getElementById('modalOverlay').classList.remove('show');
  if (_modalResolve) { _modalResolve(false); _modalResolve = null; }
}
document.getElementById('modalOverlay').addEventListener('click', e => {
  if (e.target === document.getElementById('modalOverlay')) closeModal();
});

// ─────────────────────────────────────────────────────────────────────────────
// NAVIGATION
// ─────────────────────────────────────────────────────────────────────────────
function go(id) {
  const cur = document.querySelector('.screen.active');
  if (cur) {
    cur.classList.add('leaving'); cur.classList.remove('active');
    setTimeout(() => cur.classList.remove('leaving'), 280);
  }
  setTimeout(() => document.getElementById(id).classList.add('active'), 55);
}

// ─────────────────────────────────────────────────────────────────────────────
// PROVIDER TABS
// ─────────────────────────────────────────────────────────────────────────────
(function initProviderTabs() {
  document.querySelectorAll('.ptab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.ptab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      currentProvider = tab.dataset.provider;
      const p = PROVIDERS[currentProvider];
      const isAzure = currentProvider === 'azure';
      document.getElementById('keyFieldSingle').style.display = isAzure ? 'none' : 'block';
      document.getElementById('keyFieldAzure').style.display  = isAzure ? 'block' : 'none';
      if (!isAzure) {
        document.getElementById('apiKeyInput').placeholder = p.placeholder;
        document.getElementById('apiKeyInput').value = '';
      } else {
        document.getElementById('azureEndpoint').value = '';
        document.getElementById('azureKey').value = '';
      }
      document.getElementById('keyNote').textContent = p.note;
      document.getElementById('keyVerifyStatus').textContent = '';
      document.getElementById('keyVerifyStatus').className = 'key-verify-status';
    });
  });
})();

function getRawKey() {
  if (currentProvider === 'azure') {
    const ep  = (document.getElementById('azureEndpoint').value || '').trim();
    const key = (document.getElementById('azureKey').value || '').trim();
    return ep && key ? ep + '|||' + key : '';
  }
  return (document.getElementById('apiKeyInput').value || '').trim();
}

async function submitKey() {
  const raw = getRawKey();
  const status = document.getElementById('keyVerifyStatus');
  const btn = document.getElementById('continueBtn');
  if (!raw) {
    status.textContent = currentProvider === 'azure' ? 'Enter both endpoint URL and API key.' : 'Paste your API key above.';
    status.className = 'key-verify-status fail'; return;
  }
  const p = PROVIDERS[currentProvider];
  if (!p.validateKey(raw)) {
    status.textContent = "That doesn't look like a valid " + p.name + ' key.';
    status.className = 'key-verify-status fail'; return;
  }
  btn.disabled = true; btn.textContent = 'Verifying…';
  status.textContent = 'Testing with a live call…'; status.className = 'key-verify-status spin';
  try {
    await verifyKey(raw, currentProvider);
    status.textContent = '✓ Verified — loading…'; status.className = 'key-verify-status ok';
    SecureStore.set(raw);
    if (currentProvider === 'azure') {
      document.getElementById('azureEndpoint').value = '';
      document.getElementById('azureKey').value = '';
    } else {
      document.getElementById('apiKeyInput').value = '';
    }
    setTimeout(() => go('s-home'), 600);
  } catch(err) {
    status.textContent = err.message; status.className = 'key-verify-status fail';
    btn.disabled = false; btn.textContent = 'Verify & Continue';
  }
}

document.getElementById('apiKeyInput').addEventListener('keydown', e => { if (e.key === 'Enter') submitKey(); });
document.getElementById('azureEndpoint').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('azureKey').focus(); });
document.getElementById('azureKey').addEventListener('keydown', e => { if (e.key === 'Enter') submitKey(); });
document.getElementById('authPassword').addEventListener('keydown', e => { if (e.key === 'Enter') handleAuth(); });
document.getElementById('authEmail').addEventListener('keydown', e => { if (e.key === 'Enter') { if (authMode==='login') handleAuth(); else document.getElementById('authPassword').focus(); } });

// ─────────────────────────────────────────────────────────────────────────────
// HOME
// ─────────────────────────────────────────────────────────────────────────────
function pickSC(card, sc) {
  document.querySelectorAll('.scenario-card').forEach(c => c.classList.remove('selected'));
  card.classList.add('selected'); currentSC = sc;
}

function goPrep() {
  if (!currentSC) { toast('Choose a scenario first'); return; }
  generatedOpener = ''; buildPrep(); go('s-prep');
}

// ─────────────────────────────────────────────────────────────────────────────
// PREP SCREEN
// ─────────────────────────────────────────────────────────────────────────────
function buildPrep() {
  const sc = currentSC;
  document.getElementById('prepTitle').textContent = sc.name;
  const wrap = document.getElementById('prepScroll');

  const customRow = sc.id === 'custom' ? `
    <div class="info-card">
      <div class="info-card-label">What are you negotiating?</div>
      <input class="field-input" id="custom-name" placeholder="e.g. Contractor rate with new client" style="margin-top:0" autocomplete="off"/>
    </div>` : '';

  const anchorRows = sc.anchors.map((a, i) => `
    <div class="anchor-row">
      <div class="anchor-badge ${i===0?'hi':''}">${a.l}</div>
      <input class="anchor-input ${i===0?'hi':''}" id="anc-${i}" value="${a.v}" placeholder="e.g. $150,000"/>
    </div>`).join('');

  wrap.innerHTML = customRow + `
    <div class="info-card">
      <div class="info-card-label">Anchors</div>
      ${anchorRows}
      <div class="info-hint">High anchor goes first — always. State it, then go quiet.</div>
    </div>
    <div class="info-card">
      <div class="info-card-label">BATNA — Your best alternative</div>
      <div class="editable-wrap">
        <textarea class="textarea-field" id="batna-field" rows="2" placeholder="What's your best alternative if this deal falls apart?">${sc.batna}</textarea>
      </div>
      <div class="info-hint">Never negotiate without knowing your walkaway.</div>
    </div>
    <div class="info-card">
      <div class="info-card-label">ZOPA — Zone of possible agreement</div>
      <div class="editable-wrap">
        <textarea class="textarea-field" id="zopa-field" rows="2" placeholder="Estimate their likely range and flexibility.">${sc.zopa}</textarea>
      </div>
    </div>
    <div class="info-card" id="openerCard">
      <div class="info-card-label">Opening line</div>
      <div class="opener-card" id="openerBox">
        <div class="opener-empty">Generate your opening line when ready.</div>
      </div>
      <div class="opener-actions">
        <button class="opener-gen-btn" id="openerGenBtn" onclick="generateOpener()">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8">
            <path d="M8 1v3M8 12v3M1 8h3M12 8h3M3.22 3.22l2.12 2.12M10.66 10.66l2.12 2.12M3.22 12.78l2.12-2.12M10.66 5.34l2.12-2.12"/>
          </svg>
          Generate
        </button>
        <button class="opener-regen-btn" id="openerRegenBtn" style="display:none" onclick="generateOpener()">↻ Regenerate</button>
      </div>
    </div>
    <div style="height:8px"></div>`;

  // Auto-resize textareas
  wrap.querySelectorAll('.textarea-field').forEach(ta => {
    ta.style.height = 'auto'; ta.style.height = ta.scrollHeight + 'px';
    ta.addEventListener('input', () => { ta.style.height = 'auto'; ta.style.height = ta.scrollHeight + 'px'; });
  });
}

function getLiveValues() {
  const anc = [0,1,2].map(i => { const el = document.getElementById('anc-'+i); return el ? el.value.trim() : ''; });
  const batna = (document.getElementById('batna-field')?.value || '').trim();
  const zopa  = (document.getElementById('zopa-field')?.value  || '').trim();
  const customName = (document.getElementById('custom-name')?.value || '').trim();
  return { anc, batna, zopa, customName };
}

async function generateOpener() {
  const genBtn   = document.getElementById('openerGenBtn');
  const regenBtn = document.getElementById('openerRegenBtn');
  const box      = document.getElementById('openerBox');
  if (!genBtn || !box) return;

  genBtn.disabled = true;
  box.innerHTML = `<div class="opener-loading"><div class="opener-spinner"></div><div class="opener-loading-text">Generating your line…</div></div>`;

  const { anc, batna, customName } = getLiveValues();
  const sceneName = currentSC.id === 'custom' ? customName || 'Custom' : currentSC.name;

  try {
    const content = await secureAPICall([
      {
        role: 'system',
        content: `You are a negotiation coach. Generate the opening line for a negotiation.

RULES — follow exactly:
- Max 15 words. Ideal: 8–12 words.
- State the High anchor FIRST. One number only — no ranges.
- NO: "thank you", "I appreciate", "based on my experience", "because", "I was thinking/hoping"
- NO ranges (e.g. "between X and Y")
- Sound like a confident human, not a robot
- Return ONLY the line — no quotes, no prefix, no markdown

GOOD: "I'm at $148,000." / "My number is $148,000." / "The rate is $150 an hour." / "We're starting at $50,000."
BAD: "Based on my experience, I was thinking somewhere in the range of $140,000 to $150,000."
BAD: "Thank you for the offer. I'd like to counter at around $148,000."

Return only the line.`
      },
      {
        role: 'user',
        content: `Scenario: ${sceneName}\nHigh anchor: ${anc[0]}\nBATNA (context only): ${batna}`
      }
    ], 60, false);

    generatedOpener = content.trim().replace(/^["']|["']$/g, '');
    box.innerHTML = `<div class="opener-text">${generatedOpener}</div><div class="opener-hint">Say this first. Then stop talking.</div>`;
    genBtn.style.display = 'none';
    regenBtn.style.display = 'block';
  } catch(err) {
    box.innerHTML = `<div class="opener-empty">${err.message}</div>`;
    genBtn.disabled = false;
  }
}

function goLive() {
  stopMic();
  resetLive();
  const { anc, customName } = getLiveValues();
  document.getElementById('liveScene').textContent = currentSC.id === 'custom' ? (customName || 'Custom') : currentSC.name;
  earOn = true;
  const earBtn = document.getElementById('earBtn');
  if (earBtn) { earBtn.textContent = '🔈'; earBtn.classList.add('on'); }
  go('s-live');
  setTimeout(startMic, 420);
}

function resetLive() {
  finalBuf = ''; sessionHistory = []; processing = false; micActive = false;
  clearTimeout(silenceTimer);
  document.getElementById('cIdle').style.display = 'flex';
  document.getElementById('cResult').classList.remove('show');
  document.getElementById('coachCard').classList.remove('live');
  document.getElementById('tLive').innerHTML = '';
  document.getElementById('tHistory').innerHTML = '';
  setS('idle', 'Waiting for microphone...');
}

async function confirmEnd() {
  inlineConfirm(
    document.getElementById('endBtn'),
    () => { stopMic(); earOn = true; go('s-home'); },
    { yesLabel: 'End', yesClass: 'danger' }
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// MIC
// ─────────────────────────────────────────────────────────────────────────────
function startMic() {
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SR) { setS('idle', "Use Chrome — speech recognition isn't available here."); return; }
  rec = new SR();
  rec.continuous = true; rec.interimResults = true; rec.lang = 'en-US';
  rec.onstart = () => setS('on', 'Listening...');
  rec.onresult = e => {
    let interim = '', newFinal = '';
    for (let i = e.resultIndex; i < e.results.length; i++) {
      const t = e.results[i][0].transcript;
      e.results[i].isFinal ? (newFinal += t + ' ') : (interim += t);
    }
    if (newFinal) {
      finalBuf += newFinal; setTx(finalBuf.trim(), '');
      clearTimeout(silenceTimer); silenceTimer = setTimeout(coach, 1800);
    }
    if (interim) setTx(finalBuf.trim(), interim);
    setS('on', 'Hearing them...');
  };
  rec.onerror = e => { if (e.error === 'not-allowed') setS('idle', 'Mic blocked — allow access in settings.'); };
  rec.onend = () => { if (micActive && rec) { setTimeout(() => { try { rec && rec.start(); } catch(e) {} }, 300); } };
  micActive = true;
  try { rec.start(); } catch(e) {}
  startVol();
}

function stopMic() {
  micActive = false; clearTimeout(silenceTimer);
  if (rec)      { try { rec.abort();      } catch(e) {} rec = null; }
  if (audioCtx) { try { audioCtx.close(); } catch(e) {} audioCtx = null; }
  if (animId)   { cancelAnimationFrame(animId); animId = null; }
}

function startVol() {
  navigator.mediaDevices.getUserMedia({ audio: true, video: false }).then(stream => {
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    analyser = audioCtx.createAnalyser(); analyser.fftSize = 128;
    audioCtx.createMediaStreamSource(stream).connect(analyser);
    const data = new Uint8Array(analyser.frequencyBinCount);
    const bars = document.querySelectorAll('.vb');
    function tick() {
      analyser.getByteFrequencyData(data);
      const avg = data.reduce((a,b) => a+b, 0) / data.length;
      bars.forEach((b,i) => b.classList.toggle('lit', avg > (i+1)*4));
      animId = requestAnimationFrame(tick);
    }
    tick();
  }).catch(() => {});
}

function setTx(fin, int) {
  document.getElementById('tLive').innerHTML = `<span>${fin}</span><span class="t-interim"> ${int}</span>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// COACHING
// ─────────────────────────────────────────────────────────────────────────────
async function coach() {
  const text = finalBuf.trim();
  if (!text || text.length < 4 || processing) return;
  processing = true; setS('spin', 'Getting your line...');
  pushBubble(text); finalBuf = '';
  document.getElementById('tLive').innerHTML = '';
  const { anc, batna, zopa, customName } = getLiveValues();
  const sceneName = currentSC.id === 'custom' ? customName : currentSC.name;
  const ctx = `a ${sceneName} negotiation. High anchor: ${anc[0]}. Mid: ${anc[1]||'n/a'}. Floor: ${anc[2]||'n/a'}. BATNA: "${batna}". Range: "${zopa}".`;
  const hist = sessionHistory.slice(-4).map(h => `${h.r==='them'?'Other party':'Coach'}: ${h.t}`).join('\n');
  const safeText = sanitize(text);
  try {
    const content = await secureAPICall([
      {
        role: 'system',
        content: `You are a negotiation coach whispering through someone's earpiece. They are in ${ctx}

Return a JSON object with exactly these keys:
{"tag":"TACTIC","line":"Exactly what they should say verbatim","advice":"One sentence of tactical reasoning"}

tag = 1–3 words ALL CAPS (ANCHOR HOLD, PROBE, FLINCH, WALK, REFRAME, SILENCE, TRADE, CALL BLUFF)
line = one confident natural sentence — sounds like a real person
advice = specific tactical reasoning, not generic
Be bold. No filler.`
      },
      {
        role: 'user',
        content: `${hist ? 'Recent exchange:\n' + hist + '\n\n' : ''}They just said:\n"${safeText}"\n\nGive me my line.`
      }
    ], 180, true);
    const parsed = JSON.parse(content.trim().replace(/```json|```/g, ''));
    showCoach(parsed);
    sessionHistory.push({ r:'them', t:safeText }, { r:'coach', t:parsed.line });
    if (earOn) speak(parsed.line);
  } catch(err) {
    showCoach({ tag:'PAUSE', line:'Let me think about that for a moment.', advice:'Deliberate silence applies pressure. Never rush under stress.' });
  }
  processing = false; setS('on', 'Listening...');
}

function showCoach({ tag, line, advice }) {
  document.getElementById('cIdle').style.display = 'none';
  document.getElementById('cTag').textContent = tag;
  document.getElementById('cLine').textContent = `"${line}"`;
  document.getElementById('cAdvice').textContent = advice;
  const r = document.getElementById('cResult');
  r.classList.remove('show'); void r.offsetWidth; r.classList.add('show');
  document.getElementById('coachCard').classList.add('live');
}

function markSaid() {
  document.getElementById('cResult').classList.remove('show');
  document.getElementById('coachCard').classList.remove('live');
  setTimeout(() => document.getElementById('cIdle').style.display = 'flex', 220);
  setS('on', 'Good. Listening for their reply...'); toast('Logged');
}

function pushBubble(text) {
  const h = document.getElementById('tHistory');
  if (h.children.length >= 3) h.removeChild(h.firstChild);
  const d = document.createElement('div');
  d.className = 't-bubble'; d.textContent = text;
  h.appendChild(d);
}

// ─────────────────────────────────────────────────────────────────────────────
// TTS
// ─────────────────────────────────────────────────────────────────────────────
function speak(text) {
  if (!window.speechSynthesis) return;
  window.speechSynthesis.cancel();
  const u = new SpeechSynthesisUtterance(text);
  u.rate = 0.87; u.pitch = 1; u.volume = 1;
  const v = window.speechSynthesis.getVoices().find(v => /Samantha|Karen|Google US English|Alex/.test(v.name));
  if (v) u.voice = v;
  window.speechSynthesis.speak(u);
}

function toggleEar() {
  earOn = !earOn;
  const b = document.getElementById('earBtn');
  b.textContent = earOn ? '🔈' : '🔇'; b.classList.toggle('on', earOn);
  toast(earOn ? 'Earpiece on' : 'Earpiece off');
}

// ─────────────────────────────────────────────────────────────────────────────
// STATUS & TOAST
// ─────────────────────────────────────────────────────────────────────────────
function setS(state, msg) {
  const d = document.getElementById('sDot');
  d.className = 's-dot' + (state==='on'?' on':state==='spin'?' spin':'');
  document.getElementById('sText').textContent = msg;
}

function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  clearTimeout(t._t); t._t = setTimeout(() => t.classList.remove('show'), 1800);
}

// ─────────────────────────────────────────────────────────────────────────────
// CLEANUP
// ─────────────────────────────────────────────────────────────────────────────
window.addEventListener('beforeunload', () => SecureStore.clear())
