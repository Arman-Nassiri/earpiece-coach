// ─────────────────────────────────────────────────────────────────────────────
// SECURITY: API key in closure only
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
    models: [
      { id: 'gpt-4.1-mini', label: 'GPT-4.1 Mini', badge: 'fastest · cheapest' },
      { id: 'gpt-4.1',      label: 'GPT-4.1',      badge: 'recommended' },
      { id: 'gpt-4o',       label: 'GPT-4o',        badge: 'balanced' },
    ],
    endpoint: () => 'https://api.openai.com/v1/chat/completions',
    authHeader: key => ({ 'Authorization': 'Bearer ' + key }),
    buildBody: (maxTokens, jsonMode, systemContent, userMessages) => ({
      model: currentModel, max_tokens: maxTokens, temperature: 0.7,
      messages: [...(systemContent ? [{role:'system',content:systemContent}] : []), ...userMessages],
      ...(jsonMode ? { response_format: { type: 'json_object' } } : {})
    }),
    extractContent: data => data?.choices?.[0]?.message?.content,
    validateKey: key => key.startsWith('sk-') && key.length >= 20
  },
  anthropic: {
    name: 'Anthropic', placeholder: 'sk-ant-api03-...',
    note: 'Key sent directly to api.anthropic.com — never stored or logged.',
    models: [
      { id: 'claude-haiku-4-5-20251001', label: 'Claude Haiku 4.5', badge: 'fastest · cheapest' },
      { id: 'claude-sonnet-4-5',         label: 'Claude Sonnet 4.5', badge: 'recommended' },
      { id: 'claude-opus-4-5',           label: 'Claude Opus 4.5',   badge: 'most capable' },
    ],
    endpoint: () => 'https://api.anthropic.com/v1/messages',
    authHeader: key => ({
      'x-api-key': key,
      'anthropic-version': '2023-06-01',
      'anthropic-dangerous-direct-browser-access': 'true'
    }),
    buildBody: (maxTokens, jsonMode, systemContent, userMessages) => ({
      model: currentModel, max_tokens: maxTokens,
      ...(systemContent ? { system: systemContent } : {}),
      messages: userMessages
    }),
    extractContent: data => data?.content?.[0]?.text,
    validateKey: key => key.startsWith('sk-ant-')
  },
  google: {
    name: 'Google', placeholder: 'AIzaSy...',
    note: 'Key sent directly to generativelanguage.googleapis.com.',
    models: [
      { id: 'gemini-2.0-flash',       label: 'Gemini 2.0 Flash',   badge: 'fastest · cheapest' },
      { id: 'gemini-2.5-flash',       label: 'Gemini 2.5 Flash',   badge: 'recommended' },
      { id: 'gemini-2.5-pro',         label: 'Gemini 2.5 Pro',     badge: 'most capable' },
    ],
    endpoint: key => `https://generativelanguage.googleapis.com/v1beta/models/${currentModel}:generateContent?key=${key}`,
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
    models: [
      { id: 'gpt-4o-mini', label: 'GPT-4o Mini', badge: 'fastest · cheapest' },
      { id: 'gpt-4o',      label: 'GPT-4o',      badge: 'recommended' },
      { id: 'gpt-4.1',     label: 'GPT-4.1',     badge: 'most capable' },
    ],
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
    models: [
      { id: 'Llama-4-Scout-17B-16E-Instruct', label: 'Llama 4 Scout',  badge: 'fastest · cheapest' },
      { id: 'Llama-4-Maverick-17B-128E-Instruct', label: 'Llama 4 Maverick', badge: 'recommended' },
      { id: 'Meta-Llama-3.3-70B-Instruct',    label: 'Llama 3.3 70B', badge: 'balanced' },
    ],
    endpoint: () => 'https://api.llama.com/v1/chat/completions',
    authHeader: key => ({ 'Authorization': 'Bearer ' + key }),
    buildBody: (maxTokens, jsonMode, systemContent, userMessages) => ({
      model: currentModel, max_tokens: maxTokens,
      messages: [...(systemContent ? [{role:'system',content:systemContent}] : []), ...userMessages]
    }),
    extractContent: data =>
      data?.choices?.[0]?.message?.content ??
      data?.completion_message?.content?.text ?? null,
    validateKey: key => key.length >= 20
  }
};

let currentProvider = 'openai';
let currentModel = 'gpt-4.1-mini';

// ─────────────────────────────────────────────────────────────────────────────
// SANITIZE
// ─────────────────────────────────────────────────────────────────────────────
function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>]/g,'').replace(/javascript:/gi,'').replace(/on\w+=/gi,'').trim().slice(0,500);
}

// ─────────────────────────────────────────────────────────────────────────────
// SECURE API CALL
// ─────────────────────────────────────────────────────────────────────────────
async function secureAPICall(messages, maxTokens = 200, jsonMode = false) {
  const rl = RateLimit.check();
  if (!rl.ok) throw new Error(rl.reason);
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
  } catch(e) { throw new Error('Could not reach ' + p.name + '. Check your connection.'); }
  if (!res.ok) {
    let errMsg = 'Error ' + res.status;
    try { const d = await res.json(); errMsg = d?.error?.message || d?.error?.status || errMsg; } catch(_) {}
    if (res.status === 401 || res.status === 403) throw new Error('Key rejected by ' + p.name + ' — double-check it.');
    if (res.status === 429) throw new Error('Rate limited — wait a moment.');
    throw new Error(errMsg);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SCENARIO LIBRARY — 13 scenarios, no icons
// ─────────────────────────────────────────────────────────────────────────────
const LIBRARY = [
  { id:'salary',
    name:'Salary',
    sub:'Job offer, raise, or promotion',
    anchors:[{l:'High',v:'$148,000'},{l:'Mid',v:'$142,000'},{l:'Floor',v:'$135,000'}],
    batna:'Competing offer at $128,000 from another company',
    zopa:'Their likely range: $130,000 – $150,000' },
  { id:'rent',
    name:'Rent',
    sub:'Apartment or lease negotiation',
    anchors:[{l:'High',v:'$2,100/mo'},{l:'Mid',v:'$2,200/mo'},{l:'Floor',v:'$2,350/mo'}],
    batna:'Comparable unit nearby listed at $2,150/mo',
    zopa:'Landlord likely flexible between $2,200 – $2,400' },
  { id:'car',
    name:'Car Dealer',
    sub:'New or used vehicle price',
    anchors:[{l:'High',v:'$31,500 OTD'},{l:'Mid',v:'$33,000 OTD'},{l:'Floor',v:'$34,500 OTD'}],
    batna:'Same trim at competing dealer: $33,200 out the door',
    zopa:'Dealer invoice ~$30,800 — meaningful room exists' },
  { id:'freelance',
    name:'Freelance Rate',
    sub:'Hourly or project rate with a client',
    anchors:[{l:'High',v:'$150/hr'},{l:'Mid',v:'$130/hr'},{l:'Floor',v:'$110/hr'}],
    batna:'Another client offering $105/hr for similar work',
    zopa:'Client likely has budget for $120–$145/hr' },
  { id:'joboffer',
    name:'Job Offer Counter',
    sub:'Push back on an existing offer',
    anchors:[{l:'High',v:'$155,000'},{l:'Mid',v:'$148,000'},{l:'Floor',v:'$140,000'}],
    batna:'Current offer on the table: $132,000',
    zopa:'Recruiter hinted budget can stretch to $145–$150K' },
  { id:'biz',
    name:'Business Deal',
    sub:'Partnership, contract, or vendor',
    anchors:[{l:'High',v:'$50,000'},{l:'Mid',v:'$42,000'},{l:'Floor',v:'$35,000'}],
    batna:'Alternative vendor quoted $34,000 for same scope',
    zopa:"Other party's budget appears to be $38,000–$48,000" },
  { id:'severance',
    name:'Severance',
    sub:'Negotiate exit terms with employer',
    anchors:[{l:'High',v:'6 months pay'},{l:'Mid',v:'4 months pay'},{l:'Floor',v:'2 months pay'}],
    batna:'Standard policy offers 2 weeks per year of service',
    zopa:'Company has offered 6–8 weeks in similar departures' },
  { id:'medical',
    name:'Medical Bill',
    sub:'Negotiate a hospital or provider bill',
    anchors:[{l:'High',v:'50% reduction'},{l:'Mid',v:'35% reduction'},{l:'Floor',v:'20% reduction'}],
    batna:"Can set up a 12-month payment plan if they won't reduce",
    zopa:'Hospitals routinely settle for 40–60% of billed amount' },
  { id:'realestate',
    name:'Real Estate',
    sub:'Home purchase or sale price',
    anchors:[{l:'High',v:'$620,000'},{l:'Mid',v:'$635,000'},{l:'Floor',v:'$650,000'}],
    batna:'Another property in the same area listed at $645,000',
    zopa:'Seller listed at $659,000 — likely flexible to $630–$645K' },
  { id:'equity',
    name:'Equity & Comp',
    sub:'Stock options, RSUs, or signing bonus',
    anchors:[{l:'High',v:'$80,000 signing + 1.2% equity'},{l:'Mid',v:'$60,000 signing + 0.9%'},{l:'Floor',v:'$40,000 signing + 0.6%'}],
    batna:'Competing offer includes $50K signing and 0.7% equity',
    zopa:'Startup has flexibility on equity but less cash — push equity first' },
  { id:'agency',
    name:'Agency / Retainer',
    sub:'Monthly retainer or agency contract',
    anchors:[{l:'High',v:'$12,000/mo'},{l:'Mid',v:'$9,500/mo'},{l:'Floor',v:'$7,500/mo'}],
    batna:'Can bring work in-house for roughly $6,000/mo in overhead',
    zopa:"Agency's typical range for similar scope: $8,000–$11,000/mo" },
  { id:'raise',
    name:'Performance Raise',
    sub:'Annual review or mid-cycle raise ask',
    anchors:[{l:'High',v:'22% increase'},{l:'Mid',v:'16% increase'},{l:'Floor',v:'11% increase'}],
    batna:'Market data shows peers earning 18–24% more for same role',
    zopa:'Budget cycles typically allow 8–15% — come in high to create room' },
  { id:'custom',
    name:'Custom',
    sub:'Any negotiation, your terms',
    anchors:[{l:'High',v:''},{l:'Mid',v:''},{l:'Floor',v:''}],
    batna:'',
    zopa:'' }
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

  // Typewriter on subtitle
  const twEl = document.getElementById('typewriterText');
  if (twEl) {
    const lines = ['Your AI negotiation coach,\nwhispering in your ear.'];
    const full = lines[0];
    let i = 0;
    const delay = 28; // ms per character — fast but readable
    function type() {
      if (i <= full.length) {
        twEl.innerHTML = full.slice(0, i).replace(/\n/g, '<br>');
        i++;
        setTimeout(type, delay);
      }
      // cursor keeps blinking via CSS after done
    }
    setTimeout(type, 420); // slight pause before starting
  }

  const list = document.getElementById('cardList');
  LIBRARY.forEach(sc => {
    const div = document.createElement('div');
    div.className = 'scenario-card';
    div.innerHTML = `
      <div class="sc-text">
        <div class="sc-name">${sc.name}</div>
        <div class="sc-sub">${sc.sub}</div>
      </div>
      <div class="sc-arr">&#8250;</div>`;
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
  const sym = dark ? '&#9790;' : '&#9788;';
  ['themeBtn','themeBtnLaunch'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = sym;
  });
  if (save) localStorage.setItem('gc-theme', dark ? 'dark' : 'light');
}
function toggleTheme() { applyTheme(!darkMode); }

// ─────────────────────────────────────────────────────────────────────────────
// INLINE CONFIRM
// ─────────────────────────────────────────────────────────────────────────────
function inlineConfirm(btn, onConfirm, opts = {}) {
  if (!btn || btn.dataset.confirming) return;
  btn.dataset.confirming = '1';
  const origHTML = btn.innerHTML;
  const origClass = btn.className;
  const origStyle = btn.getAttribute('style') || '';

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
    btn.innerHTML = origHTML;
    btn.className = origClass;
    btn.classList.remove('ic-host');
    btn.setAttribute('style', origStyle);
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
// CHANGE KEY — from home screen
// ─────────────────────────────────────────────────────────────────────────────
function changeKey() {
  SecureStore.clear();
  // reset key screen state
  document.getElementById('apiKeyInput').value = '';
  document.getElementById('keyVerifyStatus').textContent = '';
  document.getElementById('keyVerifyStatus').className = 'key-verify-status';
  document.getElementById('continueBtn').disabled = false;
  document.getElementById('continueBtn').textContent = 'Verify & Continue';
  go('s-key');
}

function updateModelSelect(provider) {
  const p = PROVIDERS[provider];
  const sel = document.getElementById('modelSelect');
  if (!sel || !p.models) return;
  sel.innerHTML = p.models.map(m =>
    `<option value="${m.id}">${m.label} — ${m.badge}</option>`
  ).join('');
  currentModel = p.models[0].id;
  sel.value = currentModel;
  sel.onchange = () => { currentModel = sel.value; };
}

// ─────────────────────────────────────────────────────────────────────────────
// PROVIDER TABS
// ─────────────────────────────────────────────────────────────────────────────
(function initProviderTabs() {
  updateModelSelect('openai');
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
      updateModelSelect(currentProvider);
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
    status.textContent = '✓ Verified'; status.className = 'key-verify-status ok';
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
  const sidebarTitle = document.getElementById('prepTitleSidebar');
  if (sidebarTitle) sidebarTitle.textContent = sc.name;
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
        <button class="opener-regen-btn" id="openerRegenBtn" style="display:none" onclick="generateOpener()">&#8635; Regenerate</button>
      </div>
    </div>
    <div style="height:8px"></div>`;

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
  const { customName } = getLiveValues();
  const sceneName = currentSC.id === 'custom' ? (customName || 'Custom') : currentSC.name;
  document.getElementById('liveScene').textContent = sceneName;
  const sidebarScene = document.getElementById('liveSceneSidebar');
  if (sidebarScene) sidebarScene.textContent = sceneName;
  earOn = true;
  syncEarUI();
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

// ─────────────────────────────────────────────────────────────────────────────
// END SESSION — works for both mobile and desktop buttons
// ─────────────────────────────────────────────────────────────────────────────
function confirmEnd(btn) {
  // Fallback: if called without a button reference, find first end-btn
  const target = btn || document.getElementById('endBtn') || document.querySelector('.end-btn');
  inlineConfirm(
    target,
    () => {
      stopMic();
      earOn = true;
      // Small delay so inline confirm restores before screen transition
      setTimeout(() => go('s-home'), 50);
    },
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

function syncEarUI() {
  const on = earOn;
  // In-card button
  const b = document.getElementById('earBtn');
  if (b) { b.textContent = on ? 'EAR ON' : 'EAR OFF'; b.classList.toggle('on', on); }
  // Nav bar (mobile)
  const bn = document.getElementById('earBtnNav');
  if (bn) { bn.title = on ? 'Earpiece on — tap to mute' : 'Earpiece off — tap to enable'; bn.classList.toggle('on', on); }
  // Sidebar (desktop)
  const bs = document.getElementById('earBtnSidebar');
  const bl = document.getElementById('earBtnSidebarLabel');
  if (bs) bs.classList.toggle('on', on);
  if (bl) bl.textContent = on ? 'Earpiece on' : 'Earpiece off';
}

function toggleEar() {
  earOn = !earOn;
  syncEarUI();
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
// CHAT ENGINE
// ─────────────────────────────────────────────────────────────────────────────

const CHAT_BOTS = {
  coach: {
    name: 'Coach Chat',
    chip: 'Coach',
    system: `You are an expert negotiation coach — direct, sharp, and practical. You've studied every major framework (BATNA, anchoring, mirroring, silence, ZOPA, Ackermann) and you've coached people through salary negotiations, real estate deals, business contracts, and high-stakes boardroom moments.

Your job: answer the user's negotiation questions with specific, tactical advice. No filler, no generic platitudes. Be bold. When they're wrong, tell them. When they have an edge, push them to use it.

Always end your first message with a concrete, specific question that invites them to describe their situation.`,
    opener: `I'm your negotiation coach — think of me as the voice in your ear before the big conversation.\n\nI can help you with anchoring strategy, handling pressure tactics, knowing when to walk, what to say when they lowball you, or just thinking through your position.\n\nWhat are you walking into?`
  },
  advisor: {
    name: 'Scenario Advisor',
    chip: 'Advisor',
    system: `You are a negotiation scenario advisor. Your job is to interview the user, understand their negotiation situation, and then fill out a prep brief for them.

Through the conversation, gather:
1. What kind of negotiation it is (salary, rent, car, freelance, business deal, medical bill, real estate, or other)
2. Their high anchor (the first number they'll throw out — their opening ask)
3. Their mid target (what they'd be happy with)
4. Their floor (the minimum they'd accept / walk away point)
5. Their BATNA (best alternative if this falls through)
6. The likely range (what the other party probably has as budget/flexibility)

Ask questions naturally, one or two at a time. Don't make it feel like a form. Lead with curiosity. Infer what you can from context.

CRITICAL — When you have enough information to build the brief (usually after 2-3 exchanges), you MUST output your response in this EXACT format and nothing else — a single JSON object with a "message" field and a "fill" field:

{"message":"Your warm wrap-up message here telling them you've built their brief and are redirecting them now.","fill":{"id":"SCENARIO_ID","anchors":[{"l":"High","v":"VALUE"},{"l":"Mid","v":"VALUE"},{"l":"Floor","v":"VALUE"}],"batna":"BATNA TEXT","zopa":"ZOPA TEXT","customName":""}}

For SCENARIO_ID choose from: salary, rent, car, freelance, joboffer, biz, severance, medical, realestate, equity, agency, raise, custom
Use "custom" only if nothing fits. If custom, set customName.
For all other conversations (still gathering info), respond with plain text only — no JSON.`,
    opener: `I'm your Scenario Advisor. Tell me about your negotiation and I'll build your entire prep brief for you — anchors, BATNA, the works — automatically.\n\nWhat are you negotiating?`
  },
  intel: {
    name: 'Intel Chat',
    chip: 'Intel',
    system: `You are a negotiation intelligence analyst. Your job is to help the user understand who they're negotiating with — their likely motivations, constraints, pressure points, and decision-making patterns.

You build profiles of counterparts: hiring managers, landlords, car dealers, clients, executives, medical billing departments — anyone. You draw on psychology, organizational behavior, and negotiation theory to give the user an edge.

Be specific. Generic advice is useless. Push the user to give you details so you can give them sharper intelligence.

Always end your first message with a direct question about who they're negotiating with.`,
    opener: `I'm your Intel analyst. Before you walk in, you should know exactly who you're dealing with — what they want, what they fear, where they have flexibility, and where they don't.\n\nWho are you negotiating with?`
  }
};

let chatHistory = [];
let chatBot = 'coach';
let chatTyping = false;
let chatMobileHasBot = false;

function goChat() {
  chatMobileHasBot = false;
  chatHistory = [];
  chatBot = 'coach';
  // Reset to select view on mobile, direct to chat on desktop
  const isMobile = window.innerWidth < 768;
  const botSelect = document.getElementById('chatBotSelect');
  const chatView  = document.getElementById('chatView');
  const navTitle  = document.getElementById('chatNavTitle');
  const navChip   = document.getElementById('chatNavChip');
  botSelect.style.display = isMobile ? 'flex' : 'none';
  chatView.classList.toggle('visible', !isMobile);
  navTitle.textContent = 'AI Chat';
  navChip.style.visibility = 'hidden';
  if (!isMobile) {
    // Desktop: load default bot (coach) straight in
    loadChatBot('coach');
    setActiveSidebarBot('coach');
  }
  go('s-chat');
}

function chatBack() {
  if (chatMobileHasBot && window.innerWidth < 768) {
    // Go back to bot select
    chatMobileHasBot = false;
    document.getElementById('chatBotSelect').style.display = 'flex';
    document.getElementById('chatView').classList.remove('visible');
    document.getElementById('chatNavTitle').textContent = 'AI Chat';
    document.getElementById('chatNavChip').style.visibility = 'hidden';
  } else {
    go('s-home');
  }
}

function setActiveSidebarBot(bot) {
  document.querySelectorAll('.chat-bot-nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.bot === bot);
  });
}

function switchBot(bot, _el) {
  chatBot = bot;
  chatHistory = [];
  chatMobileHasBot = true;
  const isMobile = window.innerWidth < 768;
  if (isMobile) {
    document.getElementById('chatBotSelect').style.display = 'none';
    document.getElementById('chatView').classList.add('visible');
  }
  const b = CHAT_BOTS[bot];
  document.getElementById('chatNavTitle').textContent = b.name;
  document.getElementById('chatNavChip').style.visibility = 'visible';
  document.getElementById('chatNavChip').textContent = b.chip;
  setActiveSidebarBot(bot);
  loadChatBot(bot);
}

function loadChatBot(bot) {
  const b = CHAT_BOTS[bot];
  const msgs = document.getElementById('chatMessages');
  msgs.innerHTML = '';
  // Remove any existing redirect banner
  const existing = document.getElementById('chatRedirectBanner');
  if (existing) existing.remove();
  updateChatFootnote();
  // AI speaks first
  appendChatMsg('ai', b.opener);
  chatHistory = [{ role: 'assistant', content: b.opener }];
  // Focus input
  setTimeout(() => document.getElementById('chatInput')?.focus(), 100);
}

function updateChatFootnote() {
  const p = PROVIDERS[currentProvider];
  const modelLabel = p?.models?.find(m => m.id === currentModel)?.label || currentModel;
  const footnote = `Using ${p?.name || currentProvider} · ${modelLabel}`;
  document.getElementById('chatFootnote').textContent = footnote;
  document.getElementById('chatSidebarFooter').textContent = footnote;
}

function appendChatMsg(role, text) {
  const msgs = document.getElementById('chatMessages');
  const wrap = document.createElement('div');
  wrap.className = `chat-msg ${role}`;
  const bubble = document.createElement('div');
  bubble.className = 'chat-bubble';
  // Convert newlines to <br> safely
  bubble.innerHTML = text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\n/g,'<br>');
  wrap.appendChild(bubble);
  msgs.appendChild(wrap);
  msgs.scrollTop = msgs.scrollHeight;
  return wrap;
}

function showTyping() {
  const msgs = document.getElementById('chatMessages');
  const el = document.createElement('div');
  el.className = 'chat-typing'; el.id = 'chatTypingIndicator';
  for (let i = 0; i < 3; i++) {
    const d = document.createElement('div'); d.className = 'chat-typing-dot'; el.appendChild(d);
  }
  msgs.appendChild(el);
  msgs.scrollTop = msgs.scrollHeight;
}

function removeTyping() {
  const el = document.getElementById('chatTypingIndicator');
  if (el) el.remove();
}

function tryParseAdvisorFill(reply) {
  // Strategy 1: entire reply is a JSON object with "fill" key
  try {
    const clean = reply.trim().replace(/^```json|^```|```$/gm, '').trim();
    const obj = JSON.parse(clean);
    if (obj && obj.fill && obj.fill.id && obj.fill.anchors) return obj;
    // Strategy 2: JSON object that IS the fill itself (has id + anchors)
    if (obj && obj.id && obj.anchors) return { message: '', fill: obj };
  } catch(_) {}
  // Strategy 3: find any JSON blob in the reply that looks like a fill
  const jsonMatches = reply.match(/\{[^{}]*"id"\s*:\s*"[^"]+?"[^{}]*"anchors"[^{}]*\[[\s\S]*?\][^{}]*\}/g);
  if (jsonMatches) {
    for (const m of jsonMatches) {
      try {
        const obj = JSON.parse(m);
        if (obj.id && obj.anchors) {
          const displayText = reply.replace(m, '').trim();
          return { message: displayText, fill: obj };
        }
      } catch(_) {}
    }
  }
  // Strategy 4: find any JSON blob with batna field (looser match)
  const looseMatch = reply.match(/(\{[\s\S]*?"batna"[\s\S]*?\})/);
  if (looseMatch) {
    try {
      const obj = JSON.parse(looseMatch[1]);
      if (obj.id && obj.anchors) {
        const displayText = reply.replace(looseMatch[1], '').trim();
        return { message: displayText, fill: obj };
      }
    } catch(_) {}
  }
  return null;
}

async function chatSend() {
  const inp = document.getElementById('chatInput');
  const text = (inp.value || '').trim();
  if (!text || chatTyping) return;
  inp.value = ''; inp.style.height = 'auto';
  appendChatMsg('user', text);
  chatHistory.push({ role: 'user', content: text });
  chatTyping = true;
  document.getElementById('chatSendBtn').disabled = true;
  showTyping();
  const b = CHAT_BOTS[chatBot];
  try {
    const messages = [
      { role: 'system', content: b.system },
      ...chatHistory
    ];
    const reply = await secureAPICall(messages, 700, false);
    removeTyping();
    // Advisor bot: try to detect a structured JSON response
    if (chatBot === 'advisor') {
      const fill = tryParseAdvisorFill(reply);
      if (fill) {
        if (fill.message) appendChatMsg('ai', fill.message);
        chatHistory.push({ role: 'assistant', content: reply });
        setTimeout(() => triggerScenarioFill(fill.fill || fill), 700);
      } else {
        appendChatMsg('ai', reply);
        chatHistory.push({ role: 'assistant', content: reply });
      }
    } else {
      appendChatMsg('ai', reply);
      chatHistory.push({ role: 'assistant', content: reply });
    }
  } catch(err) {
    removeTyping();
    appendChatMsg('ai', `Sorry, something went wrong: ${err.message}`);
  }
  chatTyping = false;
  document.getElementById('chatSendBtn').disabled = false;
  inp.focus();
}

function triggerScenarioFill(fill) {
  // Find the scenario card
  const sc = LIBRARY.find(s => s.id === fill.id) || LIBRARY.find(s => s.id === 'custom');
  if (!sc) return;
  // Build a modified scenario with the filled values
  const filled = {
    ...sc,
    anchors: fill.anchors || sc.anchors,
    batna: fill.batna || sc.batna,
    zopa: fill.zopa || sc.zopa,
    ...(fill.id === 'custom' ? { name: fill.customName || 'Custom' } : {})
  };
  currentSC = filled;
  // Highlight the card in the list if it exists
  document.querySelectorAll('.scenario-card').forEach((card, i) => {
    card.classList.toggle('selected', LIBRARY[i]?.id === filled.id);
  });
  // Show redirect banner inside chat
  showChatRedirectBanner(filled.name);
}

function showChatRedirectBanner(scenarioName) {
  // Remove existing banner
  const existing = document.getElementById('chatRedirectBanner');
  if (existing) existing.remove();
  const chatView = document.getElementById('chatView');
  const inputArea = document.querySelector('.chat-input-area');
  const banner = document.createElement('div');
  banner.className = 'chat-redirect-banner';
  banner.id = 'chatRedirectBanner';
  banner.innerHTML = `
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M13 8A5 5 0 113 8a5 5 0 0110 0zm-5-2v4m0 0l-1.5-1.5M8 10l1.5-1.5" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/></svg>
    <span>Prep brief ready: <strong>${scenarioName}</strong></span>
    <button class="chat-redirect-btn" onclick="launchFromChat()">Go to Prep →</button>
  `;
  chatView.insertBefore(banner, inputArea);
}

function launchFromChat() {
  if (!currentSC) return;
  generatedOpener = '';
  buildPrep();
  go('s-prep');
}

// Auto-resize textarea
document.addEventListener('DOMContentLoaded', () => {});
(function initChatInput() {
  const ta = document.getElementById('chatInput');
  if (!ta) return;
  ta.addEventListener('input', () => {
    ta.style.height = 'auto';
    ta.style.height = Math.min(ta.scrollHeight, 120) + 'px';
  });
  ta.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); chatSend(); }
  });
})();

// ─────────────────────────────────────────────────────────────────────────────
// CLEANUP
// ─────────────────────────────────────────────────────────────────────────────
window.addEventListener('beforeunload', () => SecureStore.clear());
