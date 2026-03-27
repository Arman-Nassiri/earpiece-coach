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
// VIEWPORT SYNC
// ─────────────────────────────────────────────────────────────────────────────
function syncViewportFrame() {
  const root = document.documentElement;
  const viewport = window.visualViewport;
  const height = viewport?.height ?? window.innerHeight;
  const offsetTop = viewport?.offsetTop ?? 0;
  root.style.setProperty('--app-height', `${Math.round(height)}px`);
  root.style.setProperty('--app-offset-top', `${Math.max(0, Math.round(offsetTop))}px`);
}

window.addEventListener('resize', syncViewportFrame, { passive: true });
window.addEventListener('orientationchange', syncViewportFrame, { passive: true });
window.visualViewport?.addEventListener('resize', syncViewportFrame, { passive: true });
window.visualViewport?.addEventListener('scroll', syncViewportFrame, { passive: true });
document.addEventListener('DOMContentLoaded', syncViewportFrame);
syncViewportFrame();

// ─────────────────────────────────────────────────────────────────────────────
// SANITIZE
// ─────────────────────────────────────────────────────────────────────────────
function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>]/g,'').replace(/javascript:/gi,'').replace(/on\w+=/gi,'').trim().slice(0,500);
}

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderMultilineText(el, text) {
  if (!el) return;
  el.textContent = '';
  const lines = String(text ?? '').split('\n');
  lines.forEach((line, idx) => {
    if (idx > 0) el.appendChild(document.createElement('br'));
    el.appendChild(document.createTextNode(line));
  });
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

const LIVE_SCENARIO_PROMPTS = {
  salary: {
    role: 'You are coaching a candidate negotiating compensation with a recruiter, manager, or hiring lead.',
    objective: 'Protect leverage, keep tone polished, and advance pay, title, scope, or timing.',
    examples: [
      'If they say "What number did you have in mind?" -> line should sound like a clean compensation ask, not an introduction.',
      'If they say "We are already at the top of the band." -> line should probe for flexibility in bonus, title, equity, or review timing.'
    ]
  },
  rent: {
    role: 'You are coaching a tenant speaking with a landlord, leasing office, or property manager.',
    objective: 'Lower rent, secure concessions, or improve terms without sounding chaotic.',
    examples: [
      'If they say "What are you looking for?" -> line should state the target rent or concession directly.',
      'If they say "That is our standard rate." -> line should calmly trade or push on flexibility.'
    ]
  },
  car: {
    role: 'You are coaching a buyer negotiating with a car dealer or sales manager.',
    objective: 'Drive toward an out-the-door number and avoid getting dragged into monthly-payment framing.',
    examples: [
      'If they say "How can I help you today?" -> line should anchor the out-the-door price, not introduce yourself.',
      'If they say "What monthly payment are you comfortable with?" -> line should redirect to total price.'
    ]
  },
  freelance: {
    role: 'You are coaching a freelancer or consultant negotiating rate and scope with a client.',
    objective: 'Hold rate integrity, control scope, and trade only for something meaningful.',
    examples: [
      'If they say "What do you charge?" -> line should anchor the rate crisply.',
      'If they say "That is above our budget." -> line should narrow scope or trade terms, not cave immediately.'
    ]
  },
  joboffer: {
    role: 'You are coaching someone countering an existing job offer.',
    objective: 'Increase the offer while preserving momentum and rapport.',
    examples: [
      'If they say "What would it take for you to sign?" -> line should state the exact package needed.',
      'If they say "We cannot move salary." -> line should push on other components or timing.'
    ]
  },
  biz: {
    role: 'You are coaching someone negotiating a business contract, vendor agreement, or commercial deal.',
    objective: 'Hold commercial leverage, clarify value, and trade carefully.',
    examples: [
      'If they say "What are you looking for?" -> line should state terms directly.',
      'If they say "That price is too high." -> line should reframe around scope, value, or trade.'
    ]
  },
  severance: {
    role: 'You are coaching an employee negotiating severance with HR, legal, or leadership.',
    objective: 'Expand severance, benefits, timing, and release terms while staying calm and disciplined.',
    examples: [
      'If they say "What are you asking for?" -> line should state the severance package directly.',
      'If they say "This is our standard package." -> line should push for justification and improved terms.'
    ]
  },
  medical: {
    role: 'You are coaching a patient or family member negotiating with hospital billing, a provider, or front-desk staff.',
    objective: 'Reduce the bill, uncover hardship or discount paths, and keep the conversation human and specific.',
    examples: [
      'If they say "Hi, what are you here for?" -> line should explain you are here to discuss reducing a medical bill, never that you are an AI or coach.',
      'If they say "We do not usually lower balances." -> line should push toward hardship review, itemized review, supervisor review, or settlement options.'
    ]
  },
  realestate: {
    role: 'You are coaching a buyer or seller negotiating with an agent, owner, or counterparty.',
    objective: 'Drive price and terms while controlling emotion and pace.',
    examples: [
      'If they say "What are you thinking?" -> line should anchor price or terms directly.',
      'If they say "We have other interest." -> line should call for specifics or hold the line.'
    ]
  },
  equity: {
    role: 'You are coaching a candidate or executive negotiating equity, signing bonus, or long-term compensation.',
    objective: 'Push total upside, not just cash, and sound commercially mature.',
    examples: [
      'If they say "What would make this compelling?" -> line should state the mix of cash, equity, and bonus.',
      'If they say "We are tighter on cash." -> line should push equity or milestone-based upside.'
    ]
  },
  agency: {
    role: 'You are coaching someone negotiating a retainer or agency agreement.',
    objective: 'Protect price, avoid free scope, and trade on deliverables or term length.',
    examples: [
      'If they say "Tell me what you are proposing." -> line should state the retainer clearly.',
      'If they say "Can you come down?" -> line should trade scope, term, or speed instead of dropping price nakedly.'
    ]
  },
  raise: {
    role: 'You are coaching an employee asking for a raise with a manager or leadership.',
    objective: 'Push for a concrete raise and next-step timing without sounding vague.',
    examples: [
      'If they say "What did you want to discuss?" -> line should state the raise ask directly.',
      'If they say "Budgets are tight." -> line should press on timing, criteria, and scope.'
    ]
  }
};

const NEGOTIATION_STYLES = {
  composed: {
    label: 'Composed',
    sub: 'Calm, premium, measured',
    guidance: 'Sound calm, expensive, and in control. Short sentences. No emotional leakage. Push without sounding needy.'
  },
  assertive: {
    label: 'Assertive',
    sub: 'Firm, direct, high-leverage',
    guidance: 'Sound direct and hard to move. Lead with the ask. Apply pressure cleanly. Never ramble or over-explain.'
  },
  warm: {
    label: 'Warm',
    sub: 'Human, empathetic, credible',
    guidance: 'Sound human and approachable while still protecting the number. Use warmth to lower resistance, not to surrender leverage.'
  },
  surgical: {
    label: 'Surgical',
    sub: 'Precise, analytical, disciplined',
    guidance: 'Sound highly precise and tactical. Clarify numbers, policy, and tradeoffs. Use tight wording and force specificity.'
  }
};

const PRACTICE_DIFFICULTIES = {
  cooperative: {
    label: 'Cooperative',
    sub: 'Light pushback',
    stance: 'You are polite and pragmatic, looking for a fair outcome but still protecting your side.',
    pressure: 'Low'
  },
  balanced: {
    label: 'Neutral',
    sub: 'Realistic pushback',
    stance: 'You are professional and commercially disciplined. You probe, counter, and ask for justification.',
    pressure: 'Medium'
  },
  tough: {
    label: 'Hardball',
    sub: 'Firm pressure',
    stance: 'You are skeptical and guard budget/terms tightly. You counter hard, exploit hesitation, and force specifics.',
    pressure: 'High'
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// APP STATE
// ─────────────────────────────────────────────────────────────────────────────
let currentSC = null;
let audioCtx = null, analyser = null, animId = null;
let sessionHistory = [];
let processing = false, earOn = true, darkMode = false;
let generatedOpener = '', micActive = false;
let liveAudioStream = null, livePeer = null, liveDataChannel = null;
let liveTranscriptDrafts = new Map();
let liveResponseBuffer = '';
let liveCurrentCoach = null;
let currentNegotiationStyle = 'composed';
let pendingSpeechTimer = null;
let negotiationDraft = null;
let practiceHistory = [];
let practiceTranscript = [];
let practiceTyping = false;
let practiceDifficulty = 'balanced';
let practiceKickoffStarted = false;
let practiceRequestToken = 0;
let practiceReviewContext = null;
let realtimeMode = 'coach';
let liveLastAssistantLine = '';
let liveLastAssistantAt = 0;

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
    document.getElementById('modalBody').textContent = body;
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

function openContact(event) {
  const ua = navigator.userAgent || '';
  const isMobile = /Android|iPhone|iPad|iPod/i.test(ua);
  if (isMobile) return;
  event.preventDefault();
  window.open('https://mail.google.com/mail/?view=cm&fs=1&tf=1&to=gibselcue@gmail.com', '_blank', 'noopener');
}

// ─────────────────────────────────────────────────────────────────────────────
// NAVIGATION
// ─────────────────────────────────────────────────────────────────────────────
function go(id) {
  const cur = document.querySelector('.screen.active');
  if (cur?.id === 's-practice' && id !== 's-practice') {
    resetPracticeRequestState();
  }
  if (cur?.id === 's-practice-voice' && id !== 's-practice-voice') {
    stopMic();
    realtimeMode = 'coach';
  }
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
  sel.onchange = () => {
    currentModel = sel.value;
    if (typeof updateChatFootnote === 'function') updateChatFootnote();
    if (typeof updatePracticeFootnote === 'function') updatePracticeFootnote();
    if (typeof updateVoicePracticeFootnote === 'function') updateVoicePracticeFootnote();
  };
}

function getProviderNote(provider) {
  const p = PROVIDERS[provider];
  if (!p) return '';
  if (provider === 'openai') {
    return 'Prep and chat go directly to api.openai.com. OpenAI live mode is proxied through Gibsel Cue to establish Realtime.';
  }
  return `${p.note} OpenAI live mode is still proxied through Gibsel Cue to establish Realtime.`;
}

// ─────────────────────────────────────────────────────────────────────────────
// PROVIDER TABS
// ─────────────────────────────────────────────────────────────────────────────
(function initProviderTabs() {
  updateModelSelect('openai');
  document.getElementById('keyNote').textContent = getProviderNote('openai');
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
      document.getElementById('keyNote').textContent = getProviderNote(currentProvider);
      document.getElementById('keyVerifyStatus').textContent = '';
      document.getElementById('keyVerifyStatus').className = 'key-verify-status';
      updateModelSelect(currentProvider);
      if (typeof updateChatFootnote === 'function') updateChatFootnote();
      if (typeof updatePracticeFootnote === 'function') updatePracticeFootnote();
      if (typeof updateVoicePracticeFootnote === 'function') updateVoicePracticeFootnote();
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
  card.classList.add('selected');
  currentSC = sc;
  initializeNegotiationDraft(sc);
}

function goPrep() {
  if (!currentSC) { toast('Choose a scenario first'); return; }
  ensureNegotiationDraft();
  generatedOpener = ''; buildPrep(); go('s-prep');
}

function buildNegotiationDraft(sc = currentSC) {
  if (!sc) return null;
  const styleId = currentNegotiationStyle in NEGOTIATION_STYLES ? currentNegotiationStyle : 'composed';
  const anc = (Array.isArray(sc.anchors) ? sc.anchors : [])
    .map(anchor => String(anchor?.v || '').trim())
    .slice(0, 3);
  while (anc.length < 3) anc.push('');
  const customName = sc.id === 'custom' && sc.name !== 'Custom' ? sc.name : '';
  return {
    scenarioId: sc.id || 'custom',
    anc,
    batna: String(sc.batna || '').trim(),
    zopa: String(sc.zopa || '').trim(),
    customName: String(customName || '').trim(),
    styleId
  };
}

function setNegotiationDraft(nextDraft) {
  if (!nextDraft) {
    negotiationDraft = null;
    return null;
  }
  const anc = Array.isArray(nextDraft.anc) ? nextDraft.anc.map(value => String(value || '').trim()).slice(0, 3) : ['', '', ''];
  while (anc.length < 3) anc.push('');
  const styleId = nextDraft.styleId in NEGOTIATION_STYLES ? nextDraft.styleId : 'composed';
  negotiationDraft = {
    scenarioId: nextDraft.scenarioId || currentSC?.id || 'custom',
    anc,
    batna: String(nextDraft.batna || '').trim(),
    zopa: String(nextDraft.zopa || '').trim(),
    customName: String(nextDraft.customName || '').trim(),
    styleId
  };
  currentNegotiationStyle = styleId;
  return negotiationDraft;
}

function initializeNegotiationDraft(sc = currentSC, overrides = {}) {
  const base = buildNegotiationDraft(sc);
  if (!base) return setNegotiationDraft(null);
  const nextDraft = {
    ...base,
    ...overrides,
    anc: Array.isArray(overrides.anc) ? overrides.anc : base.anc
  };
  return setNegotiationDraft(nextDraft);
}

function ensureNegotiationDraft() {
  if (!negotiationDraft && currentSC) initializeNegotiationDraft(currentSC);
  return negotiationDraft;
}

function updateNegotiationDraft(patch = {}) {
  const draft = ensureNegotiationDraft();
  if (!draft) return null;
  return setNegotiationDraft({
    ...draft,
    ...patch,
    anc: Array.isArray(patch.anc) ? patch.anc : draft.anc
  });
}

function getScenarioSceneName() {
  const values = getLiveValues();
  if (!currentSC) return 'Custom';
  if (currentSC.id === 'custom') {
    return values.customName || currentSC.name || 'Custom';
  }
  return currentSC.name;
}

function resetPracticeRequestState() {
  practiceRequestToken++;
  practiceTyping = false;
  practiceKickoffStarted = false;
  removePracticeTyping();
  const btn = document.getElementById('practiceSendBtn');
  if (btn) btn.disabled = false;
}

function pushPracticeTranscript(role, text) {
  const clean = sanitize(text);
  if (!clean) return;
  practiceTranscript.push({ role, text: clean });
}

function mapSessionHistoryToPracticeTranscript() {
  return sessionHistory
    .filter(turn => turn?.t && (turn.r === 'you' || turn.r === 'them'))
    .map(turn => ({
      role: turn.r === 'you' ? 'user' : 'assistant',
      text: sanitize(turn.t)
    }))
    .filter(turn => turn.text);
}

function getPracticeSessionTranscript(mode = 'text') {
  return (mode === 'voice' || mode === 'live') ? mapSessionHistoryToPracticeTranscript() : practiceTranscript.slice();
}

function formatPracticeTranscript(entries) {
  return entries
    .map(entry => `${entry.role === 'user' ? 'You' : 'Counterparty'}: ${entry.text}`)
    .join('\n');
}

function getPracticeReplayHandler() {
  if (practiceReviewContext?.mode === 'live') return goLive;
  if (practiceReviewContext?.mode === 'voice') return goVoicePractice;
  return goPractice;
}

function openPracticeReviewShell(mode) {
  practiceReviewContext = {
    mode,
    sceneName: getScenarioSceneName()
  };
  const title = document.getElementById('practiceReviewTitle');
  const subtitle = document.getElementById('practiceReviewSubtitle');
  const verdict = document.getElementById('practiceReviewVerdict');
  const score = document.getElementById('practiceReviewScore');
  const summary = document.getElementById('practiceReviewSummary');
  const footnote = document.getElementById('practiceReviewFootnote');
  const strengths = document.getElementById('practiceReviewStrengths');
  const misses = document.getElementById('practiceReviewMisses');
  const reps = document.getElementById('practiceReviewReps');
  const replay = document.getElementById('practiceReviewReplayBtn');
  const loading = document.getElementById('practiceReviewLoading');
  const content = document.getElementById('practiceReviewContent');

  if (title) title.textContent = practiceReviewContext.sceneName;
  if (subtitle) {
    subtitle.textContent =
      mode === 'live' ? 'Live Session Review' :
      mode === 'voice' ? 'Voice Practice Review' :
      'Text Practice Review';
  }
  if (verdict) verdict.textContent = 'Analyzing...';
  if (score) score.textContent = '—';
  if (summary) summary.textContent = 'Reading the session and building quick professional feedback.';
  if (footnote) {
    footnote.textContent =
      mode === 'live' ? 'Live coaching review' :
      mode === 'voice' ? 'Voice practice review' :
      'Text practice review';
  }
  if (strengths) strengths.innerHTML = '';
  if (misses) misses.innerHTML = '';
  if (reps) reps.innerHTML = '';
  if (replay) {
    replay.textContent =
      mode === 'live' ? 'Go Live Again' :
      mode === 'voice' ? 'Run Voice Again' :
      'Run Text Again';
  }
  if (loading) loading.style.display = 'flex';
  if (content) content.style.display = 'none';
  go('s-practice-review');
}

function renderPracticeReviewList(id, items) {
  const list = document.getElementById(id);
  if (!list) return;
  const safeItems = Array.isArray(items) && items.length ? items : ['Not enough signal yet.'];
  list.innerHTML = safeItems.map(item => `<li>${escapeHtml(item)}</li>`).join('');
}

function parsePracticeReview(reply) {
  const clean = String(reply || '').trim().replace(/```json|```/g, '').trim();
  try {
    const parsed = JSON.parse(clean);
    if (parsed && parsed.verdict && parsed.summary) {
      return parsed;
    }
  } catch(_) {}
  return {
    verdict: 'Needs another rep',
    score: '—',
    summary: clean || 'The review could not be structured cleanly, but the session completed.',
    strengths: [],
    misses: [],
    reps: []
  };
}

async function analyzePracticeSession(mode = 'text') {
  const entries = getPracticeSessionTranscript(mode);
  if (entries.length < 2) {
    toast('Not enough conversation to analyze yet');
    if (mode === 'voice') go('s-practice');
    if (mode === 'live') go('s-home');
    return;
  }

  openPracticeReviewShell(mode);
  try {
    const review = parsePracticeReview(await secureAPICall([
      {
        role: 'system',
        content: `You are a world-class negotiation trainer reviewing a short practice session.

Return a JSON object with exactly these keys:
{"verdict":"short title","score":"X/10","summary":"2-3 sentence professional review","strengths":["..."],"misses":["..."],"reps":["..."]}

Rules:
- Be direct and commercial.
- Focus on leverage, clarity, pressure handling, concessions, and pacing.
- Keep each list item to one sentence.
- Give 3 strengths, 3 misses, and 3 reps when possible.
- If the user handled something poorly, say it plainly.
- No markdown. JSON only.`
      },
      {
        role: 'user',
        content: `Scenario: ${getScenarioSceneName()}\nMode: ${mode}\nDifficulty: ${PRACTICE_DIFFICULTIES[practiceDifficulty]?.label || practiceDifficulty}\nTranscript:\n${formatPracticeTranscript(entries)}`
      }
    ], 700, true));

    const loading = document.getElementById('practiceReviewLoading');
    const content = document.getElementById('practiceReviewContent');
    const verdict = document.getElementById('practiceReviewVerdict');
    const score = document.getElementById('practiceReviewScore');
    const summary = document.getElementById('practiceReviewSummary');
    const footnote = document.getElementById('practiceReviewFootnote');

    if (loading) loading.style.display = 'none';
    if (content) content.style.display = 'grid';
    if (verdict) verdict.textContent = review.verdict || 'Session review';
    if (score) score.textContent = review.score || '—';
    if (summary) summary.textContent = review.summary || 'Review completed.';
    if (footnote) footnote.textContent = `Reviewed with ${PROVIDERS[currentProvider]?.name || currentProvider} · ${currentModel}`;
    renderPracticeReviewList('practiceReviewStrengths', review.strengths);
    renderPracticeReviewList('practiceReviewMisses', review.misses);
    renderPracticeReviewList('practiceReviewReps', review.reps);
  } catch(err) {
    const loading = document.getElementById('practiceReviewLoading');
    const content = document.getElementById('practiceReviewContent');
    const verdict = document.getElementById('practiceReviewVerdict');
    const summary = document.getElementById('practiceReviewSummary');
    if (loading) loading.style.display = 'none';
    if (content) content.style.display = 'grid';
    if (verdict) verdict.textContent = 'Review unavailable';
    if (summary) summary.textContent = err.message || 'Could not analyze the practice session.';
    renderPracticeReviewList('practiceReviewStrengths', []);
    renderPracticeReviewList('practiceReviewMisses', []);
    renderPracticeReviewList('practiceReviewReps', []);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PRACTICE MODE
// ─────────────────────────────────────────────────────────────────────────────

function renderPracticeDifficultyChips() {
  const containers = [
    document.getElementById('practiceDifficultyChips'),
    document.getElementById('practiceDifficultySidebar'),
    document.getElementById('practiceDifficultyVoice'),
    document.getElementById('practiceDifficultyVoiceSidebar')
  ].filter(Boolean);
  containers.forEach(container => {
    container.innerHTML = '';
    Object.entries(PRACTICE_DIFFICULTIES).forEach(([id, diff]) => {
      const btn = document.createElement('button');
      btn.className = 'practice-chip' + (practiceDifficulty === id ? ' active' : '');
      btn.dataset.difficulty = id;
      btn.innerHTML = `<div>${diff.label}</div><span class="practice-chip-sub">${diff.sub}</span>`;
      btn.addEventListener('click', () => setPracticeDifficulty(id));
      container.appendChild(btn);
    });
  });
}

function setPracticeStatus(text, state = 'on') {
  const el = document.getElementById('practiceStatus');
  if (el) el.textContent = text;
  const dot = document.getElementById('practiceStatusDot');
  if (dot) {
    dot.className = 's-dot' + (state === 'on' ? ' on' : state === 'spin' ? ' spin' : '');
  }
}

function setPracticeTitles() {
  const sceneName = getScenarioSceneName();
  const mobile = document.getElementById('practiceTitle');
  const desktop = document.getElementById('practiceTitleSidebar');
  if (mobile) mobile.textContent = sceneName;
  if (desktop) desktop.textContent = sceneName;
}

function setPracticeDifficulty(id) {
  if (!(id in PRACTICE_DIFFICULTIES)) return;
  practiceDifficulty = id;
  renderPracticeDifficultyChips();
  const hint = document.getElementById('practiceHint');
  if (hint) hint.textContent = `${PRACTICE_DIFFICULTIES[id].label}: ${PRACTICE_DIFFICULTIES[id].stance}`;
  const voiceHint = document.getElementById('practiceVoiceHint');
  if (voiceHint) voiceHint.textContent = `${PRACTICE_DIFFICULTIES[id].label}: ${PRACTICE_DIFFICULTIES[id].stance}`;
  refreshRealtimeSession();
}

function appendPracticeMsg(role, text) {
  const msgs = document.getElementById('practiceMessages');
  if (!msgs) return;
  const wrap = document.createElement('div');
  wrap.className = `practice-msg ${role}`;
  const bubble = document.createElement('div');
  bubble.className = 'practice-bubble';
  renderMultilineText(bubble, text);
  wrap.appendChild(bubble);
  msgs.appendChild(wrap);
  msgs.scrollTop = msgs.scrollHeight;
  return wrap;
}

function showPracticeTyping() {
  const msgs = document.getElementById('practiceMessages');
  if (!msgs) return;
  const el = document.createElement('div');
  el.className = 'practice-typing'; el.id = 'practiceTypingIndicator';
  for (let i = 0; i < 3; i++) {
    const d = document.createElement('div'); d.className = 'practice-typing-dot'; el.appendChild(d);
  }
  msgs.appendChild(el); msgs.scrollTop = msgs.scrollHeight;
}

function removePracticeTyping() {
  const el = document.getElementById('practiceTypingIndicator');
  if (el) el.remove();
}

function getPracticeSceneName() {
  return getScenarioSceneName();
}

function getPracticePrompt() {
  const { anc, batna, zopa, customName, styleId } = getLiveValues();
  const style = NEGOTIATION_STYLES[styleId] || NEGOTIATION_STYLES.composed;
  const diff = PRACTICE_DIFFICULTIES[practiceDifficulty] || PRACTICE_DIFFICULTIES.balanced;
  const sceneName = getPracticeSceneName();
  const scPrompt = LIVE_SCENARIO_PROMPTS[currentSC?.id] || null;
  const roleLine = scPrompt ? scPrompt.role.replace('You are coaching', 'You are playing') : 'You are the counterparty in this negotiation.';
  const objectiveLine = scPrompt?.objective ? `Objective: ${scPrompt.objective}` : '';
  const exampleLines = scPrompt?.examples ? scPrompt.examples.map(e => `- ${e}`).join('\n') : '';
  return `You are role-playing the COUNTERPARTY in a live negotiation practice.

Scenario: ${sceneName}
${roleLine}
${objectiveLine}
Anchors (user's asks): High ${anc[0] || 'n/a'}, Mid ${anc[1] || 'n/a'}, Floor ${anc[2] || 'n/a'}
User BATNA (their alternative): ${batna || 'n/a'}
User believes the other side's likely range: ${zopa || 'n/a'}

Difficulty mode: ${diff.label} (${diff.pressure} pressure). ${diff.stance}
Style selected by user: ${style.label} — ${style.guidance}

Rules for you:
- Stay entirely in character as the counterparty (recruiter, landlord, dealer, client, etc.). Never mention you are a simulation or coach.
- Respond in 1–3 sentences. Be concise and commercial.
- Push back, ask targeted questions, and counter with numbers or terms. Do not simply agree.
- If the user gives a number, react realistically (counter, probe, or trade). Avoid parroting their number back.
- Do not reveal or rely on the user's BATNA or floor. Treat them as unknown.
- Use the difficulty setting to set firmness and pressure. Hardball = tighter concessions and more scrutiny.
- Use the style to shape tone, not to soften leverage.
- Keep momentum; avoid long monologues.

If you need to start the conversation, open with a realistic line for the counterpart in this scenario.
${exampleLines ? `Scenario cues:\n${exampleLines}` : ''}`;
}

function updatePracticeFootnote() {
  const p = PROVIDERS[currentProvider];
  const modelLabel = p?.models?.find(m => m.id === currentModel)?.label || currentModel;
  const foot = `Counterparty AI · ${p?.name || currentProvider} · ${modelLabel}`;
  const el = document.getElementById('practiceFootnote');
  if (el) el.textContent = foot;
}

function resetPractice(startOver = false) {
  resetPracticeRequestState();
  practiceHistory = [];
  practiceTranscript = [];
  const msgs = document.getElementById('practiceMessages');
  if (msgs) msgs.innerHTML = '';
  const inp = document.getElementById('practiceInput');
  if (inp) {
    inp.value = '';
    inp.style.height = 'auto';
  }
  setPracticeStatus('Ready when you are. You can start or let them start.', 'on');
  setPracticeTitles();
  renderPracticeDifficultyChips();
  if (startOver) {
    setTimeout(kickoffPractice, 60);
  }
}

async function kickoffPractice() {
  if (practiceKickoffStarted) return;
  practiceKickoffStarted = true;
  const requestToken = practiceRequestToken;
  setPracticeStatus('Spinning up the counterparty...', 'spin');
  showPracticeTyping();
  try {
    const reply = await secureAPICall([
      { role: 'system', content: getPracticePrompt() },
      { role: 'user', content: 'Give a single realistic opening line the counterparty would say to begin this negotiation. One sentence.' }
    ], 160, false);
    if (requestToken !== practiceRequestToken) return;
    removePracticeTyping();
    appendPracticeMsg('ai', reply);
    practiceHistory.push({ role: 'assistant', content: reply });
    pushPracticeTranscript('assistant', reply);
    setPracticeStatus('Respond with your opener. Keep it sharp.', 'on');
  } catch(err) {
    if (requestToken !== practiceRequestToken) return;
    removePracticeTyping();
    setPracticeStatus('Open with your line to start practice.', 'idle');
    toast(err.message || 'Could not start practice.');
  }
}

async function practiceSend() {
  const inp = document.getElementById('practiceInput');
  if (!inp) return;
  const text = (inp.value || '').trim();
  if (!text || practiceTyping) return;
  inp.value = ''; inp.style.height = 'auto';
  appendPracticeMsg('user', text);
  practiceHistory.push({ role: 'user', content: text });
  pushPracticeTranscript('user', text);
  practiceTyping = true;
  document.getElementById('practiceSendBtn').disabled = true;
  const requestToken = practiceRequestToken;
  setPracticeStatus('Counterparty is responding...', 'spin');
  showPracticeTyping();
  try {
    const messages = [{ role: 'system', content: getPracticePrompt() }, ...practiceHistory];
    const reply = await secureAPICall(messages, 320, false);
    if (requestToken !== practiceRequestToken) return;
    removePracticeTyping();
    appendPracticeMsg('ai', reply);
    practiceHistory.push({ role: 'assistant', content: reply });
    pushPracticeTranscript('assistant', reply);
    setPracticeStatus('Keep it moving — short, specific turns.', 'on');
  } catch(err) {
    if (requestToken !== practiceRequestToken) return;
    removePracticeTyping();
    appendPracticeMsg('ai', `Practice error: ${err.message}`);
    setPracticeStatus('Try again after fixing the issue.', 'idle');
  }
  if (requestToken !== practiceRequestToken) return;
  practiceTyping = false;
  document.getElementById('practiceSendBtn').disabled = false;
  inp.focus();
}

function goPractice() {
  if (!currentSC) { toast('Choose a scenario first'); return; }
  ensureNegotiationDraft();
  const values = getLiveValues();
  if (currentSC.id === 'custom' && !values.customName && !values.anc.some(Boolean) && !values.batna && !values.zopa) {
    toast('Fill in your custom scenario first');
    generatedOpener = '';
    buildPrep();
    go('s-prep');
    return;
  }
  setPracticeTitles();
  updatePracticeFootnote();
  setPracticeDifficulty(practiceDifficulty);
  go('s-practice');
  resetPractice(false);
  setTimeout(kickoffPractice, 220);
}

function setVoicePracticeTitles() {
  const sceneName = getScenarioSceneName();
  const mobile = document.getElementById('practiceVoiceTitle');
  const desktop = document.getElementById('practiceVoiceTitleSidebar');
  if (mobile) mobile.textContent = sceneName;
  if (desktop) desktop.textContent = sceneName;
}

function updateVoicePracticeFootnote() {
  const p = PROVIDERS[currentProvider];
  const modelLabel = p?.models?.find(m => m.id === currentModel)?.label || currentModel;
  const el = document.getElementById('practiceVoiceFootnote');
  if (el) el.textContent = `Voice practice · OpenAI Realtime · ${modelLabel}`;
}

function appendVoicePracticeMsg(role, text) {
  const msgs = document.getElementById('practiceVoiceHistory');
  if (!msgs) return;
  const wrap = document.createElement('div');
  wrap.className = `practice-msg ${role}`;
  const bubble = document.createElement('div');
  bubble.className = 'practice-bubble';
  renderMultilineText(bubble, text);
  wrap.appendChild(bubble);
  msgs.appendChild(wrap);
  msgs.scrollTop = msgs.scrollHeight;
}

function setVoicePracticeHeadline(text = 'Waiting for the counterparty to speak.') {
  const el = document.getElementById('practiceVoiceHeadline');
  if (el) el.textContent = text;
}

function setVoicePracticeTranscript(finalText = '', interimText = '') {
  const el = document.getElementById('practiceVoiceLiveText');
  if (!el) return;
  el.textContent = [finalText, interimText].filter(Boolean).join(' ').trim();
}

function resetVoicePractice() {
  realtimeMode = 'practice';
  sessionHistory = [];
  micActive = false;
  liveLastAssistantLine = '';
  liveLastAssistantAt = 0;
  resetLiveRealtimeState();
  const history = document.getElementById('practiceVoiceHistory');
  if (history) history.innerHTML = '';
  setVoicePracticeHeadline('Speak naturally. The counterparty will answer in real time.');
  setVoicePracticeTranscript('', '');
  updateVoicePracticeFootnote();
  setVoicePracticeTitles();
  renderPracticeDifficultyChips();
  const hint = document.getElementById('practiceVoiceHint');
  if (hint) hint.textContent = `${PRACTICE_DIFFICULTIES[practiceDifficulty]?.label || 'Neutral'}: ${PRACTICE_DIFFICULTIES[practiceDifficulty]?.stance || ''}`;
  const btn = document.getElementById('practiceVoiceOpenBtn');
  if (btn) btn.disabled = false;
  setS('idle', 'Waiting for microphone...');
}

async function practiceVoiceLetThemOpen() {
  const btn = document.getElementById('practiceVoiceOpenBtn');
  if (btn) btn.disabled = true;
  setS('spin', 'Generating the counterparty opener...');
  try {
    const reply = await secureAPICall([
      { role: 'system', content: getPracticePrompt() },
      { role: 'user', content: 'Give a single realistic opening line the counterparty would say to begin this negotiation. One sentence.' }
    ], 160, false);
    appendVoicePracticeMsg('ai', reply);
    setVoicePracticeHeadline(reply);
    sessionHistory.push({ r: 'them', t: reply });
    refreshRealtimeSession();
    noteAssistantLine(reply);
    queueSpeech(reply);
    setS('on', 'Your turn. Speak naturally.');
  } catch(err) {
    setS('idle', err.message || 'Could not generate the opener.');
    toast(err.message || 'Could not generate opener');
  }
  if (btn) btn.disabled = false;
}

function goVoicePractice() {
  if (!currentSC) { toast('Choose a scenario first'); return; }
  ensureNegotiationDraft();
  const values = getLiveValues();
  if (currentSC.id === 'custom' && !values.customName && !values.anc.some(Boolean) && !values.batna && !values.zopa) {
    toast('Fill in your custom scenario first');
    generatedOpener = '';
    buildPrep();
    go('s-prep');
    return;
  }

  const startupError = getLiveStartupError();
  if (startupError) {
    toast('Voice practice unavailable');
    return;
  }

  const browserWarning = getLiveBrowserWarning();
  if (browserWarning) toast('Best with Chrome and headphones');

  stopMic();
  resetVoicePractice();
  earOn = true;
  syncEarUI();
  go('s-practice-voice');
  setS('spin', browserWarning || 'Starting voice practice...');
  setTimeout(startMic, 420);
}

function analyzeTextPractice() {
  analyzePracticeSession('text');
}

function analyzeLiveSession() {
  analyzePracticeSession('live');
}

function endVoicePractice() {
  stopMic();
  const transcript = getPracticeSessionTranscript('voice');
  if (transcript.length < 2) {
    go('s-practice');
    toast('Voice practice ended');
    return;
  }
  analyzePracticeSession('voice');
}

function replayPracticeReview() {
  const handler = getPracticeReplayHandler();
  if (typeof handler === 'function') handler();
}

// ─────────────────────────────────────────────────────────────────────────────
// PREP SCREEN
// ─────────────────────────────────────────────────────────────────────────────
function buildPrep() {
  const values = ensureNegotiationDraft() || initializeNegotiationDraft(currentSC);
  const sc = currentSC;
  document.getElementById('prepTitle').textContent = getScenarioSceneName();
  const sidebarTitle = document.getElementById('prepTitleSidebar');
  if (sidebarTitle) sidebarTitle.textContent = getScenarioSceneName();
  const wrap = document.getElementById('prepScroll');

  const customRow = sc.id === 'custom' ? `
    <div class="info-card">
      <div class="info-card-label">What are you negotiating?</div>
      <input class="field-input" id="custom-name" value="${escapeHtml(values?.customName || '')}" placeholder="e.g. Contractor rate with new client" style="margin-top:0" autocomplete="off"/>
    </div>` : '';

  const styleRows = Object.entries(NEGOTIATION_STYLES).map(([id, style]) => `
    <button class="style-chip ${id === values?.styleId ? 'active' : ''}" type="button" data-style="${id}">
      <span class="style-chip-title">${style.label}</span>
      <span class="style-chip-sub">${style.sub}</span>
    </button>`).join('');

  const anchorRows = sc.anchors.map((a, i) => `
    <div class="anchor-row">
      <div class="anchor-badge ${i===0?'hi':''}">${a.l}</div>
      <input class="anchor-input ${i===0?'hi':''}" id="anc-${i}" value="${escapeHtml(values?.anc?.[i] || '')}" placeholder="e.g. $150,000"/>
    </div>`).join('');

  wrap.innerHTML = customRow + `
    <div class="info-card">
      <div class="info-card-label">Negotiation style</div>
      <div class="style-chip-grid" id="styleChipGrid">${styleRows}</div>
      <div class="info-hint" id="styleHint">${NEGOTIATION_STYLES[values?.styleId || 'composed'].guidance}</div>
    </div>
    <div class="info-card">
      <div class="info-card-label">Anchors</div>
      ${anchorRows}
      <div class="info-hint">High anchor goes first — always. State it, then go quiet.</div>
    </div>
    <div class="info-card">
      <div class="info-card-label">BATNA — Your best alternative</div>
      <div class="editable-wrap">
        <textarea class="textarea-field" id="batna-field" rows="2" placeholder="What's your best alternative if this deal falls apart?">${escapeHtml(values?.batna || '')}</textarea>
      </div>
      <div class="info-hint">Never negotiate without knowing your walkaway.</div>
    </div>
    <div class="info-card">
      <div class="info-card-label">ZOPA — Zone of possible agreement</div>
      <div class="editable-wrap">
        <textarea class="textarea-field" id="zopa-field" rows="2" placeholder="Estimate their likely range and flexibility.">${escapeHtml(values?.zopa || '')}</textarea>
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
    ta.addEventListener('input', () => {
      ta.style.height = 'auto';
      ta.style.height = ta.scrollHeight + 'px';
      if (ta.id === 'batna-field') updateNegotiationDraft({ batna: ta.value });
      if (ta.id === 'zopa-field') updateNegotiationDraft({ zopa: ta.value });
    });
  });
  wrap.querySelectorAll('.anchor-input').forEach((input, idx) => {
    input.addEventListener('input', () => {
      const nextAnc = getLiveValues().anc;
      nextAnc[idx] = input.value;
      updateNegotiationDraft({ anc: nextAnc });
    });
  });
  const customNameInput = document.getElementById('custom-name');
  if (customNameInput) {
    customNameInput.addEventListener('input', () => {
      updateNegotiationDraft({ customName: customNameInput.value });
      document.getElementById('prepTitle').textContent = getScenarioSceneName();
      const sidebarTitleEl = document.getElementById('prepTitleSidebar');
      if (sidebarTitleEl) sidebarTitleEl.textContent = getScenarioSceneName();
    });
  }
  wrap.querySelectorAll('.style-chip').forEach(btn => {
    btn.addEventListener('click', () => {
      const nextStyle = btn.dataset.style || 'composed';
      updateNegotiationDraft({ styleId: nextStyle });
      wrap.querySelectorAll('.style-chip').forEach(chip => chip.classList.remove('active'));
      btn.classList.add('active');
      const hint = document.getElementById('styleHint');
      if (hint) hint.textContent = NEGOTIATION_STYLES[nextStyle].guidance;
    });
  });
}

function getLiveValues() {
  const values = ensureNegotiationDraft();
  const anc = values?.anc ? values.anc.slice(0, 3) : ['', '', ''];
  while (anc.length < 3) anc.push('');
  const styleId = values?.styleId in NEGOTIATION_STYLES ? values.styleId : 'composed';
  return {
    anc,
    batna: values?.batna || '',
    zopa: values?.zopa || '',
    customName: values?.customName || '',
    styleId
  };
}

function isLocalhost() {
  return ['localhost', '127.0.0.1', '::1'].includes(window.location.hostname);
}

function hasSecureOriginForMedia() {
  return window.isSecureContext || isLocalhost();
}

function getBrowserSupportLevel() {
  const ua = navigator.userAgent || '';
  const isDesktop = !/Android|iPhone|iPad|iPod/i.test(ua);
  const isChromium = /Chrome|CriOS|Edg\//i.test(ua) && !/Firefox|FxiOS/i.test(ua);
  if (isDesktop && isChromium) {
    return 'supported';
  }
  return 'limited';
}

function getLiveStartupError() {
  if (!hasSecureOriginForMedia()) {
    return 'Live mode needs HTTPS or localhost. Run this app through a local server.';
  }
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    return 'This browser cannot access the microphone reliably for live mode.';
  }
  if (!window.RTCPeerConnection) {
    return 'Live mode needs a browser with WebRTC support.';
  }
  return '';
}

function getLiveBrowserWarning() {
  if (getBrowserSupportLevel() === 'supported') return '';
  return 'Live mode works best on Chrome desktop. This browser may be less reliable.';
}

function getRecognitionErrorMessage(code) {
  switch (code) {
    case 'not-allowed':
    case 'service-not-allowed':
      return 'Microphone access was blocked. Allow mic access in Chrome and try again.';
    case 'audio-capture':
      return 'No microphone was found. Check your input device and browser permissions.';
    case 'network':
      return 'Speech recognition hit a network error. Check your connection and try again.';
    case 'aborted':
      return 'Microphone startup was interrupted. Try Live again.';
    case 'no-speech':
      return 'Listening... no speech detected yet.';
    default:
      return 'Speech recognition failed to start.';
  }
}

function getRealtimeCoachContext() {
  const { anc, batna, zopa, customName, styleId } = getLiveValues();
  const sceneName = currentSC?.id === 'custom' ? (customName || currentSC?.name || 'Custom') : (currentSC?.name || 'Custom');
  return {
    scenarioId: currentSC?.id || 'custom',
    sceneName,
    anc,
    batna,
    zopa,
    customName,
    styleId,
    style: NEGOTIATION_STYLES[styleId] || NEGOTIATION_STYLES.composed,
    hist: sessionHistory.slice(-8).map(h => {
      if (h.r === 'them') return `Other party: ${h.t}`;
      if (h.r === 'you') return `You: ${h.t}`;
      return `Coach suggestion: ${h.t}`;
    }).join('\n')
  };
}

function getScenarioLiveOverlay(ctx) {
  if (ctx.scenarioId === 'custom') {
    return `Scenario-specific overlay:
- This is a custom negotiation.
- Who you are in the scene: ${ctx.customName || 'Not specified clearly yet'}
- Your high anchor: ${ctx.anc[0] || 'n/a'}
- Your BATNA: ${ctx.batna || 'n/a'}
- Your likely range: ${ctx.zopa || 'n/a'}
- Never invent a new identity or situation. Stay inside the custom scene above.
- If the scene definition is weak, still answer as the user in that scene, not as an assistant.`;
  }

  const prompt = LIVE_SCENARIO_PROMPTS[ctx.scenarioId];
  if (!prompt) return '';

  return `Scenario-specific overlay:
- ${prompt.role}
- Objective: ${prompt.objective}
- Examples:
${prompt.examples.map(example => `  - ${example}`).join('\n')}`;
}

function buildPracticeVoiceInstructions() {
  const ctx = getRealtimeCoachContext();
  const diff = PRACTICE_DIFFICULTIES[practiceDifficulty] || PRACTICE_DIFFICULTIES.balanced;
  const scPrompt = LIVE_SCENARIO_PROMPTS[ctx.scenarioId] || null;
  const roleLine = scPrompt ? scPrompt.role.replace('You are coaching', 'You are playing') : 'You are the counterparty in this negotiation.';
  const history = sessionHistory.slice(-10).map(turn => {
    if (turn.r === 'you') return `User: ${turn.t}`;
    if (turn.r === 'them') return `Counterparty: ${turn.t}`;
    return '';
  }).filter(Boolean).join('\n');

  return `You are role-playing the COUNTERPARTY in a live voice negotiation practice.

${roleLine}
Scenario: ${ctx.sceneName}
Objective: ${scPrompt?.objective || 'Protect your side while negotiating realistically.'}
Difficulty mode: ${diff.label} (${diff.pressure} pressure). ${diff.stance}
User speaking style: ${ctx.style.label} — ${ctx.style.guidance}
User high anchor: ${ctx.anc[0] || 'n/a'}
User likely target range: ${ctx.anc[1] || 'n/a'} down to ${ctx.anc[2] || 'n/a'}

Rules:
- Stay fully in character as the counterparty.
- Speak like a real human in a live conversation.
- Respond in 1-3 sentences, usually under 28 words total.
- Push back, counter, ask sharp questions, and protect your side.
- Do not mention being an AI, simulation, or exercise.
- Do not narrate. Do not use markdown. Do not output JSON.
- If the user is vague, force specificity.
- If the user gives a number, react commercially instead of stalling.
- Keep the conversation moving. No speeches.
- If there is no prior conversation yet, wait for the user unless they explicitly ask you to open.

${getScenarioLiveOverlay(ctx)}
${history ? `\nRecent exchange:\n${history}` : ''}`;
}

function buildRealtimeInstructions() {
  if (realtimeMode === 'practice') {
    return buildPracticeVoiceInstructions();
  }
  const ctx = getRealtimeCoachContext();
  return `You are an elite real-time negotiation coach with decades of scar tissue across salary talks, procurement fights, hospital billing calls, landlord disputes, agency retainers, executive comp, and high-pressure commercial deals.

You think like a closer, not a chatbot.
You know anchoring, leverage, calibrated pressure, silence, trading, conditional concessions, authority constraints, face-saving, and how to move a counterparty without sounding theatrical.
You coach like someone who has sat through thousands of real negotiations and can hear weakness, drift, over-explaining, and missed leverage instantly.

Return a JSON object with exactly these keys:
{"tag":"TACTIC","line":"Exactly what they should say verbatim","advice":"One sentence of tactical reasoning"}

Global rules:
- Assume the transcript you receive is the OTHER PARTY'S latest turn.
- Your job is to produce only the USER'S next spoken reply.
- You are never the assistant, never an AI, never a negotiator introducing yourself, and never a narrator.
- Never say you are here to help, never say you are an AI coach, and never explain your role.
- Never answer as if you are talking to the user. You are writing the exact line the user should now say out loud to the other party.
- tag: 1-3 words, ALL CAPS
- line: exactly what the user should say next, one strong natural sentence, usually under 16 words
- advice: one tactical sentence, specific and blunt
- no markdown
- no extra keys
- no filler
- line should sound like a real person mid-conversation, not a chatbot
- line must be immediately usable out loud with no editing
- line should preserve leverage, not just politeness
- if the user is asked for a number, terms, or position, answer with a concrete position instead of stalling
- prefer crisp pressure over speeches
- do not over-explain, justify excessively, or soften the ask into mush
- do not invent facts, offers, policies, or credentials that are not in context
- do not escalate emotionally unless the scenario truly calls for it
- if the other party asks a basic opener like "What are you here for?" or "How can I help?", respond inside the scenario immediately
- bad line example: "I'm an AI negotiator here to help you."
- bad line example: "As your coach, I recommend saying..."
- good line example: "I'm here to talk about reducing this bill before it goes any further."
- good line example: "I'm at $148,000."

Coaching doctrine:
- Protect the user's BATNA and never expose their real floor.
- Find the ZOPA without revealing where the user actually breaks.
- Anchor early and with conviction; if they anchor first, re-anchor hard enough to reframe.
- Trade, do not give. Every concession should buy something.
- Use calibrated how and what questions to push problem-solving back onto them.
- Use tactical empathy, mirrors, and labels to lower resistance and surface real constraints.
- Treat silence as leverage. Do not reward pressure with extra words.
- Separate fake urgency from real urgency; slow down when they try to rush.
- Push for specificity when they are vague, emotional, or hiding behind policy.
- Close conditionally: tie the user's give to their commitment.
- Never let the user sound desperate, defensive, over-grateful, or eager to rescue the deal.

Delivery style:
- Selected style: ${ctx.style.label}
- Style guidance: ${ctx.style.guidance}
- Even in warmer styles, keep the line commercially disciplined.

Negotiation: ${ctx.sceneName}
High anchor: ${ctx.anc[0] || 'n/a'}
Mid: ${ctx.anc[1] || 'n/a'}
Floor: ${ctx.anc[2] || 'n/a'}
BATNA: "${ctx.batna || 'n/a'}"
Likely range: "${ctx.zopa || 'n/a'}"

${getScenarioLiveOverlay(ctx)}
${ctx.hist ? `\nRecent exchange:\n${ctx.hist}` : ''}`;
}

function buildLiveSessionUpdateEvent() {
  return {
    type: 'session.update',
    session: {
      type: 'realtime',
      instructions: buildRealtimeInstructions(),
      output_modalities: ['text'],
      max_output_tokens: 220,
      audio: {
        input: {
          transcription: {
            model: 'gpt-4o-mini-transcribe'
          },
          turn_detection: {
            type: 'server_vad',
            create_response: true,
            interrupt_response: true,
            silence_duration_ms: 600,
            idle_timeout_ms: 6000
          }
        }
      }
    }
  };
}

function refreshRealtimeSession() {
  if (!liveDataChannel || liveDataChannel.readyState !== 'open') return;
  liveDataChannel.send(JSON.stringify(buildLiveSessionUpdateEvent()));
}

function parseCoachPayload(text) {
  const clean = (text || '').trim().replace(/```json|```/g, '').trim();
  try {
    const parsed = JSON.parse(clean);
    if (parsed && parsed.tag && parsed.line && parsed.advice) {
      return {
        tag: String(parsed.tag).trim(),
        line: String(parsed.line).trim(),
        advice: String(parsed.advice).trim()
      };
    }
  } catch(_) {}

  const lineMatch = clean.match(/"line"\s*:\s*"([^"]+)"/i) || clean.match(/line\s*:\s*([^\n]+)/i);
  const tagMatch = clean.match(/"tag"\s*:\s*"([^"]+)"/i) || clean.match(/tag\s*:\s*([^\n]+)/i);
  const adviceMatch = clean.match(/"advice"\s*:\s*"([^"]+)"/i) || clean.match(/advice\s*:\s*([^\n]+)/i);

  if (lineMatch) {
    return {
      tag: (tagMatch?.[1] || 'REFRAME').trim().replace(/^["']|["']$/g, ''),
      line: lineMatch[1].trim().replace(/^["']|["']$/g, ''),
      advice: (adviceMatch?.[1] || 'Hold your pace and force the conversation back onto your terms.')
        .trim()
        .replace(/^["']|["']$/g, '')
    };
  }

  return {
    tag: 'REFRAME',
    line: clean || 'Let me think about that for a moment.',
    advice: 'Hold your pace and force the conversation back onto your terms.'
  };
}

function extractTextFromResponseDone(response) {
  const parts = [];
  for (const item of response?.output || []) {
    if (!Array.isArray(item.content)) continue;
    for (const content of item.content) {
      if ((content.type === 'output_text' || content.type === 'text') && content.text) {
        parts.push(content.text);
      }
    }
  }
  return parts.join('\n').trim();
}

function normalizeSpokenText(text) {
  return (text || '')
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

const SPOKEN_FILLER_TOKENS = new Set([
  'a','an','and','are','at','be','but','for','from','got','here','hey','hi','i','im','is',
  'it','its','just','kind','like','me','my','now','of','ok','okay','really','say','so',
  'that','the','their','them','there','this','to','uh','um','we','well','what','with','you',
  'your'
]);

function getMeaningfulTokens(text) {
  return normalizeSpokenText(text)
    .split(' ')
    .filter(token => token && !SPOKEN_FILLER_TOKENS.has(token));
}

function tokenSimilarity(a, b) {
  const aTokens = normalizeSpokenText(a).split(' ').filter(Boolean);
  const bTokens = normalizeSpokenText(b).split(' ').filter(Boolean);
  if (!aTokens.length || !bTokens.length) return 0;

  const aSet = new Set(aTokens);
  const bSet = new Set(bTokens);
  let overlap = 0;
  for (const token of aSet) {
    if (bSet.has(token)) overlap++;
  }

  return overlap / Math.max(aSet.size, bSet.size);
}

function orderedCoverage(spokenTokens, expectedTokens) {
  if (!spokenTokens.length || !expectedTokens.length) return 0;
  let idx = 0;
  for (const token of spokenTokens) {
    if (token === expectedTokens[idx]) idx++;
    if (idx === expectedTokens.length) break;
  }
  return idx / expectedTokens.length;
}

function shouldAutoMarkSaid(transcript) {
  if (!liveCurrentCoach || liveCurrentCoach.delivered) return false;
  const spoken = normalizeSpokenText(transcript);
  const expected = liveCurrentCoach.normalizedLine;
  if (!spoken || !expected) return false;

  const spokenMeaningful = getMeaningfulTokens(transcript);
  const expectedMeaningful = liveCurrentCoach.meaningfulTokens || getMeaningfulTokens(liveCurrentCoach.line);
  const spokenMeaningfulText = spokenMeaningful.join(' ');
  const expectedMeaningfulText = expectedMeaningful.join(' ');
  const containsFull = spoken.includes(expected) || expected.includes(spoken);
  const containsMeaningful = !!expectedMeaningfulText && (
    spokenMeaningfulText.includes(expectedMeaningfulText) ||
    expectedMeaningfulText.includes(spokenMeaningfulText)
  );
  const similarityFull = tokenSimilarity(spoken, expected);
  const similarityMeaningful = expectedMeaningfulText && spokenMeaningfulText
    ? tokenSimilarity(spokenMeaningfulText, expectedMeaningfulText)
    : 0;
  const coverage = orderedCoverage(spokenMeaningful, expectedMeaningful);
  const lengthRatio = Math.min(spoken.length, expected.length) / Math.max(spoken.length, expected.length);
  const meaningfulLengthRatio = expectedMeaningful.length && spokenMeaningful.length
    ? Math.min(spokenMeaningful.length, expectedMeaningful.length) / Math.max(spokenMeaningful.length, expectedMeaningful.length)
    : 0;
  const recentlyCoached = Date.now() - liveCurrentCoach.createdAt < 18000;

  return recentlyCoached && (
    containsFull ||
    containsMeaningful ||
    (similarityFull >= 0.76 && lengthRatio >= 0.7) ||
    (similarityMeaningful >= 0.74 && meaningfulLengthRatio >= 0.58) ||
    (coverage >= 0.84 && meaningfulLengthRatio >= 0.5)
  );
}

function noteAssistantLine(text) {
  liveLastAssistantLine = sanitize(text);
  liveLastAssistantAt = Date.now();
}

function shouldIgnoreAssistantEcho(transcript) {
  if (!liveLastAssistantLine || Date.now() - liveLastAssistantAt > 12000) return false;
  const clean = sanitize(transcript);
  if (!clean) return false;
  const similarity = tokenSimilarity(clean, liveLastAssistantLine);
  const coverage = orderedCoverage(getMeaningfulTokens(clean), getMeaningfulTokens(liveLastAssistantLine));
  return similarity >= 0.78 || coverage >= 0.84;
}

function resetLiveRealtimeState() {
  liveTranscriptDrafts = new Map();
  liveResponseBuffer = '';
  processing = false;
  liveCurrentCoach = null;
  liveLastAssistantLine = '';
  liveLastAssistantAt = 0;
  if (pendingSpeechTimer) {
    clearTimeout(pendingSpeechTimer);
    pendingSpeechTimer = null;
  }
}

function handleRealtimeError(message, toastMessage = 'Live error') {
  setS('idle', message);
  toast(toastMessage);
}

function queueTranscriptTurn(transcript) {
  const cleanTurn = sanitize(transcript);
  if (!cleanTurn || cleanTurn.length < 4) {
    setS('on', realtimeMode === 'practice' ? 'Listening for you...' : 'Listening...');
    return;
  }

  if (realtimeMode === 'practice') {
    if (shouldIgnoreAssistantEcho(cleanTurn)) {
      setS('on', 'Listening for you...');
      return;
    }
    appendVoicePracticeMsg('user', cleanTurn);
    sessionHistory.push({ r: 'you', t: cleanTurn });
    setVoicePracticeTranscript('', '');
    setVoicePracticeHeadline('Counterparty is responding...');
    return;
  }

  if (shouldAutoMarkSaid(cleanTurn)) {
    markSaid(true, cleanTurn);
    return;
  }

  pushBubble(cleanTurn);
  sessionHistory.push({ r: 'them', t: cleanTurn });
  setTx('', '');
}

function finalizeRealtimeResponse() {
  if (!liveResponseBuffer.trim()) {
    processing = false;
    setS('on', realtimeMode === 'practice' ? 'Listening for you...' : 'Listening...');
    return;
  }
  if (realtimeMode === 'practice') {
    const reply = liveResponseBuffer.trim();
    appendVoicePracticeMsg('ai', reply);
    sessionHistory.push({ r: 'them', t: reply });
    setVoicePracticeHeadline(reply);
    noteAssistantLine(reply);
    queueSpeech(reply);
    liveResponseBuffer = '';
    processing = false;
    setS('on', 'Listening for you...');
    return;
  }
  const parsed = parseCoachPayload(liveResponseBuffer);
  showCoach(parsed);
  sessionHistory.push({ r: 'coach', t: parsed.line });
  queueSpeech(parsed.line);
  liveResponseBuffer = '';
  processing = false;
  setS('on', 'Listening...');
}

function handleRealtimeMessage(raw) {
  let event;
  try {
    event = JSON.parse(raw.data);
  } catch(_) {
    return;
  }

  switch (event.type) {
    case 'session.created':
      console.debug('[live]', event.type, event);
      break;
    case 'session.updated':
      console.debug('[live]', event.type, event);
      setS('on', realtimeMode === 'practice' ? 'Listening for you...' : 'Listening...');
      break;
    case 'input_audio_buffer.speech_started':
      if (pendingSpeechTimer) {
        clearTimeout(pendingSpeechTimer);
        pendingSpeechTimer = null;
      }
      stopSpeech();
      setS('on', realtimeMode === 'practice' ? 'Listening to you...' : 'Hearing them...');
      break;
    case 'input_audio_buffer.speech_stopped':
      setS('spin', realtimeMode === 'practice' ? 'Transcribing your line...' : 'Transcribing...');
      processing = true;
      break;
    case 'conversation.item.input_audio_transcription.delta': {
      const nextDraft = (liveTranscriptDrafts.get(event.item_id) || '') + (event.delta || '');
      liveTranscriptDrafts.set(event.item_id, nextDraft);
      setTx('', nextDraft.trim());
      break;
    }
    case 'conversation.item.input_audio_transcription.completed': {
      const transcript = (event.transcript || liveTranscriptDrafts.get(event.item_id) || '').trim();
      liveTranscriptDrafts.delete(event.item_id);
      queueTranscriptTurn(transcript);
      break;
    }
    case 'conversation.item.input_audio_transcription.failed': {
      liveTranscriptDrafts.delete(event.item_id);
      processing = false;
      const message = event.error?.message || 'The speech could not be transcribed.';
      handleRealtimeError(message, 'Transcription failed');
      break;
    }
    case 'response.created':
      console.debug('[live]', event.type, event);
      liveResponseBuffer = '';
      processing = true;
      break;
    case 'response.output_item.done': {
      if (!liveResponseBuffer.trim() && Array.isArray(event.item?.content)) {
        for (const content of event.item.content) {
          if ((content.type === 'output_text' || content.type === 'text') && content.text) {
            liveResponseBuffer += content.text;
          }
        }
      }
      break;
    }
    case 'response.output_text.delta':
      liveResponseBuffer += event.delta || '';
      break;
    case 'response.output_text.done':
      liveResponseBuffer += event.text || '';
      break;
    case 'response.done':
      if (event.response?.status && event.response.status !== 'completed') {
        processing = false;
        const message = event.response?.status_details?.error?.message
          || event.response?.status_details?.reason
          || `The live response ended with status: ${event.response.status}.`;
        handleRealtimeError(message, 'Response failed');
        break;
      }
      if (!liveResponseBuffer.trim()) {
        liveResponseBuffer = extractTextFromResponseDone(event.response);
      }
      finalizeRealtimeResponse();
      break;
    case 'error': {
      console.debug('[live]', event.type, event);
      processing = false;
      const message = event.error?.message || 'The realtime session failed.';
      handleRealtimeError(message, 'Realtime error');
      break;
    }
    default:
      if (!/^rate_limits|^input_audio_buffer/.test(event.type)) {
        console.debug('[live]', event.type, event);
      }
      break;
  }
}

async function generateOpener() {
  const genBtn   = document.getElementById('openerGenBtn');
  const regenBtn = document.getElementById('openerRegenBtn');
  const box      = document.getElementById('openerBox');
  if (!genBtn || !box) return;
  genBtn.disabled = true;
  box.textContent = '';
  const loading = document.createElement('div');
  loading.className = 'opener-loading';
  const spinner = document.createElement('div');
  spinner.className = 'opener-spinner';
  const loadingText = document.createElement('div');
  loadingText.className = 'opener-loading-text';
  loadingText.textContent = 'Generating your line…';
  loading.appendChild(spinner);
  loading.appendChild(loadingText);
  box.appendChild(loading);
  const { anc, batna, customName, styleId } = getLiveValues();
  const sceneName = currentSC?.id === 'custom' ? (customName || currentSC?.name || 'Custom') : (currentSC?.name || 'Custom');
  const style = NEGOTIATION_STYLES[styleId] || NEGOTIATION_STYLES.composed;
  try {
    const content = await secureAPICall([
      {
        role: 'system',
        content: `You are an elite negotiation coach. Generate the opening line for a negotiation.

RULES — follow exactly:
- Max 15 words. Ideal: 8–12 words.
- State the High anchor FIRST. One number only — no ranges.
- NO: "thank you", "I appreciate", "based on my experience", "because", "I was thinking/hoping"
- NO ranges (e.g. "between X and Y")
- Sound like a confident human, not a robot
- Match this style: ${style.label} — ${style.guidance}
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
    box.textContent = '';
    const openerText = document.createElement('div');
    openerText.className = 'opener-text';
    openerText.textContent = generatedOpener;
    const openerHint = document.createElement('div');
    openerHint.className = 'opener-hint';
    openerHint.textContent = 'Say this first. Then stop talking.';
    box.appendChild(openerText);
    box.appendChild(openerHint);
    genBtn.style.display = 'none';
    regenBtn.style.display = 'block';
  } catch(err) {
    box.textContent = '';
    const openerError = document.createElement('div');
    openerError.className = 'opener-empty';
    openerError.textContent = err.message;
    box.appendChild(openerError);
    genBtn.disabled = false;
  }
}

function goLive() {
  realtimeMode = 'coach';
  const startupError = getLiveStartupError();
  if (startupError) {
    setS('idle', startupError);
    toast('Live mode unavailable');
    return;
  }
  const browserWarning = getLiveBrowserWarning();
  if (browserWarning) {
    toast('Best on Chrome desktop');
  }
  stopMic();
  resetLive();
  const { customName } = getLiveValues();
  const sceneName = currentSC?.id === 'custom' ? (customName || currentSC?.name || 'Custom') : (currentSC?.name || 'Custom');
  document.getElementById('liveScene').textContent = sceneName;
  const sidebarScene = document.getElementById('liveSceneSidebar');
  if (sidebarScene) sidebarScene.textContent = sceneName;
  earOn = true;
  syncEarUI();
  go('s-live');
  setS('spin', browserWarning || 'Starting microphone...');
  setTimeout(startMic, 420);
}

function resetLive() {
  realtimeMode = 'coach';
  sessionHistory = []; micActive = false;
  resetLiveRealtimeState();
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
  if (realtimeMode === 'practice') {
    inlineConfirm(
      btn || document.getElementById('practiceVoiceEndBtn'),
      () => {
        endVoicePractice();
      },
      { yesLabel: 'End', yesClass: 'danger' }
    );
    return;
  }
  // Fallback: if called without a button reference, find first end-btn
  const target = btn || document.getElementById('endBtn') || document.querySelector('.end-btn');
  inlineConfirm(
    target,
    () => {
      stopMic();
      earOn = true;
      const transcript = getPracticeSessionTranscript('live');
      if (transcript.length < 2) {
        setTimeout(() => go('s-home'), 50);
        toast('Live session ended');
        return;
      }
      setTimeout(() => analyzeLiveSession(), 50);
    },
    { yesLabel: 'End', yesClass: 'danger' }
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// MIC
// ─────────────────────────────────────────────────────────────────────────────
async function startMic() {
  const startupError = getLiveStartupError();
  if (startupError) {
    setS('idle', startupError);
    return;
  }

  try {
    liveAudioStream = await navigator.mediaDevices.getUserMedia({
      audio: {
        channelCount: 1,
        echoCancellation: true,
        noiseSuppression: true,
        autoGainControl: true
      },
      video: false
    });
  } catch(err) {
    setS('idle', getRecognitionErrorMessage(err?.name === 'NotAllowedError' ? 'not-allowed' : 'audio-capture'));
    return;
  }

  try {
    startVol(liveAudioStream);

    livePeer = new RTCPeerConnection();
    liveDataChannel = livePeer.createDataChannel('oai-events');
    liveDataChannel.addEventListener('open', () => {
      liveDataChannel.send(JSON.stringify(buildLiveSessionUpdateEvent()));
      setS('spin', realtimeMode === 'practice' ? 'Configuring counterparty...' : 'Configuring live coach...');
    });
    liveDataChannel.addEventListener('message', handleRealtimeMessage);
    liveDataChannel.addEventListener('close', () => {
      if (micActive) handleRealtimeError('Live connection closed. Start Live again.', 'Connection closed');
    });
    liveDataChannel.addEventListener('error', () => handleRealtimeError('Live data channel failed.', 'Channel error'));

    livePeer.addEventListener('connectionstatechange', () => {
      if (['failed', 'disconnected', 'closed'].includes(livePeer.connectionState) && micActive) {
        handleRealtimeError('Realtime connection dropped. Start Live again.', 'Connection dropped');
      }
    });

    liveAudioStream.getTracks().forEach(track => livePeer.addTrack(track, liveAudioStream));

    const offer = await livePeer.createOffer();
    await livePeer.setLocalDescription(offer);

    const liveHeaders = { 'Content-Type': 'application/sdp' };
    if (currentProvider === 'openai' && SecureStore.has()) {
      liveHeaders['X-OpenAI-Key'] = SecureStore.get();
    }

    const response = await fetch('/api/live/call', {
      method: 'POST',
      headers: liveHeaders,
      body: offer.sdp
    });

    if (!response.ok) {
      let message = 'Could not start the realtime session.';
      try {
        const err = await response.json();
        message = err.error || message;
      } catch(_) {}
      throw new Error(message);
    }

    const answerSdp = await response.text();
    await livePeer.setRemoteDescription({ type: 'answer', sdp: answerSdp });
    micActive = true;
    setS('spin', realtimeMode === 'practice' ? 'Connecting voice practice...' : 'Connecting to realtime coach...');
  } catch(err) {
    stopMic();
    handleRealtimeError(err.message || 'Could not start the realtime coach.', 'Live start failed');
  }
}

function stopMic() {
  micActive = false;
  resetLiveRealtimeState();
  stopSpeech();
  if (liveDataChannel) {
    try { liveDataChannel.close(); } catch(_) {}
    liveDataChannel = null;
  }
  if (livePeer) {
    try { livePeer.close(); } catch(_) {}
    livePeer = null;
  }
  if (audioCtx) { try { audioCtx.close(); } catch(e) {} audioCtx = null; }
  if (liveAudioStream) {
    liveAudioStream.getTracks().forEach(track => track.stop());
    liveAudioStream = null;
  }
  analyser = null;
  if (animId)   { cancelAnimationFrame(animId); animId = null; }
}

function startVol(stream) {
  if (!stream) return;
  if (audioCtx) { try { audioCtx.close(); } catch(_) {} }
  try {
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    analyser = audioCtx.createAnalyser(); analyser.fftSize = 128;
    audioCtx.createMediaStreamSource(stream).connect(analyser);
    const data = new Uint8Array(analyser.frequencyBinCount);
    const bars = document.querySelectorAll(realtimeMode === 'practice' ? '.pvb' : '.vb');
    function tick() {
      if (!analyser) return;
      analyser.getByteFrequencyData(data);
      const avg = data.reduce((a,b) => a+b, 0) / data.length;
      bars.forEach((b,i) => b.classList.toggle('lit', avg > (i+1)*4));
      animId = requestAnimationFrame(tick);
    }
    tick();
  } catch(_) {
    toast('Volume meter unavailable');
  }
}

function setTx(fin, int) {
  const live = document.getElementById(realtimeMode === 'practice' ? 'practiceVoiceLiveText' : 'tLive');
  if (!live) return;
  live.textContent = '';
  const finalSpan = document.createElement('span');
  finalSpan.textContent = fin || '';
  live.appendChild(finalSpan);
  if (int) {
    const interimSpan = document.createElement('span');
    interimSpan.className = 't-interim';
    interimSpan.textContent = ` ${int}`;
    live.appendChild(interimSpan);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// COACHING
// ─────────────────────────────────────────────────────────────────────────────
function showCoach({ tag, line, advice }) {
  document.getElementById('cIdle').style.display = 'none';
  document.getElementById('cTag').textContent = tag;
  document.getElementById('cLine').textContent = `"${line}"`;
  document.getElementById('cAdvice').textContent = advice;
  liveCurrentCoach = {
    tag,
    line,
    advice,
    normalizedLine: normalizeSpokenText(line),
    meaningfulTokens: getMeaningfulTokens(line),
    createdAt: Date.now(),
    delivered: false
  };
  const r = document.getElementById('cResult');
  r.classList.remove('show'); void r.offsetWidth; r.classList.add('show');
  document.getElementById('coachCard').classList.add('live');
}

function markSaid(auto = false, deliveredLine = '') {
  if (liveCurrentCoach && !liveCurrentCoach.delivered) {
    const finalLine = sanitize(deliveredLine) || liveCurrentCoach.line;
    sessionHistory.push({ r: 'you', t: finalLine });
    liveCurrentCoach.delivered = true;
  }
  document.getElementById('cResult').classList.remove('show');
  document.getElementById('coachCard').classList.remove('live');
  setTimeout(() => document.getElementById('cIdle').style.display = 'flex', 220);
  setS('on', auto ? 'Delivered. Listening for their reply...' : 'Good. Listening for their reply...');
  toast(auto ? 'Marked as said' : 'Logged');
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
function stopSpeech() {
  if (pendingSpeechTimer) {
    clearTimeout(pendingSpeechTimer);
    pendingSpeechTimer = null;
  }
  if (!window.speechSynthesis) return;
  window.speechSynthesis.cancel();
}

function queueSpeech(text) {
  if (!earOn) return;
  stopSpeech();
  pendingSpeechTimer = setTimeout(() => {
    pendingSpeechTimer = null;
    speak(text);
  }, 320);
}

function speak(text) {
  if (!window.speechSynthesis || !earOn) return;
  window.speechSynthesis.cancel();
  const u = new SpeechSynthesisUtterance(text);
  u.rate = 1.06; u.pitch = 1; u.volume = 1;
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
  const pv = document.getElementById('practiceVoiceEarBtn');
  if (pv) { pv.textContent = on ? 'VOICE ON' : 'VOICE OFF'; pv.classList.toggle('on', on); }
}

function toggleEar() {
  earOn = !earOn;
  if (!earOn) stopSpeech();
  syncEarUI();
  toast(earOn ? 'Earpiece on' : 'Earpiece off');
}

// ─────────────────────────────────────────────────────────────────────────────
// STATUS & TOAST
// ─────────────────────────────────────────────────────────────────────────────
function setS(state, msg) {
  const dotId = realtimeMode === 'practice' ? 'practiceVoiceStatusDot' : 'sDot';
  const textId = realtimeMode === 'practice' ? 'practiceVoiceStatusText' : 'sText';
  const d = document.getElementById(dotId);
  const t = document.getElementById(textId);
  if (!d || !t) return;
  d.className = 's-dot' + (state==='on'?' on':state==='spin'?' spin':'');
  t.textContent = msg;
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
  renderMultilineText(bubble, text);
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
  initializeNegotiationDraft(filled, {
    anc: (fill.anchors || sc.anchors || []).map(anchor => anchor?.v || ''),
    batna: fill.batna || sc.batna || '',
    zopa: fill.zopa || sc.zopa || '',
    customName: fill.id === 'custom' ? (fill.customName || '') : ''
  });
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
  const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  icon.setAttribute('width', '16');
  icon.setAttribute('height', '16');
  icon.setAttribute('viewBox', '0 0 16 16');
  icon.setAttribute('fill', 'none');
  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('d', 'M13 8A5 5 0 113 8a5 5 0 0110 0zm-5-2v4m0 0l-1.5-1.5M8 10l1.5-1.5');
  path.setAttribute('stroke', '#fff');
  path.setAttribute('stroke-width', '1.5');
  path.setAttribute('stroke-linecap', 'round');
  icon.appendChild(path);

  const text = document.createElement('span');
  text.append('Prep brief ready: ');
  const strong = document.createElement('strong');
  strong.textContent = scenarioName;
  text.appendChild(strong);

  const button = document.createElement('button');
  button.className = 'chat-redirect-btn';
  button.type = 'button';
  button.textContent = 'Go to Prep →';
  button.addEventListener('click', launchFromChat);

  banner.appendChild(icon);
  banner.appendChild(text);
  banner.appendChild(button);
  chatView.insertBefore(banner, inputArea);
}

function launchFromChat() {
  if (!currentSC) return;
  ensureNegotiationDraft();
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

(function initPracticeInput() {
  const ta = document.getElementById('practiceInput');
  if (!ta) return;
  ta.addEventListener('input', () => {
    ta.style.height = 'auto';
    ta.style.height = Math.min(ta.scrollHeight, 120) + 'px';
  });
  ta.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); practiceSend(); }
  });
})();

// ─────────────────────────────────────────────────────────────────────────────
// CLEANUP
// ─────────────────────────────────────────────────────────────────────────────
window.addEventListener('beforeunload', () => SecureStore.clear());
