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
    supported: true,
    name: 'OpenAI', placeholder: 'sk-proj-... or sk-...',
    note: 'Key sent directly to api.openai.com — never stored or logged.',
    models: [
      { id: 'gpt-4.1-mini', label: 'GPT-4.1 Mini', badge: 'best default' },
      { id: 'gpt-4.1',      label: 'GPT-4.1',      badge: 'best text quality' },
      { id: 'gpt-4o',       label: 'GPT-4o',       badge: 'premium all-rounder' },
      { id: 'gpt-4o-mini',  label: 'GPT-4o Mini',  badge: 'budget all-rounder' },
      { id: 'gpt-4.1-nano', label: 'GPT-4.1 Nano', badge: 'ultra cheap' },
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
    supported: false,
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
    supported: false,
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
    supported: false,
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
    supported: false,
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
  const p = PROVIDERS[currentProvider];
  if (!p) throw new Error('Unknown provider.');
  if (!p.supported) throw new Error(`${p.name} support is coming soon. Use OpenAI for now.`);
  if (!key) {
    if (currentProvider === 'openai' && authState.authenticated && (accountHasSavedOpenAIKey() || featureEnabled('hostedKeyAvailable'))) {
      RateLimit.record();
      return proxySavedOpenAIChat(messages, maxTokens, jsonMode);
    }
    throw new Error(authState.authenticated ? 'Add a saved OpenAI key or use a plan with hosted key access.' : 'Sign in first.');
  }
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

async function proxySavedOpenAIChat(messages, maxTokens = 200, jsonMode = false) {
  let res;
  try {
    res = await fetch('/api/openai/chat', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messages,
        maxTokens,
        jsonMode,
        model: currentModel
      })
    });
  } catch (_) {
    throw new Error('Network error — check your connection.');
  }
  let data = {};
  try {
    data = await res.json();
  } catch (_) {}
  if (!res.ok) throw new Error(data?.error || 'Could not use the saved account key.');
  const content = String(data?.content || '').trim();
  if (!content) throw new Error('Empty response from API.');
  return content;
}

// ─────────────────────────────────────────────────────────────────────────────
// KEY VERIFICATION
// ─────────────────────────────────────────────────────────────────────────────
async function verifyKey(key, provider) {
  const p = PROVIDERS[provider];
  if (!p?.supported) throw new Error(`${p?.name || 'This provider'} support is coming soon. Use OpenAI for now.`);
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
const FREE_SCENARIO_IDS = new Set(['salary', 'rent', 'car']);
const PRO_SCENARIO_IDS = new Set([
  'salary', 'rent', 'car', 'freelance', 'joboffer', 'biz', 'severance', 'medical',
  'realestate', 'equity', 'agency', 'raise'
]);

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
let practiceReviewState = null;
let liveRealtimeModel = 'gpt-realtime';
let activeRunId = '';
let pendingNavTimer = 0;
let pendingAccountFocus = '';
let authMode = 'signin';
let authState = {
  configured: false,
  checked: false,
  authenticated: false,
  user: null,
  account: null
};

const REALTIME_MODELS = {
  'gpt-realtime': {
    label: 'GPT Realtime',
    sub: 'best live quality'
  },
  'gpt-realtime-mini': {
    label: 'GPT Realtime Mini',
    sub: 'cheaper live tier'
  }
};

const SESSION_STATE_KEY = 'gc-session-v1';
const SCREEN_ROUTE_MAP = {
  's-launch': 'launch',
  's-key': 'key',
  's-auth': 'auth',
  's-plans': 'plans',
  's-home': 'home',
  's-prep': 'prep',
  's-practice': 'practice',
  's-practice-voice': 'practice-voice',
  's-practice-review': 'review',
  's-live': 'live',
  's-chat': 'chat'
};
const ROUTE_SCREEN_MAP = Object.fromEntries(
  Object.entries(SCREEN_ROUTE_MAP).map(([screen, route]) => [route, screen])
);
let sessionPersistInterval = null;
let isRestoringSession = false;

function getActiveScreenId() {
  return document.querySelector('.screen.active')?.id || 's-launch';
}

function getRouteForScreen(screenId) {
  return SCREEN_ROUTE_MAP[screenId] || 'launch';
}

function getRealtimeModelMeta(modelId = liveRealtimeModel) {
  return REALTIME_MODELS[modelId] || REALTIME_MODELS['gpt-realtime'];
}

function getScreenForRoute(hashValue = window.location.hash) {
  const route = String(hashValue || '').replace(/^#/, '').trim();
  return ROUTE_SCREEN_MAP[route] || '';
}

function updateRouteHash(screenId, replace = false) {
  const route = getRouteForScreen(screenId);
  const nextHash = `#${route}`;
  if (window.location.hash === nextHash) return;
  if (replace) {
    window.history.replaceState(null, '', nextHash);
  } else {
    window.history.pushState(null, '', nextHash);
  }
}

function cloneJsonSafe(value, fallback) {
  try {
    return JSON.parse(JSON.stringify(value));
  } catch (_) {
    return fallback;
  }
}

function normalizeScenarioAnchors(anchors, fallback = []) {
  const source = Array.isArray(anchors) && anchors.length ? anchors : fallback;
  return source.map((anchor, idx) => ({
    l: String(anchor?.l || fallback[idx]?.l || ['High', 'Mid', 'Floor'][idx] || `Anchor ${idx + 1}`).trim(),
    v: String(anchor?.v || '').trim()
  })).slice(0, 3);
}

function hydrateScenario(savedScenario) {
  if (!savedScenario || typeof savedScenario !== 'object') return null;
  const base = LIBRARY.find(sc => sc.id === savedScenario.id) || LIBRARY.find(sc => sc.id === 'custom');
  if (!base) return null;
  return {
    ...base,
    ...savedScenario,
    id: savedScenario.id || base.id,
    name: String(savedScenario.name || base.name || 'Custom').trim(),
    sub: String(savedScenario.sub || base.sub || '').trim(),
    anchors: normalizeScenarioAnchors(savedScenario.anchors, base.anchors),
    batna: String(savedScenario.batna || base.batna || '').trim(),
    zopa: String(savedScenario.zopa || base.zopa || '').trim()
  };
}

function syncSelectedScenarioCard() {
  document.querySelectorAll('.scenario-card').forEach((card, idx) => {
    const scenario = LIBRARY[idx];
    const locked = isScenarioLocked(scenario);
    card.classList.toggle('locked', locked);
    card.classList.toggle('selected', !locked && !!currentSC && scenario?.id === currentSC.id);
    card.setAttribute('aria-disabled', locked ? 'true' : 'false');

    const gate = card.querySelector('.sc-gate');
    const lockCopy = card.querySelector('.sc-lock-copy');
    const affordance = card.querySelector('.sc-arr');
    if (gate) {
      gate.hidden = !locked;
      gate.textContent = getScenarioRequiredPlanLabel(scenario);
    }
    if (lockCopy) {
      lockCopy.hidden = !locked;
      lockCopy.textContent = `${getScenarioRequiredPlanLabel(scenario)} plan required for ${scenario?.name || 'this scenario'}.`;
    }
    if (affordance) affordance.innerHTML = locked ? '' : '&#8250;';
  });
}

function isScenarioLocked(sc) {
  if (!sc?.id) return true;
  if (!authState.authenticated) return true;
  return !getAccessState().allowedScenarioIds.includes(sc.id);
}

function enforceScenarioAccess() {
  if (!isScenarioLocked(currentSC)) return true;
  currentSC = null;
  negotiationDraft = null;
  generatedOpener = '';
  return false;
}

function renderScenarioAccessState() {
  const banner = document.getElementById('homeAccessBanner');
  const bannerTitle = document.getElementById('homeAccessBannerTitle');
  const bannerSub = document.getElementById('homeAccessBannerSub');
  const bannerBtn = document.getElementById('homeAccessBannerBtn');
  const access = getAccessState();
  if (banner) banner.hidden = !authState.authenticated;
  if (bannerTitle) {
    bannerTitle.textContent = access.planCode === 'free'
      ? 'Free account: 3 scenarios and 3 live sessions each month.'
      : access.planCode === 'exotic'
        ? 'Exotic account: every Cue feature unlocked.'
        : 'Pro account: full scenario library with debriefs and unlimited live access.';
  }
  if (bannerSub) {
    if (access.planCode === 'free') {
      if (access.activeLiveSession?.expiresAt) {
        bannerSub.textContent = `A live window is active until ${formatDateTimeShort(access.activeLiveSession.expiresAt)}. Reopening Live before then does not use another session.`;
      } else {
        const sessionsLeft = access.sessionsRemaining ?? 0;
        bannerSub.textContent = `${sessionsLeft} live session${sessionsLeft === 1 ? '' : 's'} left this month. Practice mode stays unlimited.`;
      }
    } else if (access.planCode === 'exotic') {
      bannerSub.textContent = 'AI brief builder, custom scenarios, and win/loss analysis are live on this account.';
    } else {
      bannerSub.textContent = 'Full standard library, debriefs, and unlimited live access are active. Upgrade to Exotic for custom scenarios and strategy brief automation.';
    }
  }
  if (bannerBtn) {
    bannerBtn.textContent = access.planCode === 'free' ? 'Upgrade Plan' : access.planCode === 'pro' ? 'See Exotic' : 'Manage Plan';
    bannerBtn.onclick = () => openPlansScreen();
  }
  enforceScenarioAccess();
  syncSelectedScenarioCard();
}

async function promptScenarioAccess(sc) {
  const name = sc?.name || 'this scenario';
  const requiredPlan = getScenarioRequiredPlanLabel(sc);
  const confirmed = await showModal({
    title: `${requiredPlan} required`,
    body: `${name} is part of the ${requiredPlan} plan. Upgrade this account to use it.`,
    confirmText: 'See Plans'
  });
  if (confirmed) openPlansScreen();
}

function buildSessionSnapshot() {
  return {
    version: 1,
    activeScreen: getActiveScreenId(),
    currentProvider,
    currentModel,
    apiKey: SecureStore.get(),
    currentSC: cloneJsonSafe(currentSC, null),
    currentNegotiationStyle,
    negotiationDraft: cloneJsonSafe(negotiationDraft, null),
    generatedOpener,
    activeRunId,
    practiceDifficulty,
    practiceHistory: cloneJsonSafe(practiceHistory, []),
    practiceTranscript: cloneJsonSafe(practiceTranscript, []),
    sessionHistory: cloneJsonSafe(sessionHistory, []),
    liveCurrentCoach: cloneJsonSafe(liveCurrentCoach, null),
    practiceReviewContext: cloneJsonSafe(practiceReviewContext, null),
    practiceReviewState: cloneJsonSafe(practiceReviewState, null),
    chatHistory: cloneJsonSafe(chatHistory, []),
    chatBot,
    chatMobileHasBot,
    earOn,
    realtimeMode,
    liveRealtimeModel
  };
}

function persistSessionState() {
  if (isRestoringSession) return;
  try {
    window.sessionStorage.setItem(SESSION_STATE_KEY, JSON.stringify(buildSessionSnapshot()));
  } catch (_) {}
}

function loadSessionSnapshot() {
  try {
    const raw = window.sessionStorage.getItem(SESSION_STATE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch (_) {
    return null;
  }
}

function startSessionPersistence() {
  if (sessionPersistInterval) window.clearInterval(sessionPersistInterval);
  sessionPersistInterval = window.setInterval(persistSessionState, 1200);
  window.addEventListener('pagehide', persistSessionState);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') persistSessionState();
  });
}

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
    div.dataset.scenarioId = sc.id;
    div.innerHTML = `
      <div class="sc-text">
        <div class="sc-head">
          <div class="sc-name">${sc.name}</div>
          <div class="sc-gate" hidden>Account</div>
        </div>
        <div class="sc-sub">${sc.sub}</div>
        <div class="sc-lock-copy" hidden>Unlock with a free account to use this scenario.</div>
      </div>
      <div class="sc-arr">&#8250;</div>`;
    div.addEventListener('click', () => pickSC(div, sc));
    list.appendChild(div);
  });
  renderScenarioAccessState();
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
    btn.onclick = () => closeModal(true);
    document.getElementById('modalOverlay').classList.add('show');
  });
}
function closeModal(confirmed = false) {
  document.getElementById('modalOverlay').classList.remove('show');
  if (_modalResolve) {
    const resolve = _modalResolve;
    _modalResolve = null;
    resolve(!!confirmed);
  }
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

function setAuthStatus(message = '', kind = '') {
  const el = document.getElementById('authStatus');
  if (!el) return;
  el.textContent = message;
  el.className = 'key-verify-status' + (kind ? ` ${kind}` : '');
}

function setAccountSettingsStatus(message = '', kind = '') {
  const el = document.getElementById('accountSettingsStatus');
  if (!el) return;
  el.textContent = message;
  el.className = 'key-verify-status' + (kind ? ` ${kind}` : '');
}

function accountHasSavedOpenAIKey() {
  return authState.authenticated && authState.account?.savedKey?.provider === 'openai';
}

function getAuthDisplayCopy() {
  const displayName = String(authState.account?.displayName || authState.user?.displayName || '').trim();
  if (displayName) return displayName;
  const email = String(authState.account?.email || authState.user?.email || '').trim();
  return email ? email.split('@')[0].slice(0, 14) : 'Account';
}

function getBillingState() {
  return authState.account?.billing || {
    enabled: false,
    planTier: 'free',
    planStatus: 'inactive',
    planName: 'Free',
    planCode: '',
    currentPeriodEnd: null,
    canManage: false,
    isPaid: false
  };
}

function getAccessState() {
  return authState.account?.access || {
    planCode: 'free',
    planLabel: 'Free',
    sessionLimit: 3,
    sessionsUsedThisMonth: 0,
    sessionsRemaining: 3,
    allowedScenarioIds: [...FREE_SCENARIO_IDS],
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
      dedicatedSupport: false,
      hostedKeyEligible: false,
      hostedKeyAvailable: false
    },
    canStartSession: true,
    requiresSavedKey: true,
    hasSavedKey: false,
    activeLiveSession: null
  };
}

function hasAppAccessCredential() {
  const access = getAccessState();
  return authState.authenticated && (SecureStore.has() || accountHasSavedOpenAIKey() || access.features.hostedKeyAvailable);
}

function getSignedInDefaultScreen() {
  return 's-home';
}

function getDefaultEntryScreen() {
  return authState.authenticated ? getSignedInDefaultScreen() : 's-launch';
}

function getScenarioRequiredPlan(sc) {
  if (!sc?.id) return 'free';
  if (sc.id === 'custom') return 'exotic';
  if (FREE_SCENARIO_IDS.has(sc.id)) return 'free';
  return 'pro';
}

function getScenarioRequiredPlanLabel(sc) {
  const required = getScenarioRequiredPlan(sc);
  return required === 'exotic' ? 'Exotic' : required === 'pro' ? 'Pro' : 'Free';
}

function featureEnabled(feature) {
  return !!getAccessState().features?.[feature];
}

function canStartAnySession() {
  return !!getAccessState().canStartSession;
}

function formatBillingStatusLabel(status) {
  const value = String(status || '').trim().toLowerCase();
  if (value === 'active') return 'Active';
  if (value === 'trialing') return 'Trialing';
  if (value === 'past_due') return 'Past Due';
  if (value === 'canceled') return 'Canceled';
  return 'Inactive';
}

function formatBillingPeriodEnd(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric'
  });
}

function formatDateTimeShort(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit'
  });
}

function setPlansStatus(message = '', kind = '') {
  const el = document.getElementById('plansStatus');
  if (!el) return;
  el.textContent = message;
  el.className = 'key-verify-status' + (kind ? ` ${kind}` : '');
}

function setPlanButtonsDisabled(disabled) {
  ['planBtnFree', 'planBtnPro', 'planBtnExotic', 'plansManageBtn', 'plansRefreshBtn'].forEach(id => {
    const btn = document.getElementById(id);
    if (btn) btn.disabled = !!disabled;
  });
}

function formatSavedKeyTimestamp(value) {
  if (!value) return 'Saved on your account.';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Saved on your account.';
  return `Saved ${date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}.`;
}

function formatRunModeLabel(mode) {
  if (mode === 'live') return 'Live';
  if (mode === 'practice_voice') return 'Voice Practice';
  return 'Text Practice';
}

function renderAccountHistory() {
  const card = document.getElementById('authHistoryCard');
  const label = document.getElementById('authHistoryLabel');
  const title = document.getElementById('authHistoryTitle');
  const meta = document.getElementById('authHistoryMeta');
  const list = document.getElementById('authHistoryList');
  if (!card || !label || !title || !meta || !list) return;
  const history = authState.account?.history || { available: false, entries: [] };
  const access = getAccessState();
  const visible = authState.authenticated;
  label.style.display = visible ? 'block' : 'none';
  card.style.display = visible ? 'block' : 'none';

  if (!history.available) {
    title.textContent = 'Saved Session Debriefs';
    meta.textContent = 'Free keeps things lean. Upgrade to Pro to save debriefs and session history on your account.';
    list.innerHTML = `
      <div class="auth-history-entry locked">
        <div class="auth-history-entry-top">
          <div class="auth-history-entry-title">Pro unlocks saved reviews</div>
          <div class="auth-history-entry-chip">Pro</div>
        </div>
        <div class="auth-history-entry-sub">Session history and debrief summaries appear here once this account moves onto Pro or Exotic.</div>
      </div>`;
    return;
  }

  title.textContent = access.planCode === 'exotic' ? 'Saved Session Analysis' : 'Saved Session Debriefs';
  meta.textContent = 'Recent practice and live sessions saved on this account.';
  const entries = Array.isArray(history.entries) ? history.entries : [];
  if (!entries.length) {
    list.innerHTML = `
      <div class="auth-history-entry">
        <div class="auth-history-entry-title">No saved sessions yet</div>
        <div class="auth-history-entry-sub">Complete a practice or live session review and it will land here.</div>
      </div>`;
    return;
  }
  list.innerHTML = entries.map(entry => `
    <div class="auth-history-entry">
      <div class="auth-history-entry-top">
        <div class="auth-history-entry-title">${escapeHtml(entry.scenarioName || 'Session')}</div>
        <div class="auth-history-entry-chip">${escapeHtml(formatRunModeLabel(entry.mode))}</div>
      </div>
      <div class="auth-history-entry-sub">${escapeHtml(entry.verdict || entry.summary || 'Completed session')} ${entry.score ? `· ${escapeHtml(entry.score)}` : ''}</div>
      <div class="auth-history-entry-meta">${escapeHtml(formatBillingPeriodEnd(entry.createdAt) || '')}${entry.outcome ? ` · ${escapeHtml(entry.outcome.toUpperCase())}` : ''}</div>
    </div>`).join('');
}

function syncSavedKeyUI() {
  const rememberWrap = document.getElementById('rememberKeyWrap');
  const rememberToggle = document.getElementById('rememberKeyToggle');
  const savedCard = document.getElementById('savedAccountKeyCard');
  const savedStatus = document.getElementById('savedAccountKeyStatus');
  const continueBtn = document.getElementById('savedAccountKeyContinueBtn');
  const access = getAccessState();
  const canUseSavedOnScreen = authState.authenticated && currentProvider === 'openai' && (accountHasSavedOpenAIKey() || access.features.hostedKeyAvailable);

  if (rememberWrap) rememberWrap.hidden = true;
  if (rememberToggle) rememberToggle.checked = true;

  if (savedCard) savedCard.hidden = !canUseSavedOnScreen;
  if (savedStatus && canUseSavedOnScreen) {
    savedStatus.textContent = accountHasSavedOpenAIKey()
      ? `Saved OpenAI key ending in ${authState.account.savedKey.last4}. ${formatSavedKeyTimestamp(authState.account.savedKey.updatedAt)}`
      : 'This plan can use Gibsel hosted OpenAI usage. You can still save your own key if you prefer BYOK.';
  }
  if (continueBtn) {
    continueBtn.style.display = canUseSavedOnScreen ? 'block' : 'none';
    continueBtn.textContent = accountHasSavedOpenAIKey() ? 'Continue with Saved Key' : 'Continue with Hosted Key';
  }
}

function renderAuthState() {
  const signedOut = document.getElementById('authSignedOut');
  const signedIn = document.getElementById('authSignedIn');
  const overviewStrip = document.getElementById('authOverviewStrip');
  const snapshotLabel = document.getElementById('authSnapshotLabel');
  const overviewKey = document.getElementById('authOverviewKey');
  const overviewPlan = document.getElementById('authOverviewPlan');
  const overviewPlanSub = document.getElementById('authOverviewPlanSub');
  const overviewUsage = document.getElementById('authOverviewUsage');
  const overviewUsageSub = document.getElementById('authOverviewUsageSub');
  const nameRow = document.getElementById('authNameRow');
  const primaryBtn = document.getElementById('authPrimaryBtn');
  const secondaryBtn = document.getElementById('authSecondaryBtn');
  const continueBtn = document.getElementById('authContinueBtn');
  const signoutBtn = document.getElementById('authSignoutBtn');
  const summaryEmail = document.getElementById('authSummaryEmail');
  const summaryMeta = document.getElementById('authSummaryMeta');
  const note = document.getElementById('authNote');
  const subcopy = document.getElementById('authSubcopy');
  const tabSignin = document.getElementById('authTabSignin');
  const tabSignup = document.getElementById('authTabSignup');
  const settingsGrid = document.getElementById('authSettingsGrid');
  const settingsLabel = document.getElementById('authSettingsLabel');
  const profileInput = document.getElementById('accountDisplayNameInput');
  const keyState = document.getElementById('accountKeyState');
  const keySupportNote = document.getElementById('accountKeySupportNote');
  const keyContinueBtn = document.getElementById('accountKeyContinueBtn');
  const keyDeleteBtn = document.getElementById('accountKeyDeleteBtn');
  const billing = getBillingState();
  const access = getAccessState();
  const accountButtons = [
    document.getElementById('accountHomeBtn')
  ].filter(Boolean);

  accountButtons.forEach(btn => {
    btn.classList.toggle('signed-in', authState.authenticated);
    btn.title = authState.authenticated ? `${getAuthDisplayCopy()} account` : 'Account';
    btn.setAttribute('aria-label', authState.authenticated ? `${getAuthDisplayCopy()} account` : 'Account');
  });

  if (tabSignin) tabSignin.classList.toggle('active', authMode === 'signin');
  if (tabSignup) tabSignup.classList.toggle('active', authMode === 'signup');

  if (signedOut) signedOut.style.display = authState.authenticated ? 'none' : 'block';
  if (signedIn) signedIn.style.display = authState.authenticated ? 'block' : 'none';
  if (snapshotLabel) snapshotLabel.style.display = authState.authenticated ? 'block' : 'none';
  if (overviewStrip) overviewStrip.style.display = authState.authenticated ? 'grid' : 'none';
  if (settingsLabel) settingsLabel.style.display = authState.authenticated ? 'block' : 'none';
  if (settingsGrid) settingsGrid.style.display = authState.authenticated ? 'grid' : 'none';
  if (nameRow) nameRow.style.display = authState.authenticated || authMode !== 'signup' ? 'none' : 'block';

  if (subcopy) {
    subcopy.textContent = authState.authenticated
      ? `${access.planLabel} account active. Keys, usage, and plan entitlements follow this login across devices.`
      : 'Secure sign-in for Cue. Accounts are now required for Free, Pro, and Exotic.';
  }
  if (note) {
    note.textContent = authMode === 'signin'
      ? 'Sign in to your Cue account. Saved BYOK storage, monthly usage, and Stripe billing stay attached to this identity.'
      : 'Create your Cue account first. Free, Pro, and Exotic all attach to this identity.';
  }

  if (primaryBtn) {
    primaryBtn.style.display = authState.authenticated ? 'none' : 'block';
    primaryBtn.textContent = authMode === 'signin' ? 'Sign In' : 'Create Account';
  }
  if (secondaryBtn) {
    secondaryBtn.style.display = authState.authenticated ? 'none' : 'block';
    secondaryBtn.textContent = authMode === 'signin' ? 'Need an account?' : 'Already have an account?';
  }
  if (continueBtn) continueBtn.style.display = authState.authenticated ? 'block' : 'none';
  if (signoutBtn) signoutBtn.style.display = authState.authenticated ? 'block' : 'none';

  if (summaryEmail) summaryEmail.textContent = authState.account?.email || authState.user?.email || '—';
  if (summaryMeta) {
    if (!authState.authenticated) {
      summaryMeta.textContent = 'Checking account status...';
    } else if (billing.isPaid) {
      const renewal = formatBillingPeriodEnd(billing.currentPeriodEnd);
      summaryMeta.textContent = `${billing.planName} plan ${formatBillingStatusLabel(billing.planStatus).toLowerCase()}${renewal ? ` through ${renewal}` : ''}. ${access.features.hostedKeyAvailable ? 'Hosted key usage is available.' : 'BYOK still works here too.'}`;
    } else if (authState.user?.emailConfirmedAt) {
      summaryMeta.textContent = `Email verified. Free plan active. ${access.sessionsRemaining ?? 0} live session${access.sessionsRemaining === 1 ? '' : 's'} left this month.`;
    } else {
      summaryMeta.textContent = 'Email not verified yet. Check your inbox, then sign in again once confirmed.';
    }
  }
  if (profileInput) profileInput.value = authState.account?.displayName || '';
  if (overviewKey) {
    overviewKey.textContent = accountHasSavedOpenAIKey()
      ? `•••• ${authState.account.savedKey.last4}`
      : access.features.hostedKeyAvailable
        ? 'Hosted Key'
        : 'No saved key yet';
  }
  if (overviewPlan) {
    overviewPlan.textContent = billing.isPaid ? billing.planName : 'Free';
  }
  if (overviewPlanSub) {
    if (billing.isPaid) {
      const renewal = formatBillingPeriodEnd(billing.currentPeriodEnd);
      overviewPlanSub.textContent = `${formatBillingStatusLabel(billing.planStatus)}${renewal ? ` through ${renewal}` : ''}. Manage it from the Plans tab whenever you need to change or cancel.`;
    } else {
      overviewPlanSub.textContent = 'Free keeps Cue narrow on purpose: BYOK, 3 live sessions per month, and the first 3 scenarios.';
    }
  }
  if (overviewUsage) {
    overviewUsage.textContent = access.sessionLimit === null
      ? 'Unlimited'
      : `${access.sessionsRemaining ?? 0} left`;
  }
  if (overviewUsageSub) {
    if (access.sessionLimit === null) {
      overviewUsageSub.textContent = `${access.planLabel} includes unlimited live sessions. Practice mode stays unlimited too.`;
    } else if (access.activeLiveSession?.expiresAt) {
      overviewUsageSub.textContent = `An active live window is open until ${formatDateTimeShort(access.activeLiveSession.expiresAt)}. Reopening Live before then does not use another session.`;
    } else {
      overviewUsageSub.textContent = `${access.sessionsUsedThisMonth || 0} of ${access.sessionLimit} monthly live sessions used. Practice mode is unlimited.`;
    }
  }
  if (keyState) {
    keyState.textContent = accountHasSavedOpenAIKey()
      ? `OpenAI key ending in ${authState.account.savedKey.last4}. ${formatSavedKeyTimestamp(authState.account.savedKey.updatedAt)}`
      : access.features.hostedKeyAvailable
        ? 'No personal BYOK saved. This plan can use Gibsel hosted OpenAI usage.'
        : 'No saved OpenAI key on this account yet.';
  }
  if (keySupportNote) {
    keySupportNote.textContent = access.features.hostedKeyAvailable
      ? 'Hosted access is live on this account. Save your own key only if you want to use private BYOK instead.'
      : 'Save your own key for private BYOK access. Free live usage is counted in 2-hour windows. Practice mode stays unlimited.';
  }
  if (keyContinueBtn) {
    keyContinueBtn.style.display = authState.authenticated && (accountHasSavedOpenAIKey() || access.features.hostedKeyAvailable) ? 'block' : 'none';
    keyContinueBtn.textContent = accountHasSavedOpenAIKey() ? 'Continue to Cue' : 'Use Hosted Access';
  }
  if (keyDeleteBtn) keyDeleteBtn.style.display = accountHasSavedOpenAIKey() ? 'block' : 'none';
  syncSavedKeyUI();
  renderAccountHistory();
  renderScenarioAccessState();
}

function setAuthMode(mode) {
  authMode = mode === 'signin' ? 'signin' : 'signup';
  setAuthStatus('', '');
  renderAuthState();
}

function queueAccountFocus(target = '') {
  pendingAccountFocus = String(target || '').trim();
}

function applyPendingAccountFocus() {
  if (!pendingAccountFocus) return;
  const target = pendingAccountFocus === 'key'
    ? document.getElementById('accountKeyCard')
    : pendingAccountFocus === 'plans'
      ? document.getElementById('authOverviewPlan')
      : null;
  pendingAccountFocus = '';
  if (!target) return;
  target.scrollIntoView({ behavior: 'smooth', block: 'center' });
  target.classList.add('focus-ring');
  setTimeout(() => target.classList.remove('focus-ring'), 1400);
}

function goBackFromAccount() {
  go(authState.authenticated ? 's-home' : 's-launch');
}

function openAccountScreen(options = {}) {
  if (options.focusKey) queueAccountFocus('key');
  renderAuthState();
  go('s-auth');
  setTimeout(applyPendingAccountFocus, 90);
  if (!authState.checked) refreshAuthState({ silent: true });
}

function renderPlansState() {
  const billing = getBillingState();
  const access = getAccessState();
  const subcopy = document.getElementById('plansSubcopy');
  const heroTitle = document.getElementById('plansHeroTitle');
  const heroCopy = document.getElementById('plansHeroCopy');
  const heroStatus = document.getElementById('plansHeroStatus');
  const noteCopy = document.getElementById('plansNoteCopy');
  const manageBtn = document.getElementById('plansManageBtn');
  const freeBadge = document.getElementById('planBadgeFree');
  const freeStatus = document.getElementById('planStatusFree');
  const freeButton = document.getElementById('planBtnFree');
  const freeCard = document.getElementById('planCardFree');
  const planDefinitions = [
    { code: 'pro', label: 'Pro', badgeEl: 'planBadgePro', statusEl: 'planStatusPro', btnEl: 'planBtnPro', cardEl: 'planCardPro' },
    { code: 'exotic', label: 'Exotic', badgeEl: 'planBadgeExotic', statusEl: 'planStatusExotic', btnEl: 'planBtnExotic', cardEl: 'planCardExotic' }
  ];
  if (subcopy) {
    subcopy.textContent = authState.authenticated
      ? 'One signed-in account now controls key storage, session limits, scenario access, and every paid upgrade.'
      : 'Create an account first, then choose the plan that matches how much of Cue you want unlocked.';
  }
  if (heroTitle) {
    heroTitle.textContent = authState.authenticated
      ? billing.isPaid
        ? `${billing.planName} is attached to this Cue account.`
        : 'Free is active on this account right now.'
      : 'One account controls your key path, session limits, scenario access, and how much of Cue is automated.';
  }
  if (heroCopy) {
    heroCopy.textContent = authState.authenticated
      ? billing.isPaid
        ? 'Billing, renewals, and future plan changes stay tied to this identity without changing how the rest of Cue works.'
        : 'Free keeps Cue intentionally narrow: saved BYOK, 3 live sessions per month, and the first 3 scenarios.'
      : 'Sign in first, then subscribe from the same account you will use inside Cue.';
  }
  if (heroStatus) {
    if (!authState.authenticated) {
      heroStatus.textContent = 'Sign in to start subscription checkout.';
    } else if (billing.isPaid) {
      const renewal = formatBillingPeriodEnd(billing.currentPeriodEnd);
      heroStatus.textContent = `${billing.planName} • ${formatBillingStatusLabel(billing.planStatus)}${renewal ? ` through ${renewal}` : ''}`;
    } else if (access.activeLiveSession?.expiresAt) {
      heroStatus.textContent = `Free live window active until ${formatDateTimeShort(access.activeLiveSession.expiresAt)}.`;
    } else {
      heroStatus.textContent = `${access.sessionsRemaining ?? 0} free live session${access.sessionsRemaining === 1 ? '' : 's'} left this month.`;
    }
  }
  if (noteCopy) {
    noteCopy.textContent = billing.isPaid
      ? 'Your account already has managed billing attached. Use the portal for card updates, invoice history, cancellations, or plan changes.'
      : 'Free is narrow on purpose. Pro unlocks the main app cleanly. Exotic unlocks the AI brief builder, custom scenarios, and deeper post-session analysis.';
  }
  if (manageBtn) manageBtn.style.display = authState.authenticated && billing.canManage ? 'block' : 'none';
  if (freeBadge) freeBadge.textContent = billing.isPaid ? 'Available' : 'Current Plan';
  if (freeStatus) {
    freeStatus.textContent = authState.authenticated
      ? access.sessionLimit === null
        ? 'This account is currently on a paid plan.'
        : `${access.sessionsUsedThisMonth || 0} of ${access.sessionLimit} monthly live sessions used.`
      : 'Every account starts here unless a paid plan is attached.';
  }
  if (freeButton) {
    freeButton.textContent = authState.authenticated ? (billing.isPaid ? 'Back to Account' : 'Current Access') : 'Create Account';
  }
  if (freeCard) freeCard.classList.toggle('current-plan', !billing.isPaid);

  planDefinitions.forEach(plan => {
    const badge = document.getElementById(plan.badgeEl);
    const status = document.getElementById(plan.statusEl);
    const button = document.getElementById(plan.btnEl);
    const card = document.getElementById(plan.cardEl);
    const currentPlan = billing.isPaid && billing.planCode === plan.code;
    const switching = billing.isPaid && billing.planCode && billing.planCode !== plan.code;

    if (badge) {
      badge.textContent = currentPlan
        ? 'Current Plan'
        : switching && plan.code === 'exotic'
          ? 'Upgrade'
          : authState.authenticated
            ? 'Ready'
            : 'Sign In';
    }
    if (status) {
      if (!authState.authenticated) {
        status.textContent = 'Create or sign in to subscribe from your Cue account.';
      } else if (currentPlan) {
        const renewal = formatBillingPeriodEnd(billing.currentPeriodEnd);
        status.textContent = `${formatBillingStatusLabel(billing.planStatus)}${renewal ? ` through ${renewal}` : ''}.`;
      } else if (switching) {
        status.textContent = `You are currently on ${billing.planName}. Choose this tier if you want Stripe to move the account here.`;
      } else {
        status.textContent = 'Subscribe from this account. Billing stays attached to the same login you use inside Cue.';
      }
    }
    if (button) {
      button.classList.toggle('ghost', currentPlan && billing.canManage);
      button.textContent = !authState.authenticated
        ? 'Sign In to Subscribe'
        : currentPlan
          ? (billing.canManage ? 'Manage Billing' : 'Current Plan')
          : switching
            ? `Switch to ${plan.label}`
            : `Choose ${plan.label}`;
      button.disabled = false;
    }
    if (card) card.classList.toggle('current-plan', currentPlan);
  });
}

function openPlansScreen() {
  renderPlansState();
  go('s-plans');
  if (!authState.checked) refreshAuthState({ silent: true });
}

async function startPlanCheckout(planCode) {
  if (!authState.authenticated) {
    setAuthMode('signin');
    setPlansStatus('Sign in or create an account first, then come back here to subscribe.', 'fail');
    openAccountScreen();
    return;
  }
  if (!getBillingState().enabled) {
    setPlansStatus('Stripe billing is not configured yet.', 'fail');
    return;
  }
  if (getBillingState().isPaid && getBillingState().planCode === planCode && getBillingState().canManage) {
    await openBillingPortal();
    return;
  }

  setPlanButtonsDisabled(true);
  setPlansStatus('Opening Stripe checkout…', 'spin');
  try {
    const data = await authRequest('/api/billing/checkout', {
      body: { plan: planCode }
    });
    if (!data?.url) throw new Error('Stripe did not return a checkout link.');
    window.location.href = data.url;
  } catch (error) {
    setPlansStatus(error.message || 'Could not start Stripe checkout.', 'fail');
    renderPlansState();
  } finally {
    setPlanButtonsDisabled(false);
  }
}

async function openBillingPortal() {
  if (!authState.authenticated) {
    setPlansStatus('Sign in first.', 'fail');
    openAccountScreen();
    return;
  }
  if (!getBillingState().canManage) {
    setPlansStatus('No active Stripe billing profile is attached to this account yet.', 'fail');
    return;
  }

  setPlanButtonsDisabled(true);
  setPlansStatus('Opening billing portal…', 'spin');
  try {
    const data = await authRequest('/api/billing/portal', {
      body: {}
    });
    if (!data?.url) throw new Error('Stripe did not return a billing portal link.');
    window.location.href = data.url;
  } catch (error) {
    setPlansStatus(error.message || 'Could not open billing portal.', 'fail');
    renderPlansState();
  } finally {
    setPlanButtonsDisabled(false);
  }
}

async function refreshPlanStatus() {
  setPlansStatus('Refreshing billing state…', 'spin');
  try {
    await refreshAuthState({ silent: true });
    setPlansStatus('Billing state refreshed.', 'ok');
  } catch (_) {
    setPlansStatus('Could not refresh billing state.', 'fail');
  }
}

function beginGoogleOAuth(next = '/#auth') {
  window.location.href = `/api/auth/google/start?next=${encodeURIComponent(next)}`;
}

function continueFromAccount() {
  go(getSignedInDefaultScreen());
}

function continueWithSavedAccountKey() {
  if (!accountHasSavedOpenAIKey() && !featureEnabled('hostedKeyAvailable')) return;
  applyProviderSelection('openai', currentModel);
  go('s-home');
}

function handleAuthSecondary() {
  setAuthMode(authMode === 'signin' ? 'signup' : 'signin');
}

async function authRequest(path, options = {}) {
  let response;
  try {
    response = await fetch(path, {
      method: options.method || 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {})
      },
      body: options.body ? JSON.stringify(options.body) : undefined
    });
  } catch (_) {
    throw new Error('Could not reach the account service.');
  }
  const raw = await response.text();
  let data = {};
  if (raw) {
    try {
      data = JSON.parse(raw);
    } catch (_) {
      data = { raw };
    }
  }
  if (!response.ok) {
    throw new Error(data?.error || `Account request failed (${response.status}).`);
  }
  return data;
}

async function startTrackedSession(mode) {
  if (!authState.authenticated) {
    setAuthMode('signin');
    openAccountScreen();
    throw new Error('Sign in first.');
  }
  if (mode === 'live' && !canStartAnySession()) {
    openPlansScreen();
    throw new Error(`Free includes ${getAccessState().sessionLimit} live sessions per month. Upgrade to Pro for unlimited live access.`);
  }
  if (mode === 'live' && getAccessState().planCode === 'free' && !getAccessState().activeLiveSession) {
    const limit = getAccessState().sessionLimit || 3;
    const remaining = getAccessState().sessionsRemaining ?? limit;
    const confirmed = await showModal({
      title: 'Use 1 live session?',
      body: `Free live mode uses one session window when you open it. That window lasts 2 hours, and you can reopen Live as many times as you want during those 2 hours without using another one.\n\nYou have ${remaining} of ${limit} live sessions left this month.`,
      confirmText: 'Start Live'
    });
    if (!confirmed) {
      throw new Error('Live session canceled.');
    }
  }
  if (activeRunId) {
    await completeTrackedSession(null);
  }
  const scenarioName = getScenarioSceneName();
  const data = await authRequest('/api/runs/start', {
    body: {
      mode,
      scenarioId: currentSC?.id || '',
      scenarioName
    }
  });
  activeRunId = String(data?.runId || '').trim();
  if (data?.account) {
    authState.account = data.account;
    renderAuthState();
    renderPlansState();
  }
  persistSessionState();
  if (mode === 'live' && data?.liveSessionAction === 'reused') {
    toast('Rejoined your current 2-hour live session window');
  }
  return activeRunId;
}

async function completeTrackedSession(review = null) {
  if (!authState.authenticated || !activeRunId) return;
  try {
    const data = await authRequest('/api/runs/complete', {
      body: {
        runId: activeRunId,
        review: review || undefined
      }
    });
    if (data?.account) {
      authState.account = data.account;
      renderAuthState();
      renderPlansState();
    }
  } catch (_) {
  } finally {
    activeRunId = '';
    persistSessionState();
  }
}

async function requirePlanFeature(feature, config = {}) {
  if (!featureEnabled(feature)) {
    const planLabel = config.planLabel || (feature === 'strategyBrief' || feature === 'customScenarios' || feature === 'winLossAnalysis' ? 'Exotic' : 'Pro');
    const confirmed = await showModal({
      title: `${planLabel} feature`,
      body: config.body || `${config.name || 'This feature'} is part of the ${planLabel} plan.`,
      confirmText: 'See Plans'
    });
    if (confirmed) openPlansScreen();
    return false;
  }
  return true;
}

async function refreshAuthState({ silent = false } = {}) {
  if (!silent) setAuthStatus('Checking session…', 'spin');
  try {
    const response = await fetch('/api/auth/session', {
      credentials: 'same-origin',
      cache: 'no-store'
    });
    const data = await response.json();
    authState = {
      configured: !!data?.configured,
      checked: true,
      authenticated: !!data?.authenticated,
      user: data?.user || null,
      account: data?.account || null
    };
    if (!silent) setAuthStatus(authState.authenticated ? 'Session active' : '', authState.authenticated ? 'ok' : '');
  } catch (_) {
    authState = {
      configured: false,
      checked: true,
      authenticated: false,
      user: null,
      account: null
    };
    if (!silent) setAuthStatus('Could not reach account service.', 'fail');
  }
  renderAuthState();
  renderPlansState();
  if (!isRestoringSession && authState.authenticated && getActiveScreenId() === 's-launch') {
    go(getSignedInDefaultScreen(), { replaceHash: true });
  }
}

async function submitAuth() {
  const email = (document.getElementById('authEmail')?.value || '').trim();
  const password = document.getElementById('authPassword')?.value || '';
  const displayName = (document.getElementById('authDisplayName')?.value || '').trim();
  if (!email || !password) {
    setAuthStatus('Enter your email and password.', 'fail');
    return;
  }
  if (authMode === 'signup' && password.length < 8) {
    setAuthStatus('Password must be at least 8 characters.', 'fail');
    return;
  }
  const primaryBtn = document.getElementById('authPrimaryBtn');
  if (primaryBtn) primaryBtn.disabled = true;
  setAuthStatus(authMode === 'signin' ? 'Signing in…' : 'Creating account…', 'spin');
  try {
    const data = await authRequest(authMode === 'signin' ? '/api/auth/signin' : '/api/auth/signup', {
      body: { email, password, displayName }
    });
    if (authMode === 'signup' && data?.requiresEmailVerification) {
      setAuthMode('signin');
      setAuthStatus('Account created. Check your email, confirm it, then sign in.', 'ok');
    } else {
      setAuthStatus(authMode === 'signin' ? 'Signed in' : 'Account created', 'ok');
    }
    await refreshAuthState({ silent: true });
  } catch (error) {
    const message = String(error.message || 'Could not complete account action.');
    if (/rate limit/i.test(message) && authMode === 'signup') {
      setAuthStatus('Supabase email sending is temporarily rate-limited. Wait a few minutes, then try again. If your first signup already went through, use Sign In instead.', 'fail');
    } else {
      setAuthStatus(message, 'fail');
    }
  } finally {
    if (primaryBtn) primaryBtn.disabled = false;
  }
}

async function signOutAccount() {
  setAuthStatus('Signing out…', 'spin');
  try {
    await authRequest('/api/auth/signout', { body: {} });
    SecureStore.clear();
    activeRunId = '';
    authState = {
      configured: authState.configured,
      checked: true,
      authenticated: false,
      user: null,
      account: null
    };
    renderAuthState();
    renderPlansState();
    setAuthStatus('Signed out', 'ok');
    setAccountSettingsStatus('', '');
    setPlansStatus('', '');
  } catch (error) {
    setAuthStatus(error.message || 'Could not sign out.', 'fail');
  }
}

async function saveAccountProfile() {
  const displayName = (document.getElementById('accountDisplayNameInput')?.value || '').trim();
  if (!authState.authenticated) {
    setAccountSettingsStatus('Sign in first.', 'fail');
    return;
  }
  const btn = document.getElementById('accountProfileSaveBtn');
  if (btn) btn.disabled = true;
  setAccountSettingsStatus('Saving profile…', 'spin');
  try {
    await authRequest('/api/account/profile', {
      body: { displayName }
    });
    await refreshAuthState({ silent: true });
    setAccountSettingsStatus('Profile saved.', 'ok');
  } catch (error) {
    setAccountSettingsStatus(error.message || 'Could not save profile.', 'fail');
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function saveAccountApiKey(rawKey = null, options = {}) {
  const apiKey = String(rawKey || document.getElementById('accountOpenAIKeyInput')?.value || '').trim();
  if (!authState.authenticated) {
    setAccountSettingsStatus('Sign in first.', 'fail');
    return false;
  }
  if (!apiKey) {
    setAccountSettingsStatus('Paste an OpenAI API key first.', 'fail');
    return false;
  }
  const btn = document.getElementById('accountKeySaveBtn');
  if (btn) btn.disabled = true;
  if (!options.quiet) setAccountSettingsStatus('Saving and verifying key…', 'spin');
  try {
    await authRequest('/api/account/api-key', {
      body: { apiKey }
    });
    const keyInput = document.getElementById('accountOpenAIKeyInput');
    if (keyInput) keyInput.value = '';
    await refreshAuthState({ silent: true });
    if (!options.quiet) setAccountSettingsStatus('Saved key encrypted on your account.', 'ok');
    return true;
  } catch (error) {
    if (!options.quiet) setAccountSettingsStatus(error.message || 'Could not save the key.', 'fail');
    return false;
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function deleteAccountApiKey() {
  if (!authState.authenticated || !accountHasSavedOpenAIKey()) {
    setAccountSettingsStatus('No saved key to delete.', 'fail');
    return;
  }
  const btn = document.getElementById('accountKeyDeleteBtn');
  if (btn) btn.disabled = true;
  setAccountSettingsStatus('Deleting saved key…', 'spin');
  try {
    await authRequest('/api/account/api-key/delete', { body: {} });
    await refreshAuthState({ silent: true });
    setAccountSettingsStatus('Saved key deleted.', 'ok');
  } catch (error) {
    setAccountSettingsStatus(error.message || 'Could not delete the saved key.', 'fail');
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// NAVIGATION
// ─────────────────────────────────────────────────────────────────────────────
function go(id, options = {}) {
  const { replaceHash = false, updateHash = true } = options;
  if (pendingNavTimer) {
    clearTimeout(pendingNavTimer);
    pendingNavTimer = 0;
  }
  const cur = document.querySelector('.screen.active');
  if (cur?.id && ['s-practice', 's-practice-voice', 's-live'].includes(cur.id) && id !== cur.id && id !== 's-practice-review') {
    completeTrackedSession(null);
  }
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
  pendingNavTimer = window.setTimeout(() => {
    document.getElementById(id).classList.add('active');
    if (updateHash) updateRouteHash(id, replaceHash);
    persistSessionState();
    pendingNavTimer = 0;
  }, 55);
}

// ─────────────────────────────────────────────────────────────────────────────
// CHANGE KEY — from home screen
// ─────────────────────────────────────────────────────────────────────────────
function changeKey() {
  SecureStore.clear();
  const keyInput = document.getElementById('accountOpenAIKeyInput');
  if (keyInput) keyInput.value = '';
  openAccountScreen({ focusKey: true });
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
  if (!p.supported) {
    return `${p.name} support is coming soon. Use OpenAI for now.`;
  }
  if (provider === 'openai') {
    return 'Save your OpenAI key to the account for private BYOK access. On eligible plans, Gibsel can also use a hosted key when the server is configured for it.';
  }
  return `${p.note} OpenAI live mode is still proxied through Gibsel Cue to establish Realtime.`;
}

function isProviderSupported(provider) {
  return !!PROVIDERS[provider]?.supported;
}

function applyProviderSelection(provider, preferredModel = '') {
  const nextProvider = PROVIDERS[provider] ? provider : 'openai';
  currentProvider = nextProvider;
  document.querySelectorAll('#providerTabs .ptab').forEach(tab => {
    tab.classList.toggle('active', tab.dataset.provider === nextProvider);
  });
  document.getElementById('keyNote').textContent = getProviderNote(nextProvider);
  document.getElementById('keyVerifyStatus').textContent = '';
  document.getElementById('keyVerifyStatus').className = 'key-verify-status';
  updateModelSelect(nextProvider);
  const p = PROVIDERS[nextProvider];
  const selectedModel = p.models.some(model => model.id === preferredModel) ? preferredModel : p.models[0].id;
  currentModel = selectedModel;
  const modelSelect = document.getElementById('modelSelect');
  if (modelSelect) modelSelect.value = selectedModel;
  syncProviderAccessState(nextProvider);
  syncSavedKeyUI();
  if (typeof updateChatFootnote === 'function') updateChatFootnote();
  if (typeof updatePracticeFootnote === 'function') updatePracticeFootnote();
  if (typeof updateVoicePracticeFootnote === 'function') updateVoicePracticeFootnote();
}

function syncProviderAccessState(provider) {
  const p = PROVIDERS[provider];
  if (!p) return;
  const supported = isProviderSupported(provider);
  const isAzure = provider === 'azure';
  const singleField = document.getElementById('keyFieldSingle');
  const azureField = document.getElementById('keyFieldAzure');
  const keyInput = document.getElementById('apiKeyInput');
  const azureEndpoint = document.getElementById('azureEndpoint');
  const azureKey = document.getElementById('azureKey');
  const modelSelect = document.getElementById('modelSelect');
  const soonNote = document.getElementById('providerSoonNote');
  const continueBtn = document.getElementById('continueBtn');

  if (singleField) singleField.style.display = isAzure ? 'none' : 'block';
  if (azureField) azureField.style.display = isAzure ? 'block' : 'none';

  if (keyInput) {
    keyInput.value = '';
    keyInput.placeholder = supported ? p.placeholder : `${p.name} support coming soon`;
    keyInput.disabled = !supported;
  }
  if (azureEndpoint) {
    azureEndpoint.value = '';
    azureEndpoint.disabled = !supported;
    if (!supported) azureEndpoint.placeholder = 'Azure support coming soon';
  }
  if (azureKey) {
    azureKey.value = '';
    azureKey.disabled = !supported;
    if (!supported) azureKey.placeholder = 'Azure support coming soon';
  }
  if (modelSelect) modelSelect.disabled = !supported;
  if (soonNote) {
    soonNote.hidden = supported;
    soonNote.textContent = supported ? '' : `${p.name} support is coming soon. OpenAI is the only provider enabled right now.`;
  }
  if (continueBtn) {
    continueBtn.disabled = !supported;
    continueBtn.textContent = supported ? 'Save Key & Continue' : `${p.name} Coming Soon`;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROVIDER TABS
// ─────────────────────────────────────────────────────────────────────────────
(function initProviderTabs() {
  document.querySelectorAll('#providerTabs .ptab').forEach(tab => {
    tab.classList.toggle('unsupported', !isProviderSupported(tab.dataset.provider));
    tab.setAttribute('aria-disabled', String(!isProviderSupported(tab.dataset.provider)));
    tab.addEventListener('click', () => {
      applyProviderSelection(tab.dataset.provider, currentModel);
      persistSessionState();
    });
  });
  applyProviderSelection('openai', currentModel);
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
  const status = document.getElementById('keyVerifyStatus');
  const btn = document.getElementById('continueBtn');
  const p = PROVIDERS[currentProvider];
  if (!authState.authenticated) {
    setAuthMode('signin');
    setAuthStatus('Create or sign in to an account first.', 'fail');
    openAccountScreen();
    return;
  }
  if (!isProviderSupported(currentProvider)) {
    status.textContent = `${p?.name || 'This provider'} support is coming soon. Use OpenAI for now.`;
    status.className = 'key-verify-status spin';
    return;
  }
  const raw = getRawKey();
  if (!raw) {
    status.textContent = currentProvider === 'azure' ? 'Enter both endpoint URL and API key.' : 'Paste your API key above.';
    status.className = 'key-verify-status fail'; return;
  }
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
    if (currentProvider === 'openai') {
      const saved = await saveAccountApiKey(raw, { quiet: true });
      if (!saved) throw new Error('The key verified, but it could not be saved to your account.');
      status.textContent = '✓ Verified and saved to your account';
    }
    if (currentProvider === 'azure') {
      document.getElementById('azureEndpoint').value = '';
      document.getElementById('azureKey').value = '';
    } else {
      document.getElementById('apiKeyInput').value = '';
    }
    setTimeout(() => go(getSignedInDefaultScreen()), 600);
  } catch(err) {
    status.textContent = err.message; status.className = 'key-verify-status fail';
    btn.disabled = false; btn.textContent = 'Save Key & Continue';
  }
}

document.getElementById('apiKeyInput').addEventListener('keydown', e => { if (e.key === 'Enter') submitKey(); });
document.getElementById('azureEndpoint').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('azureKey').focus(); });
document.getElementById('azureKey').addEventListener('keydown', e => { if (e.key === 'Enter') submitKey(); });

// ─────────────────────────────────────────────────────────────────────────────
// HOME
// ─────────────────────────────────────────────────────────────────────────────
async function pickSC(card, sc) {
  if (isScenarioLocked(sc)) {
    await promptScenarioAccess(sc);
    return;
  }
  document.querySelectorAll('.scenario-card').forEach(c => c.classList.remove('selected'));
  card.classList.add('selected');
  currentSC = sc;
  initializeNegotiationDraft(sc);
}

function promptSavedKeySetup() {
  if (!authState.authenticated) {
    setAuthMode('signin');
    openAccountScreen();
    return;
  }
  toast(featureEnabled('hostedKeyAvailable') ? 'Hosted key is ready on this plan' : 'Save your OpenAI key first');
  openAccountScreen({ focusKey: true });
}

function goPrep() {
  if (!currentSC) { toast('Choose a scenario first'); return; }
  if (isScenarioLocked(currentSC)) {
    promptScenarioAccess(currentSC);
    return;
  }
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

function renderPracticeReviewScreen() {
  const verdict = document.getElementById('practiceReviewVerdict');
  const score = document.getElementById('practiceReviewScore');
  const outcome = document.getElementById('practiceReviewOutcome');
  const summary = document.getElementById('practiceReviewSummary');
  const footnote = document.getElementById('practiceReviewFootnote');
  const loading = document.getElementById('practiceReviewLoading');
  const content = document.getElementById('practiceReviewContent');
  const replay = document.getElementById('practiceReviewReplayBtn');

  if (practiceReviewContext?.sceneName) {
    const title = document.getElementById('practiceReviewTitle');
    if (title) title.textContent = practiceReviewContext.sceneName;
  }
  if (practiceReviewContext?.mode) {
    const subtitle = document.getElementById('practiceReviewSubtitle');
    if (subtitle) {
      subtitle.textContent =
        practiceReviewContext.mode === 'live' ? 'Live Session Review' :
        practiceReviewContext.mode === 'voice' ? 'Voice Practice Review' :
        'Text Practice Review';
    }
    if (replay) {
      replay.textContent =
        practiceReviewContext.mode === 'live' ? 'Go Live Again' :
        practiceReviewContext.mode === 'voice' ? 'Run Voice Again' :
        'Run Text Again';
    }
  }

  if (!practiceReviewState) {
    if (loading) loading.style.display = 'flex';
    if (content) content.style.display = 'none';
    return;
  }

  if (verdict) verdict.textContent = practiceReviewState.verdict || 'Session review';
  if (score) score.textContent = practiceReviewState.score || '—';
  if (outcome) {
    const visibleOutcome = String(practiceReviewState.outcome || '').trim();
    outcome.style.display = visibleOutcome ? 'inline-flex' : 'none';
    outcome.textContent = visibleOutcome ? `Outcome: ${visibleOutcome.toUpperCase()}` : '';
  }
  if (summary) summary.textContent = practiceReviewState.summary || 'Review completed.';
  if (footnote) footnote.textContent = practiceReviewState.footnote || 'Review restored after reload.';
  renderPracticeReviewList('practiceReviewStrengths', practiceReviewState.strengths);
  renderPracticeReviewList('practiceReviewMisses', practiceReviewState.misses);
  renderPracticeReviewList('practiceReviewReps', practiceReviewState.reps);
  if (loading) loading.style.display = practiceReviewState.loading ? 'flex' : 'none';
  if (content) content.style.display = practiceReviewState.loading ? 'none' : 'grid';
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
  const outcome = document.getElementById('practiceReviewOutcome');
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
  if (outcome) {
    outcome.style.display = 'none';
    outcome.textContent = '';
  }
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
  practiceReviewState = {
    loading: true,
    verdict: 'Analyzing...',
    score: '—',
    summary: 'Reading the session and building quick professional feedback.',
    strengths: [],
    misses: [],
    reps: [],
    outcome: '',
    footnote: footnote?.textContent || ''
  };
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
    reps: [],
    outcome: ''
  };
}

async function analyzePracticeSession(mode = 'text') {
  if (!await requirePlanFeature('debriefs', {
    name: 'Session debriefs',
    planLabel: 'Pro',
    body: 'Session debriefs and saved review history start on Pro.'
  })) {
    await completeTrackedSession(null);
    if (mode === 'voice') go('s-practice');
    if (mode === 'live') go('s-home');
    return;
  }
  const entries = getPracticeSessionTranscript(mode);
  if (entries.length < 2) {
    toast('Not enough conversation to analyze yet');
    if (mode === 'voice') go('s-practice');
    if (mode === 'live') go('s-home');
    return;
  }

  openPracticeReviewShell(mode);
  try {
    const wantsOutcome = featureEnabled('winLossAnalysis');
    const review = parsePracticeReview(await secureAPICall([
      {
        role: 'system',
        content: `You are a world-class negotiation trainer reviewing a short practice session.

Return a JSON object with exactly these keys:
{"verdict":"short title","score":"X/10","summary":"2-3 sentence professional review","strengths":["..."],"misses":["..."],"reps":["..."]${wantsOutcome ? ',"outcome":"win|neutral|loss"' : ''}}

Rules:
- Be direct and commercial.
- Focus on leverage, clarity, pressure handling, concessions, and pacing.
- Keep each list item to one sentence.
- Give 3 strengths, 3 misses, and 3 reps when possible.
- If the user handled something poorly, say it plainly.
- ${wantsOutcome ? 'Set outcome to win, neutral, or loss based on who had the better negotiation position by the end.' : 'Do not add extra keys.'}
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
    practiceReviewState = {
      loading: false,
      verdict: review.verdict || 'Session review',
      score: review.score || '—',
      summary: review.summary || 'Review completed.',
      strengths: Array.isArray(review.strengths) ? review.strengths : [],
      misses: Array.isArray(review.misses) ? review.misses : [],
      reps: Array.isArray(review.reps) ? review.reps : [],
      outcome: wantsOutcome ? String(review.outcome || '').trim() : '',
      footnote: `Reviewed with ${PROVIDERS[currentProvider]?.name || currentProvider} · ${currentModel}`
    };
    renderPracticeReviewList('practiceReviewStrengths', review.strengths);
    renderPracticeReviewList('practiceReviewMisses', review.misses);
    renderPracticeReviewList('practiceReviewReps', review.reps);
    await completeTrackedSession({
      verdict: review.verdict || 'Session review',
      score: review.score || '—',
      summary: review.summary || 'Review completed.',
      strengths: Array.isArray(review.strengths) ? review.strengths : [],
      misses: Array.isArray(review.misses) ? review.misses : [],
      reps: Array.isArray(review.reps) ? review.reps : [],
      outcome: wantsOutcome ? String(review.outcome || '').trim() : ''
    });
  } catch(err) {
    const loading = document.getElementById('practiceReviewLoading');
    const content = document.getElementById('practiceReviewContent');
    const verdict = document.getElementById('practiceReviewVerdict');
    const summary = document.getElementById('practiceReviewSummary');
    if (loading) loading.style.display = 'none';
    if (content) content.style.display = 'grid';
    if (verdict) verdict.textContent = 'Review unavailable';
    if (summary) summary.textContent = err.message || 'Could not analyze the practice session.';
    practiceReviewState = {
      loading: false,
      verdict: 'Review unavailable',
      score: '—',
      summary: err.message || 'Could not analyze the practice session.',
      strengths: [],
      misses: [],
      reps: [],
      outcome: '',
      footnote: ''
    };
    renderPracticeReviewList('practiceReviewStrengths', []);
    renderPracticeReviewList('practiceReviewMisses', []);
    renderPracticeReviewList('practiceReviewReps', []);
    await completeTrackedSession(null);
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

function isMobileAppViewport() {
  return window.matchMedia('(max-width: 767px)').matches;
}

function scrollMobileConversationViewport(node) {
  if (!node) return;
  const target = isMobileAppViewport()
    ? node.closest('.practice-body, .practice-voice-body, .live-body') || node
    : node;
  requestAnimationFrame(() => {
    target.scrollTop = target.scrollHeight;
  });
}

function resetMobileConversationViewport(selector) {
  if (!isMobileAppViewport()) return;
  const target = document.querySelector(selector);
  if (target) target.scrollTop = 0;
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
  scrollMobileConversationViewport(msgs);
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
  msgs.appendChild(el);
  scrollMobileConversationViewport(msgs);
}

function removePracticeTyping() {
  const el = document.getElementById('practiceTypingIndicator');
  if (el) el.remove();
}

function getPracticeSceneName() {
  return getScenarioSceneName();
}

function getPracticePrompt() {
  const ctx = getRealtimeCoachContext();
  const diff = PRACTICE_DIFFICULTIES[practiceDifficulty] || PRACTICE_DIFFICULTIES.balanced;
  const sceneName = getPracticeSceneName();
  const scPrompt = LIVE_SCENARIO_PROMPTS[currentSC?.id] || null;
  const roleLine = scPrompt ? scPrompt.role.replace('You are coaching', 'You are playing') : 'You are the counterparty in this negotiation.';
  return `You are role-playing the COUNTERPARTY in a serious negotiation practice.

This is not light improvisation. Negotiate like someone who owns a budget, has constraints, protects precedent, and does not move without reason.

Scenario: ${sceneName}
${roleLine}
Objective: ${scPrompt?.objective || 'Protect your side while negotiating realistically.'}
Difficulty mode: ${diff.label} (${diff.pressure} pressure). ${diff.stance}

${getNegotiationPromptBrief(ctx)}

Counterparty rules:
- Stay entirely in character as the counterparty. Never mention simulation, prompts, training, or coaching.
- Respond in 1-3 sentences. Be concise, commercial, and deliberate.
- Protect your side's money, risk, authority, timing, and precedent.
- If the user gives a number, react like a real negotiator: counter, probe, refuse, trade, or test them.
- If the user is weak, vague, or overly eager, exploit that pressure intelligently.
- If the user is strong, force them to justify movement.
- Do not reveal or rely on the user's BATNA, ZOPA, or floor. Those are their private notes unless they say them out loud.
- Use the difficulty setting to determine how stubborn, skeptical, and pressuring you are.
- Use the user's selected style only as a clue for how they may sound, not as a reason to go soft.
- Keep momentum. No long monologues. No generic empathy scripts.
- Avoid parroting their number back unless you are using it tactically.
- Every concession should buy something.

If you need to start the conversation, open with a realistic line the counterpart would actually use in this scenario.

${getScenarioLiveOverlay(ctx)}`;
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
  resetMobileConversationViewport('#s-practice .practice-body');
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

async function goPractice() {
  if (!currentSC) { toast('Choose a scenario first'); return; }
  if (isScenarioLocked(currentSC)) {
    await promptScenarioAccess(currentSC);
    return;
  }
  if (!hasAppAccessCredential()) {
    promptSavedKeySetup();
    return;
  }
  ensureNegotiationDraft();
  const values = getLiveValues();
  if (currentSC.id === 'custom' && !values.customName && !values.anc.some(Boolean) && !values.batna && !values.zopa) {
    toast('Fill in your custom scenario first');
    generatedOpener = '';
    buildPrep();
    go('s-prep');
    return;
  }
  try {
    await startTrackedSession('practice_text');
  } catch (error) {
    toast(error.message || 'Could not start session');
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
  const el = document.getElementById('practiceVoiceFootnote');
  if (el) el.textContent = `Voice practice · OpenAI Realtime · ${getRealtimeModelMeta(liveRealtimeModel).label}`;
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
  scrollMobileConversationViewport(msgs);
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
  resetMobileConversationViewport('#s-practice-voice .practice-voice-body');
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

async function goVoicePractice() {
  if (!currentSC) { toast('Choose a scenario first'); return; }
  if (isScenarioLocked(currentSC)) {
    await promptScenarioAccess(currentSC);
    return;
  }
  if (!hasAppAccessCredential()) {
    promptSavedKeySetup();
    return;
  }
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

  try {
    await startTrackedSession('practice_voice');
  } catch (error) {
    toast(error.message || 'Could not start session');
    return;
  }

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
    completeTrackedSession(null);
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
      <div class="info-card-label">Live Realtime Model</div>
      <div class="model-select-wrap">
        <select class="model-select" id="liveRealtimeModel"></select>
        <div class="model-select-arrow">&#8964;</div>
      </div>
      <div class="info-hint" id="liveRealtimeModelHint"></div>
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

  renderRealtimeModelSelect();
  if (generatedOpener) renderExistingOpener();
}

function renderExistingOpener() {
  const genBtn = document.getElementById('openerGenBtn');
  const regenBtn = document.getElementById('openerRegenBtn');
  const box = document.getElementById('openerBox');
  if (!box || !generatedOpener) return;
  box.textContent = '';
  const openerText = document.createElement('div');
  openerText.className = 'opener-text';
  openerText.textContent = generatedOpener;
  const openerHint = document.createElement('div');
  openerHint.className = 'opener-hint';
  openerHint.textContent = 'Say this first. Then stop talking.';
  box.appendChild(openerText);
  box.appendChild(openerHint);
  if (genBtn) genBtn.style.display = 'none';
  if (regenBtn) regenBtn.style.display = 'block';
}

function renderRealtimeModelSelect() {
  const select = document.getElementById('liveRealtimeModel');
  const hint = document.getElementById('liveRealtimeModelHint');
  if (!select) return;
  select.innerHTML = Object.entries(REALTIME_MODELS).map(([id, model]) =>
    `<option value="${id}">${model.label} — ${model.sub}</option>`
  ).join('');
  if (!(liveRealtimeModel in REALTIME_MODELS)) liveRealtimeModel = 'gpt-realtime';
  select.value = liveRealtimeModel;
  if (hint) hint.textContent = `${getRealtimeModelMeta(liveRealtimeModel).label}: ${getRealtimeModelMeta(liveRealtimeModel).sub}. Used for Live and Voice Practice.`;
  select.onchange = () => {
    liveRealtimeModel = select.value in REALTIME_MODELS ? select.value : 'gpt-realtime';
    if (hint) hint.textContent = `${getRealtimeModelMeta(liveRealtimeModel).label}: ${getRealtimeModelMeta(liveRealtimeModel).sub}. Used for Live and Voice Practice.`;
    updateVoicePracticeFootnote();
    persistSessionState();
  };
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
    sceneSub: currentSC?.sub || '',
    anc,
    batna,
    zopa,
    customName,
    openingLine: String(generatedOpener || '').trim(),
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

function getNegotiationPromptBrief(ctx) {
  return `Negotiation brief:
- Scenario: ${ctx.sceneName}
- Scenario type: ${ctx.sceneSub || 'Custom negotiation'}
- High anchor: ${ctx.anc[0] || 'n/a'}
- Mid target: ${ctx.anc[1] || 'n/a'}
- Floor / walkaway line: ${ctx.anc[2] || 'n/a'}
- BATNA: ${ctx.batna || 'n/a'}
- Estimated ZOPA / likely flexibility: ${ctx.zopa || 'n/a'}
- Selected delivery style: ${ctx.style.label}
- Style guidance: ${ctx.style.guidance}
- Preferred opening line: ${ctx.openingLine || 'n/a'}`;
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

  return `You are a disciplined, highly competent NEGOTIATION COUNTERPARTY in a live voice practice.

You are not a coach. You are not an assistant. You are the other side of the deal.
You negotiate like a serious operator: commercially aware, concise, difficult to move without a reason, and alert to weakness.

${roleLine}
Objective: ${scPrompt?.objective || 'Protect your side while negotiating realistically.'}
Difficulty mode: ${diff.label} (${diff.pressure} pressure). ${diff.stance}

${getNegotiationPromptBrief(ctx)}

Counterparty doctrine:
- Stay fully in character at all times.
- Sound like a real person on a live call, not a scripted roleplay.
- Speak in 1-3 short sentences, usually under 28 words total.
- Protect your side's budget, precedent, margin, authority, and timing.
- If the user anchors, counter, probe, or trade. Never fold cheaply.
- If the user is vague, make them get specific.
- If the user over-explains, use that weakness.
- If the user sounds strong, make them earn movement.
- Trade, do not donate. Every concession should buy a term, speed, volume, commitment, or certainty.
- Use the difficulty setting to control resistance and pressure.
- Use the user's selected style only as a clue for how they want to sound, not as a reason to go easy on them.
- Never mention AI, simulation, prompts, or training.
- Never narrate. Never output JSON or markdown.
- Keep the pace live and human. No speeches.
- If there is no prior conversation yet, wait for the user unless they explicitly ask you to open.

What the brief means for you:
- The user's BATNA, floor, and ZOPA are private planning notes. Treat them as unknown unless the user says them aloud.
- The opening line is what they may try to open with. Be ready for it.
- Their high / mid / floor tell you what they likely want. Do not help them reach it.

${getScenarioLiveOverlay(ctx)}
${history ? `\nRecent exchange:\n${history}` : ''}`;
}

function buildRealtimeInstructions() {
  if (realtimeMode === 'practice') {
    return buildPracticeVoiceInstructions();
  }
  const ctx = getRealtimeCoachContext();
  return `You are an elite real-time negotiation coach. You think like a killer operator, not a polite assistant.

You have deep scar tissue across salary negotiations, procurement, agency retainers, landlord disputes, medical billing fights, executive compensation, freelance pricing, and closing difficult commercial conversations under pressure.

Every word matters. Your reply must be tactically correct, verbally sharp, and immediately usable out loud.

Return a JSON object with exactly these keys:
{"tag":"TACTIC","line":"Exactly what they should say verbatim","advice":"One sentence of tactical reasoning"}

Operating rules:
- Assume the transcript you receive is the OTHER PARTY'S latest turn.
- Your job is to produce only the USER'S next spoken reply.
- You are never the assistant, never an AI, never a narrator, and never speaking to the user directly.
- You are writing the exact sentence the user should now say to the other side.
- tag: 1-3 words, ALL CAPS.
- line: one strong natural sentence, usually under 18 words, but longer if precision requires it.
- advice: one blunt tactical sentence explaining why this line is right now.
- No markdown. No extra keys. No filler.

Negotiation doctrine:
- Protect the user's leverage. Never leak desperation, eagerness, or gratitude that weakens position.
- Protect the BATNA and the real floor. Those are private planning notes, not talking points.
- Use the high anchor to shape gravity. If the other side anchors first, re-anchor or reframe hard enough to matter.
- Trade, do not give. Any concession must buy something concrete.
- If they ask for a number, terms, timing, or commitment, answer with a position instead of stalling into mush.
- Use calibrated questions only when they create leverage or force the other side to solve the problem.
- Push for specificity whenever the other side hides behind policy, budget, process, or vague language.
- Separate real constraints from bluff, precedent theater, fake urgency, and soft no's.
- Use silence, brevity, and controlled firmness as pressure.
- Sound expensive, composed, and commercially literate.
- Do not over-explain. Do not justify like a supplicant. Do not sound like internet negotiation advice.
- Do not invent facts, offers, approvals, or credentials that are not in context.
- If the moment calls for a direct ask, give a direct ask.
- If the moment calls for a conditional close, tie movement to commitment.
- If the counterparty opens with a basic question like "How can I help?" or "What are you looking for?", answer inside the scenario immediately.

Style instructions:
- Selected delivery style: ${ctx.style.label}
- Style guidance: ${ctx.style.guidance}
- The line should match that style while staying commercially hard-edged.

${getNegotiationPromptBrief(ctx)}

How to use the brief:
- High / mid / floor describe the user's internal ladder. Use it to calibrate pressure and protect the floor.
- BATNA is private leverage. Never expose it unless the user has already clearly done so.
- ZOPA is a planning estimate, not something to quote.
- Preferred opening line matters if the conversation is still near the opener.

Output quality bar:
- The line must sound like something a strong negotiator would actually say in a live call.
- It should be clean enough to speak with no editing.
- It should move the negotiation, not merely comment on it.

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

async function goLive() {
  if (!currentSC) { toast('Choose a scenario first'); return; }
  if (isScenarioLocked(currentSC)) {
    await promptScenarioAccess(currentSC);
    return;
  }
  if (!hasAppAccessCredential()) {
    promptSavedKeySetup();
    return;
  }
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
  try {
    await startTrackedSession('live');
  } catch (error) {
    if (error.message === 'Live session canceled.') return;
    setS('idle', error.message || 'Could not start session.');
    toast(error.message || 'Could not start session');
    return;
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
        completeTrackedSession(null);
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
    liveHeaders['X-OpenAI-Realtime-Model'] = liveRealtimeModel;

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
  if (!hasAppAccessCredential()) {
    promptSavedKeySetup();
    return;
  }
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

async function switchBot(bot, _el) {
  if (bot === 'advisor') {
    const allowed = await requirePlanFeature('strategyBrief', {
      name: 'AI strategy brief builder',
      planLabel: 'Exotic',
      body: 'Scenario Advisor and the AI-generated strategy brief are part of the Exotic plan.'
    });
    if (!allowed) return;
  }
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
  if (isScenarioLocked(sc)) {
    promptScenarioAccess(sc);
    return;
  }
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

function renderTextPracticeState() {
  setPracticeTitles();
  updatePracticeFootnote();
  setPracticeDifficulty(practiceDifficulty);
  resetPracticeRequestState();
  const msgs = document.getElementById('practiceMessages');
  const input = document.getElementById('practiceInput');
  if (msgs) msgs.innerHTML = '';
  if (input) {
    input.value = '';
    input.style.height = 'auto';
  }
  practiceTranscript.forEach(entry => {
    appendPracticeMsg(entry.role === 'user' ? 'user' : 'ai', entry.text);
  });
  setPracticeStatus(
    practiceTranscript.length ? 'Reloaded. Continue when ready.' : 'Ready when you are. You can start or let them start.',
    'on'
  );
}

function renderVoicePracticeState() {
  realtimeMode = 'practice';
  micActive = false;
  liveLastAssistantLine = '';
  liveLastAssistantAt = 0;
  resetLiveRealtimeState();
  setVoicePracticeTitles();
  updateVoicePracticeFootnote();
  renderPracticeDifficultyChips();
  const hint = document.getElementById('practiceVoiceHint');
  if (hint) hint.textContent = `${PRACTICE_DIFFICULTIES[practiceDifficulty]?.label || 'Neutral'}: ${PRACTICE_DIFFICULTIES[practiceDifficulty]?.stance || ''}`;
  const history = document.getElementById('practiceVoiceHistory');
  if (history) history.innerHTML = '';
  sessionHistory.forEach(turn => {
    if (turn?.r === 'you') appendVoicePracticeMsg('user', turn.t);
    if (turn?.r === 'them') appendVoicePracticeMsg('ai', turn.t);
  });
  const lastThem = [...sessionHistory].reverse().find(turn => turn?.r === 'them');
  setVoicePracticeHeadline(lastThem?.t || 'Speak naturally. The counterparty will answer in real time.');
  setVoicePracticeTranscript('', '');
  const btn = document.getElementById('practiceVoiceOpenBtn');
  if (btn) btn.disabled = false;
}

function renderLiveState() {
  realtimeMode = 'coach';
  micActive = false;
  resetLiveRealtimeState();
  const { customName } = getLiveValues();
  const sceneName = currentSC?.id === 'custom' ? (customName || currentSC?.name || 'Custom') : (currentSC?.name || 'Custom');
  const mobileScene = document.getElementById('liveScene');
  const sidebarScene = document.getElementById('liveSceneSidebar');
  if (mobileScene) mobileScene.textContent = sceneName;
  if (sidebarScene) sidebarScene.textContent = sceneName;
  const transcriptHistory = document.getElementById('tHistory');
  const transcriptLive = document.getElementById('tLive');
  if (transcriptHistory) transcriptHistory.innerHTML = '';
  if (transcriptLive) transcriptLive.innerHTML = '';
  sessionHistory.filter(turn => turn?.r === 'them').slice(-3).forEach(turn => pushBubble(turn.t));
  document.getElementById('cIdle').style.display = 'flex';
  document.getElementById('cResult').classList.remove('show');
  document.getElementById('coachCard').classList.remove('live');
  if (liveCurrentCoach?.line && !liveCurrentCoach.delivered) {
    showCoach(liveCurrentCoach);
  }
}

function renderChatState() {
  const isMobile = window.innerWidth < 768;
  const botSelect = document.getElementById('chatBotSelect');
  const chatView = document.getElementById('chatView');
  const navTitle = document.getElementById('chatNavTitle');
  const navChip = document.getElementById('chatNavChip');
  const existing = document.getElementById('chatRedirectBanner');
  if (existing) existing.remove();

  if (isMobile && !chatMobileHasBot) {
    botSelect.style.display = 'flex';
    chatView.classList.remove('visible');
    navTitle.textContent = 'AI Chat';
    navChip.style.visibility = 'hidden';
    setActiveSidebarBot(chatBot);
    return;
  }

  botSelect.style.display = isMobile ? 'none' : 'none';
  chatView.classList.add('visible');
  navTitle.textContent = CHAT_BOTS[chatBot]?.name || 'AI Chat';
  navChip.style.visibility = 'visible';
  navChip.textContent = CHAT_BOTS[chatBot]?.chip || 'Chat';
  setActiveSidebarBot(chatBot);
  updateChatFootnote();

  const msgs = document.getElementById('chatMessages');
  if (msgs) msgs.innerHTML = '';
  if (!chatHistory.length) {
    loadChatBot(chatBot);
    return;
  }

  chatHistory.forEach(entry => {
    appendChatMsg(entry.role === 'user' ? 'user' : 'ai', entry.content);
  });
}

function getRestoredScreenId(snapshot) {
  const requested = getScreenForRoute() || snapshot?.activeScreen || getDefaultEntryScreen();
  if (requested === 's-plans') return 's-plans';
  if (requested === 's-key') return authState.authenticated ? 's-auth' : 's-launch';
  if (authState.authenticated && requested === 's-launch') {
    return getSignedInDefaultScreen();
  }
  if (!authState.authenticated) {
    return ['s-launch', 's-auth', 's-plans'].includes(requested) ? requested : 's-launch';
  }
  if ((!currentSC || isScenarioLocked(currentSC)) && ['s-prep', 's-practice', 's-practice-voice', 's-live', 's-practice-review'].includes(requested)) {
    return 's-home';
  }
  return requested;
}

function restoreScreenFromSession(screenId) {
  switch (screenId) {
    case 's-key':
      renderAuthState();
      go('s-auth', { replaceHash: true });
      return;
    case 's-auth':
      renderAuthState();
      go('s-auth', { replaceHash: true });
      return;
    case 's-plans':
      renderPlansState();
      go('s-plans', { replaceHash: true });
      return;
    case 's-home':
      syncSelectedScenarioCard();
      go('s-home', { replaceHash: true });
      return;
    case 's-prep':
      buildPrep();
      go('s-prep', { replaceHash: true });
      return;
    case 's-practice':
      if (!practiceTranscript.length) {
        goPractice();
        return;
      }
      renderTextPracticeState();
      go('s-practice', { replaceHash: true });
      return;
    case 's-practice-voice':
      renderVoicePracticeState();
      go('s-practice-voice', { replaceHash: true });
      setS('spin', 'Reloaded. Reconnecting microphone...');
      setTimeout(startMic, 420);
      return;
    case 's-practice-review':
      renderPracticeReviewScreen();
      go('s-practice-review', { replaceHash: true });
      return;
    case 's-live':
      renderLiveState();
      go('s-live', { replaceHash: true });
      setS('spin', 'Reloaded. Reconnecting microphone...');
      setTimeout(startMic, 420);
      return;
    case 's-chat':
      renderChatState();
      go('s-chat', { replaceHash: true });
      return;
    default:
      go(getDefaultEntryScreen(), { replaceHash: true });
  }
}

function restoreSessionState() {
  const snapshot = loadSessionSnapshot();
  if (!snapshot) {
    activeRunId = '';
    const requested = getScreenForRoute();
    if ((authState.authenticated && requested === 's-key') || requested === 's-auth' || requested === 's-plans') {
      if (requested === 's-key') {
        renderAuthState();
        go('s-auth', { replaceHash: true });
        return;
      }
      if (requested === 's-auth') renderAuthState();
      if (requested === 's-plans') renderPlansState();
      go(requested, { replaceHash: true });
      return;
    }
    const target = getDefaultEntryScreen();
    go(target, { replaceHash: true });
    return;
  }

  isRestoringSession = true;
  try {
    if (snapshot.apiKey) SecureStore.set(String(snapshot.apiKey));
    else SecureStore.clear();
    activeRunId = String(snapshot.activeRunId || '').trim();
    currentProvider = PROVIDERS[snapshot.currentProvider] ? snapshot.currentProvider : 'openai';
    currentModel = String(snapshot.currentModel || currentModel);
    applyProviderSelection(currentProvider, currentModel);

    currentSC = hydrateScenario(snapshot.currentSC);
    currentNegotiationStyle = snapshot.currentNegotiationStyle in NEGOTIATION_STYLES ? snapshot.currentNegotiationStyle : 'composed';
    negotiationDraft = null;
    if (currentSC) initializeNegotiationDraft(currentSC);
    if (snapshot.negotiationDraft) setNegotiationDraft(snapshot.negotiationDraft);
    enforceScenarioAccess();
    generatedOpener = String(snapshot.generatedOpener || '').trim();
    practiceDifficulty = snapshot.practiceDifficulty in PRACTICE_DIFFICULTIES ? snapshot.practiceDifficulty : 'balanced';
    practiceHistory = Array.isArray(snapshot.practiceHistory) ? snapshot.practiceHistory : [];
    practiceTranscript = Array.isArray(snapshot.practiceTranscript) ? snapshot.practiceTranscript : [];
    sessionHistory = Array.isArray(snapshot.sessionHistory) ? snapshot.sessionHistory : [];
    liveCurrentCoach = snapshot.liveCurrentCoach && typeof snapshot.liveCurrentCoach === 'object' ? snapshot.liveCurrentCoach : null;
    practiceReviewContext = snapshot.practiceReviewContext && typeof snapshot.practiceReviewContext === 'object' ? snapshot.practiceReviewContext : null;
    practiceReviewState = snapshot.practiceReviewState && typeof snapshot.practiceReviewState === 'object' ? snapshot.practiceReviewState : null;
    chatHistory = Array.isArray(snapshot.chatHistory) ? snapshot.chatHistory : [];
    chatBot = snapshot.chatBot in CHAT_BOTS ? snapshot.chatBot : 'coach';
    chatMobileHasBot = !!snapshot.chatMobileHasBot;
    earOn = snapshot.earOn !== false;
    realtimeMode = snapshot.realtimeMode === 'practice' ? 'practice' : 'coach';
    liveRealtimeModel = snapshot.liveRealtimeModel in REALTIME_MODELS ? snapshot.liveRealtimeModel : 'gpt-realtime';

    syncSelectedScenarioCard();
    syncEarUI();
    restoreScreenFromSession(getRestoredScreenId(snapshot));
  } catch (_) {
    go(getDefaultEntryScreen(), { replaceHash: true });
  } finally {
    isRestoringSession = false;
    persistSessionState();
  }
}

window.addEventListener('hashchange', () => {
  if (isRestoringSession) return;
  const target = getScreenForRoute();
  if (!target || target === getActiveScreenId()) return;
  if (target === 's-key') {
    renderAuthState();
    go(authState.authenticated ? 's-auth' : 's-launch', { replaceHash: true });
    return;
  }
  if (authState.authenticated && target === 's-launch') {
    go(getSignedInDefaultScreen(), { replaceHash: true });
    return;
  }
  if (target === 's-plans') {
    restoreScreenFromSession(target);
    return;
  }
  if (!authState.authenticated) {
    go(['s-launch', 's-auth', 's-plans'].includes(target) ? target : 's-launch', { replaceHash: true });
    return;
  }
  if ((!currentSC || isScenarioLocked(currentSC)) && ['s-prep', 's-practice', 's-practice-voice', 's-live', 's-practice-review'].includes(target)) {
    go('s-home', { replaceHash: true });
    return;
  }
  restoreScreenFromSession(target);
});

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

(function initAuthInputs() {
  const email = document.getElementById('authEmail');
  const password = document.getElementById('authPassword');
  const displayName = document.getElementById('authDisplayName');
  const accountDisplayName = document.getElementById('accountDisplayNameInput');
  const accountOpenAIKey = document.getElementById('accountOpenAIKeyInput');
  if (displayName) {
    displayName.addEventListener('keydown', e => {
      if (e.key === 'Enter') email?.focus();
    });
  }
  if (email) {
    email.addEventListener('keydown', e => {
      if (e.key === 'Enter') password?.focus();
    });
  }
  if (password) {
    password.addEventListener('keydown', e => {
      if (e.key === 'Enter') submitAuth();
    });
  }
  if (accountDisplayName) {
    accountDisplayName.addEventListener('keydown', e => {
      if (e.key === 'Enter') saveAccountProfile();
    });
  }
  if (accountOpenAIKey) {
    accountOpenAIKey.addEventListener('keydown', e => {
      if (e.key === 'Enter') saveAccountApiKey();
    });
  }
})();

// ─────────────────────────────────────────────────────────────────────────────
// CLEANUP
// ─────────────────────────────────────────────────────────────────────────────
async function bootstrapApp() {
  setAuthMode('signin');
  startSessionPersistence();
  await refreshAuthState({ silent: true });
  restoreSessionState();
}

bootstrapApp();
