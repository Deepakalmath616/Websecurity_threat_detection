/**
 * CyberShield — phishing-detector.js
 * Phishing URL detection — connected to Flask backend API
 * Pure vanilla JS, no external libraries
 */

'use strict';

/* ─────────────────────────────────────────────────────────────
   CONFIG
───────────────────────────────────────────────────────────── */
const API_CONFIG = {
  endpoint: 'http://127.0.0.1:5000/check-url',
  timeout:  10000, // 10 seconds before we give up
};

/* ─────────────────────────────────────────────────────────────
   BACKEND API CALL
   Sends POST { url } to Flask and returns a normalised report
   object that the existing renderResults() can consume.
───────────────────────────────────────────────────────────── */

/**
 * Call the Flask /check-url endpoint.
 * @param {string} rawUrl
 * @returns {Promise<{ status: string, details: string }>}
 * @throws {ApiError}
 */
async function callBackendAPI(rawUrl) {
  // AbortController lets us enforce a timeout
  const controller = new AbortController();
  const timeoutId  = setTimeout(() => controller.abort(), API_CONFIG.timeout);

  let response;
  try {
    response = await fetch(API_CONFIG.endpoint, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url: rawUrl }),
      signal:  controller.signal,
    });
  } catch (err) {
    // Network-level failure (server down, CORS preflight blocked, etc.)
    if (err.name === 'AbortError') {
      throw new ApiError('timeout', 'The request timed out. The server took too long to respond.');
    }
    throw new ApiError('network', 'Cannot reach the backend server. Make sure Flask is running on port 5000.');
  } finally {
    clearTimeout(timeoutId);
  }

  // HTTP error status (4xx / 5xx)
  if (!response.ok) {
    let serverMsg = '';
    try {
      const errBody = await response.json();
      serverMsg = errBody.error || errBody.message || '';
    } catch { /* ignore parse errors on error bodies */ }

    if (response.status === 400) {
      throw new ApiError('validation', serverMsg || 'The server rejected the URL. Please check the format.');
    }
    if (response.status === 429) {
      throw new ApiError('ratelimit', 'Too many requests. Please wait a moment and try again.');
    }
    if (response.status >= 500) {
      throw new ApiError('server', serverMsg || `Server error (${response.status}). The backend encountered a problem.`);
    }
    throw new ApiError('http', serverMsg || `Unexpected response from server (HTTP ${response.status}).`);
  }

  // Parse JSON body
  let data;
  try {
    data = await response.json();
  } catch {
    throw new ApiError('parse', 'The server returned an unreadable response. Expected JSON.');
  }

  // Validate expected fields
  if (!data.status || !data.details) {
    throw new ApiError('parse', 'Unexpected response format from server. Missing "status" or "details" fields.');
  }

  return data; // { status: "Safe ✅", details: "No threats detected." }
}

/* ─────────────────────────────────────────────────────────────
   CUSTOM ERROR CLASS
───────────────────────────────────────────────────────────── */
class ApiError extends Error {
  /**
   * @param {'network'|'timeout'|'validation'|'ratelimit'|'server'|'http'|'parse'} code
   * @param {string} message
   */
  constructor(code, message) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
  }
}

/* ─────────────────────────────────────────────────────────────
   RESPONSE → REPORT MAPPER
   Converts the Flask API response into the internal report
   shape that renderResults() already understands.
   Also runs client-side URL parsing for the breakdown panel.
───────────────────────────────────────────────────────────── */

/**
 * Map API { status, details, threat_type, url } + raw URL into a
 * full report object that renderResults() consumes.
 *
 * Backend response shape (from app.py):
 *   { status, details, url, threat_type }
 *   threat_type: "MALWARE" | "SOCIAL_ENGINEERING" |
 *                "UNWANTED_SOFTWARE" | "POTENTIALLY_HARMFUL_APPLICATION" | null
 *
 * @param {string} rawUrl
 * @param {{ status: string, details: string, threat_type: string|null, url?: string }} apiData
 * @returns {object} report
 */
function buildReportFromApiResponse(rawUrl, apiData) {
  const { status, details, threat_type = null } = apiData;

  // ── 1. Determine threat level ──────────────────────────────
  // Primary source: threat_type from backend (most reliable)
  // Fallback: parse the status string
  let level;

  if (threat_type === null || threat_type === undefined) {
    // null threat_type means backend confirmed safe
    level = 'safe';
  } else if (threat_type === 'UNWANTED_SOFTWARE' || threat_type === 'POTENTIALLY_HARMFUL_APPLICATION') {
    level = 'suspicious';
  } else if (threat_type === 'MALWARE' || threat_type === 'SOCIAL_ENGINEERING') {
    level = 'danger';
  } else {
    // Unknown threat type — fall back to parsing the status string
    const s = status.toLowerCase();
    if (s.includes('safe') || s.includes('clean') || s.includes('legit')) {
      level = 'safe';
    } else if (s.includes('phishing') || s.includes('malicious') || s.includes('malware') ||
               s.includes('danger') || s.includes('threat') || s.includes('unsafe')) {
      level = 'danger';
    } else {
      level = 'suspicious';
    }
  }

  // ── 2. Security score ──────────────────────────────────────
  // Base score driven by the specific threat type for precision,
  // then blended with client-side URL structural signals (30%).
  const BASE_SCORES = {
    null:                              88,  // confirmed safe
    'SAFE':                            88,
    'SOCIAL_ENGINEERING':               8,  // phishing — most dangerous
    'MALWARE':                         10,  // malware
    'UNWANTED_SOFTWARE':               38,  // suspicious but not critical
    'POTENTIALLY_HARMFUL_APPLICATION': 42,
  };
  const baseScore  = BASE_SCORES[threat_type] ?? (level === 'safe' ? 85 : level === 'suspicious' ? 40 : 10);
  const urlSignals = getUrlSignals(rawUrl);
  const score      = Math.max(0, Math.min(100,
    Math.round(baseScore * 0.7 + urlSignals.heuristicScore * 0.3)
  ));

  // ── 3. Human-readable threat type label ───────────────────
  const THREAT_LABELS = {
    'MALWARE':                         'Malware',
    'SOCIAL_ENGINEERING':              'Phishing / Social Engineering',
    'UNWANTED_SOFTWARE':               'Unwanted Software',
    'POTENTIALLY_HARMFUL_APPLICATION': 'Potentially Harmful App',
  };
  const threatLabel = threat_type ? (THREAT_LABELS[threat_type] || threat_type) : null;

  // ── 4. Indicators list ────────────────────────────────────
  const verdictType = level === 'safe' ? 'pass' : level === 'suspicious' ? 'warn' : 'fail';
  const indicators  = [
    { text: `Google Safe Browsing verdict: ${status}`, type: verdictType },
    ...(threatLabel ? [{ text: `Threat classification: ${threatLabel}`, type: 'fail' }] : []),
    ...urlSignals.indicators,
  ];

  // ── 5. Flag chips ─────────────────────────────────────────
  const flags = [
    { label: threatLabel ? threatLabel : 'Google: Safe', type: verdictType },
    ...urlSignals.flags,
  ];

  return {
    score,
    level,
    flags,
    indicators,
    breakdown:   urlSignals.breakdown,
    explanation: details,    // backend's own explanation shown verbatim
    threatLabel,             // e.g. "Phishing / Social Engineering" or null
    protocol:    urlSignals.protocol,
  };
}

/* ─────────────────────────────────────────────────────────────
   CLIENT-SIDE URL SIGNAL EXTRACTOR
   Parses the URL in the browser to enrich the display with
   structural details (protocol, domain, path, query).
   Does NOT make any security decisions — that's the backend's job.
───────────────────────────────────────────────────────────── */
function getUrlSignals(rawUrl) {
  const fallback = {
    heuristicScore: 50,
    indicators: [],
    flags: [],
    breakdown: {
      protocol: { value: '—', highlight: 'pass' },
      domain:   { value: rawUrl, highlight: 'pass' },
      path:     { value: '/', highlight: 'pass' },
      query:    { value: 'none', highlight: 'pass' },
    },
    protocol: '',
  };

  let url;
  try {
    const normalized = /^https?:\/\//i.test(rawUrl) ? rawUrl : `http://${rawUrl}`;
    url = new URL(normalized);
  } catch {
    return fallback;
  }

  const hostname = url.hostname.toLowerCase();
  const protocol = url.protocol;
  const indicators = [];
  const flags      = [];
  let   score      = 100;

  // HTTPS
  if (protocol === 'https:') {
    flags.push({ label: 'HTTPS', type: 'pass' });
    indicators.push({ text: 'Encrypted HTTPS connection', type: 'pass' });
  } else {
    score -= 25;
    flags.push({ label: 'No HTTPS', type: 'fail' });
    indicators.push({ text: 'Unencrypted HTTP — data sent in plain text', type: 'fail' });
  }

  // IP address hostname
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score -= 30;
    flags.push({ label: 'IP Address URL', type: 'fail' });
    indicators.push({ text: 'URL uses a raw IP address instead of a domain name', type: 'fail' });
  }

  // Suspicious TLD
  const tld = '.' + hostname.split('.').pop();
  const suspiciousTlds = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.click','.bid','.win','.loan'];
  if (suspiciousTlds.includes(tld)) {
    score -= 20;
    flags.push({ label: `Risky TLD (${tld})`, type: 'warn' });
    indicators.push({ text: `TLD "${tld}" is frequently used in phishing campaigns`, type: 'warn' });
  }

  // Sensitive query params
  const sensitiveParams = ['password','passwd','token','auth','credential','secret','key','redirect'];
  const queryStr = url.search.toLowerCase();
  const foundParams = sensitiveParams.filter(p => queryStr.includes(p));
  if (foundParams.length > 0) {
    score -= 15;
    flags.push({ label: 'Sensitive Params', type: 'warn' });
    indicators.push({ text: `Query contains sensitive parameters: ${foundParams.join(', ')}`, type: 'warn' });
  }

  score = Math.max(0, Math.min(100, score));

  // Breakdown highlights
  const hasRiskyPath = ['login','verify','account','password','credential','update','confirm']
    .some(kw => url.pathname.toLowerCase().includes(kw));

  const breakdown = {
    protocol: { value: protocol.replace(':', ''), highlight: protocol === 'http:' ? 'fail' : 'pass' },
    domain:   { value: hostname, highlight: /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 'fail' : suspiciousTlds.includes(tld) ? 'warn' : 'pass' },
    path:     { value: url.pathname || '/', highlight: hasRiskyPath ? 'warn' : 'pass' },
    query:    { value: url.search || 'none', highlight: foundParams.length > 0 ? 'warn' : 'pass' },
  };

  return { heuristicScore: score, indicators, flags, breakdown, protocol };
}

/* ─────────────────────────────────────────────────────────────
   ERROR UI RENDERER
───────────────────────────────────────────────────────────── */
const ERROR_ICONS = {
  network:    '📡',
  timeout:    '⏱️',
  ratelimit:  '🚦',
  server:     '🖥️',
  validation: '⚠️',
  http:       '🔴',
  parse:      '📄',
};

function renderApiError(err) {
  const section = byId('resultsSection');
  section.hidden = false;
  section.scrollIntoView({ behavior: 'smooth', block: 'start' });

  const icon    = ERROR_ICONS[err.code] || '❌';
  const isRetry = ['network', 'timeout', 'server', 'ratelimit'].includes(err.code);

  // Reuse the verdict banner with a special "error" appearance
  const banner = byId('verdictBanner');
  banner.className = 'verdict-banner error-state fade-in';
  banner.style.cssText = `
    background: linear-gradient(135deg, rgba(239,68,68,.06) 0%, transparent 60%);
    border-color: rgba(239,68,68,.35);
    box-shadow: 0 0 40px rgba(239,68,68,.08);
  `;

  byId('verdictIconWrap').textContent = icon;
  byId('verdictIconWrap').style.cssText = `
    background: rgba(239,68,68,.12);
    border: 1px solid rgba(239,68,68,.3);
  `;
  byId('verdictTitle').textContent    = 'Analysis Failed';
  byId('verdictTitle').style.color    = '#ef4444';
  byId('verdictSubtitle').textContent = err.message;

  // Hide score ring — not meaningful for errors
  const scoreWrap = document.querySelector('.verdict-score-wrap');
  if (scoreWrap) scoreWrap.style.display = 'none';

  // Hide detail cards
  byId('threatStatusCard').hidden      = true;
  byId('threatExplanationCard').hidden = true;
  byId('urlBreakdownCard').hidden      = true;
  byId('recommendationsCard').hidden   = true;

  // Show a helpful error detail card instead
  let errorCard = byId('apiErrorCard');
  if (!errorCard) {
    errorCard = document.createElement('div');
    errorCard.id        = 'apiErrorCard';
    errorCard.className = 'result-card fade-in';
    // Insert before result-actions
    const actions = document.querySelector('.result-actions');
    actions.parentNode.insertBefore(errorCard, actions);
  }
  errorCard.hidden = false;

  const tips = {
    network:    ['Make sure your Flask server is running: <code>python app.py</code>', 'Check that it is listening on <code>http://127.0.0.1:5000</code>', 'Ensure CORS is enabled in Flask (install <code>flask-cors</code>)'],
    timeout:    ['The server is taking too long — check for slow ML model loading', 'Try again in a moment', 'Check Flask terminal for errors'],
    ratelimit:  ['You have sent too many requests', 'Wait 30 seconds and try again'],
    server:     ['Flask returned a 5xx error — check the terminal for a traceback', 'Restart the Flask server and try again'],
    validation: ['The URL format was rejected by the server', 'Try a full URL including <code>https://</code>'],
    http:       ['The server returned an unexpected status code', 'Check the Flask terminal for details'],
    parse:      ['The server response could not be parsed as JSON', 'Ensure your Flask route returns <code>jsonify({"status": ..., "details": ...})</code>'],
  };

  const tipList = (tips[err.code] || ['Check the browser console (F12) for more details.']).map(t => `<li>→ ${t}</li>`).join('');

  errorCard.innerHTML = `
    <div class="result-card-header">
      <span class="result-card-icon">🔧</span>
      <h3 class="result-card-title">Troubleshooting</h3>
    </div>
    <ul style="list-style:none;display:flex;flex-direction:column;gap:8px;font-size:.88rem;color:var(--text-secondary);line-height:1.6;">
      ${tipList}
    </ul>
    ${isRetry ? `<button class="btn btn-secondary" id="retryBtn" style="margin-top:16px;width:100%;justify-content:center;">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 4v6h6"/><path d="M3.51 15a9 9 0 1 0 .49-4.5"/></svg>
      Retry
    </button>` : ''}
  `;

  // Trigger fade-in
  setTimeout(() => {
    section.querySelectorAll('.fade-in').forEach(e => e.classList.add('visible'));
  }, 50);
}

/** Reset any error-state styling left on the verdict banner */
function clearErrorState() {
  const banner = byId('verdictBanner');
  banner.style.cssText = '';
  byId('verdictIconWrap').style.cssText = '';
  byId('verdictTitle').style.color = '';

  const scoreWrap = document.querySelector('.verdict-score-wrap');
  if (scoreWrap) scoreWrap.style.display = '';

  byId('threatStatusCard').hidden      = false;
  byId('threatExplanationCard').hidden = false;
  byId('urlBreakdownCard').hidden      = false;
  byId('recommendationsCard').hidden   = false;

  const errorCard = byId('apiErrorCard');
  if (errorCard) errorCard.hidden = true;

  // Hide threat type badge until next result renders it
  const badge = byId('threatTypeBadge');
  if (badge) badge.hidden = true;
}

/* ─────────────────────────────────────────────────────────────
   RESULT CONTENT GENERATORS
───────────────────────────────────────────────────────────── */

const VERDICTS = {
  safe: {
    icon: '✅',
    title: 'URL Appears Safe',
    subtitle: 'No significant phishing indicators were detected. Exercise normal caution when visiting.',
  },
  suspicious: {
    icon: '⚠️',
    title: 'Suspicious URL Detected',
    subtitle: 'Several risk factors were identified. Proceed with caution and verify the source.',
  },
  danger: {
    icon: '🚨',
    title: 'High Threat Detected',
    subtitle: 'This URL exhibits strong phishing characteristics. Do NOT visit this link.',
  },
};

/**
 * Return the explanation text for the results panel.
 * Prefers the backend's own details string; falls back to a
 * generic message if the backend didn't provide one.
 */
function getExplanation(level, report) {
  // Use the backend's explanation if it exists and is meaningful
  if (report.explanation && report.explanation.trim().length > 5) {
    return report.explanation;
  }
  // Generic fallbacks
  if (level === 'safe') {
    return 'The backend analysis found no phishing indicators for this URL. Always verify the sender before clicking links.';
  }
  if (level === 'suspicious') {
    return 'The backend flagged this URL as suspicious. While not definitively malicious, proceed with caution and verify the source.';
  }
  return 'The backend classified this URL as a phishing threat. Do not visit this link — it may attempt to steal credentials or install malware.';
}

function getRecommendations(level, report) {
  const common = [
    { icon: '🔍', text: 'Always hover over links to preview the destination URL before clicking.' },
    { icon: '🔒', text: 'Prefer HTTPS links — look for the padlock icon in your browser.' },
  ];

  if (level === 'safe') {
    return [
      { icon: '✅', text: 'This URL appears safe to visit. Standard browsing precautions apply.' },
      { icon: '🛡️', text: 'Keep your browser and security software up to date for ongoing protection.' },
      ...common,
    ];
  }
  if (level === 'suspicious') {
    return [
      { icon: '⚠️', text: 'Do not enter personal information or credentials on this page.' },
      { icon: '📧', text: 'If received via email, verify the sender\'s identity through a separate channel.' },
      { icon: '🔗', text: 'Navigate directly to the official website instead of using this link.' },
      ...common,
    ];
  }
  return [
    { icon: '🚫', text: 'Do NOT visit this URL. Close any tabs that may have already opened it.' },
    { icon: '🔑', text: 'If you already visited and entered credentials, change your passwords immediately.' },
    { icon: '📢', text: 'Report this URL to your IT/security team and to phishtank.com.' },
    { icon: '🛡️', text: 'Run a malware scan if you clicked the link or downloaded any files.' },
    ...common,
  ];
}

/* ─────────────────────────────────────────────────────────────
   DOM HELPERS
   byId(id)           — document.getElementById shorthand
   mkEl(tag, cls, html) — create element with optional class/html
   These are intentionally different names from main.js's $ / $$
   (which use querySelector) to avoid redeclaration conflicts.
───────────────────────────────────────────────────────────── */
const byId = id => document.getElementById(id);
const mkEl = (tag, cls, html) => {
  const e = document.createElement(tag);
  if (cls)              e.className   = cls;
  if (html !== undefined) e.innerHTML = html;
  return e;
};

/* ─────────────────────────────────────────────────────────────
   MINI MATRIX CANVAS (page hero background)
───────────────────────────────────────────────────────────── */
(function initMiniMatrix() {
  const canvas = document.getElementById('miniMatrix');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const CHARS = '01アイウエオABCDEF<>/\\{}[]';
  const FS = 13;
  let cols, drops;

  function resize() {
    canvas.width  = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    cols  = Math.floor(canvas.width / FS);
    drops = new Array(cols).fill(1);
  }

  function draw() {
    ctx.fillStyle = 'rgba(10,14,26,0.06)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = `${FS}px monospace`;
    for (let i = 0; i < drops.length; i++) {
      const ch = CHARS[Math.floor(Math.random() * CHARS.length)];
      const y  = drops[i] * FS;
      const a  = Math.max(0.1, 1 - y / canvas.height);
      ctx.fillStyle = `rgba(0,255,136,${a})`;
      ctx.fillText(ch, i * FS, y);
      if (y > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }

  resize();
  window.addEventListener('resize', resize, { passive: true });
  let id;
  (function loop() { draw(); id = requestAnimationFrame(loop); })();
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) cancelAnimationFrame(id);
    else (function loop() { draw(); id = requestAnimationFrame(loop); })();
  });
})();

/* ─────────────────────────────────────────────────────────────
   LOADING SEQUENCE
───────────────────────────────────────────────────────────── */
const LOAD_STEPS = [
  'Initializing threat scanner...',
  'Checking domain reputation...',
  'Validating SSL certificate...',
  'Running phishing pattern analysis...',
  'Querying blacklist databases...',
  'Classifying with ML model...',
  'Generating threat report...',
];

function runLoadingSequence(onComplete) {
  const loader   = byId('analysisLoader');
  const bar      = byId('loaderBar');
  const stepEl   = byId('loaderStep');
  const checks   = ['lc1','lc2','lc3','lc4','lc5'];

  loader.hidden = false;
  loader.scrollIntoView({ behavior: 'smooth', block: 'center' });

  let stepIdx = 0;
  let checkIdx = 0;
  const totalDuration = 2600; // ms
  const stepInterval  = totalDuration / LOAD_STEPS.length;

  // Progress bar
  let progress = 0;
  const barInterval = setInterval(() => {
    progress = Math.min(progress + 1.8, 98);
    bar.style.width = progress + '%';
  }, totalDuration / 60);

  // Step text
  const stepTimer = setInterval(() => {
    stepIdx++;
    if (stepIdx < LOAD_STEPS.length) {
      stepEl.style.opacity = '0';
      setTimeout(() => {
        stepEl.textContent = LOAD_STEPS[stepIdx];
        stepEl.style.opacity = '1';
      }, 150);
    }
  }, stepInterval);

  // Check items
  const checkTimer = setInterval(() => {
    if (checkIdx < checks.length) {
      const lcEl = byId(checks[checkIdx]);
      if (lcEl) {
        lcEl.classList.add('active');
        lcEl.querySelector('.lc-icon').classList.remove('pending');
        lcEl.querySelector('.lc-icon').classList.add('active');
        lcEl.querySelector('.lc-icon').textContent = '◉';
      }
      // Mark previous as done
      if (checkIdx > 0) {
        const prev = byId(checks[checkIdx - 1]);
        if (prev) {
          prev.classList.remove('active');
          prev.classList.add('done');
          prev.querySelector('.lc-icon').classList.remove('active');
          prev.querySelector('.lc-icon').classList.add('done');
          prev.querySelector('.lc-icon').textContent = '✓';
        }
      }
      checkIdx++;
    }
  }, totalDuration / checks.length);

  // Complete
  setTimeout(() => {
    clearInterval(barInterval);
    clearInterval(stepTimer);
    clearInterval(checkTimer);

    // Mark last check done
    const lastCheck = byId(checks[checks.length - 1]);
    if (lastCheck) {
      lastCheck.classList.remove('active');
      lastCheck.classList.add('done');
      lastCheck.querySelector('.lc-icon').classList.remove('active');
      lastCheck.querySelector('.lc-icon').classList.add('done');
      lastCheck.querySelector('.lc-icon').textContent = '✓';
    }

    bar.style.width = '100%';
    stepEl.textContent = 'Analysis complete.';

    setTimeout(() => {
      loader.hidden = true;
      onComplete();
    }, 400);
  }, totalDuration);
}

/* ─────────────────────────────────────────────────────────────
   RENDER RESULTS
───────────────────────────────────────────────────────────── */
function renderResults(report) {
  const section = byId('resultsSection');
  section.hidden = false;
  section.scrollIntoView({ behavior: 'smooth', block: 'start' });

  const { score, level, flags, indicators, breakdown, threatLabel } = report;
  const verdict = VERDICTS[level];

  // ── Verdict banner ──────────────────────────────────────────
  const banner = byId('verdictBanner');
  banner.className = `verdict-banner fade-in ${level}`;

  byId('verdictIconWrap').textContent = verdict.icon;
  byId('verdictTitle').textContent    = verdict.title;
  byId('verdictSubtitle').textContent = verdict.subtitle;

  // Score ring animation
  const circumference = 201; // 2π × 32
  const offset = circumference - (score / 100) * circumference;
  const fill = byId('scoreFill');
  fill.style.strokeDashoffset = circumference;
  setTimeout(() => { fill.style.strokeDashoffset = offset; }, 100);

  // Animate score number
  animateNumber(byId('scoreNumber'), 0, score, 1200);

  // ── Threat level bar ────────────────────────────────────────
  const fillPct = 100 - score;
  setTimeout(() => {
    byId('threatLevelFill').style.width  = fillPct + '%';
    byId('threatLevelThumb').style.left  = fillPct + '%';
  }, 200);

  // Threat indicators
  const indContainer = byId('threatIndicators');
  indContainer.innerHTML = '';
  indicators.slice(0, 5).forEach(ind => {
    const row = mkEl('div', 'threat-indicator');
    row.innerHTML = `<span class="ti-dot ${ind.type}"></span><span>${escapeHtml(ind.text)}</span>`;
    indContainer.appendChild(row);
  });

  // ── Analysis Details card ───────────────────────────────────
  // Show backend explanation text
  byId('explanationText').textContent = getExplanation(level, report);

  // Threat type badge — injected right after the explanation text
  let threatTypeBadge = byId('threatTypeBadge');
  if (!threatTypeBadge) {
    threatTypeBadge = document.createElement('div');
    threatTypeBadge.id = 'threatTypeBadge';
    threatTypeBadge.style.cssText = 'margin-bottom: 14px;';
    byId('explanationText').insertAdjacentElement('afterend', threatTypeBadge);
  }

  if (threatLabel) {
    const badgeType = level === 'danger' ? 'fail' : 'warn';
    threatTypeBadge.innerHTML = `
      <div style="display:flex;align-items:center;gap:10px;padding:10px 14px;
                  border-radius:8px;background:${level === 'danger' ? 'rgba(239,68,68,.08)' : 'rgba(245,158,11,.08)'};
                  border:1px solid ${level === 'danger' ? 'rgba(239,68,68,.25)' : 'rgba(245,158,11,.25)'};
                  margin-bottom:4px;">
        <span style="font-size:1rem;">${level === 'danger' ? '🚨' : '⚠️'}</span>
        <div>
          <div style="font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.6px;
                      color:var(--text-secondary);margin-bottom:2px;">Threat Type</div>
          <div style="font-size:.9rem;font-weight:700;
                      color:${level === 'danger' ? '#ef4444' : '#f59e0b'};">${escapeHtml(threatLabel)}</div>
        </div>
        <span class="flag-chip ${badgeType}" style="margin-left:auto;">
          Google Safe Browsing
        </span>
      </div>`;
    threatTypeBadge.hidden = false;
  } else {
    // Safe — show a "Verified Safe" badge instead
    threatTypeBadge.innerHTML = `
      <div style="display:flex;align-items:center;gap:10px;padding:10px 14px;
                  border-radius:8px;background:rgba(0,255,136,.06);
                  border:1px solid rgba(0,255,136,.2);margin-bottom:4px;">
        <span style="font-size:1rem;">✅</span>
        <div>
          <div style="font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.6px;
                      color:var(--text-secondary);margin-bottom:2px;">Threat Type</div>
          <div style="font-size:.9rem;font-weight:700;color:var(--accent-green);">None Detected</div>
        </div>
        <span class="flag-chip pass" style="margin-left:auto;">Google Safe Browsing</span>
      </div>`;
    threatTypeBadge.hidden = false;
  }

  // Flag chips
  const flagsContainer = byId('explanationFlags');
  flagsContainer.innerHTML = '';
  flags.slice(0, 6).forEach(f => {
    const chip = mkEl('span', `flag-chip ${f.type}`, escapeHtml(f.label));
    flagsContainer.appendChild(chip);
  });

  // ── URL Breakdown ───────────────────────────────────────────
  const bkContainer = byId('urlBreakdown');
  bkContainer.innerHTML = '';
  const parts = [
    { label: 'Protocol', key: 'protocol' },
    { label: 'Domain',   key: 'domain' },
    { label: 'Path',     key: 'path' },
    { label: 'Query',    key: 'query' },
  ];
  parts.forEach(p => {
    const part = breakdown[p.key];
    const wrap = mkEl('div', 'url-part');
    wrap.innerHTML = `
      <span class="url-part-label">${p.label}</span>
      <span class="url-part-value highlight-${part.highlight}">${escapeHtml(part.value)}</span>
    `;
    bkContainer.appendChild(wrap);
  });

  // ── Recommendations ─────────────────────────────────────────
  const recList = byId('recommendationsList');
  recList.innerHTML = '';
  getRecommendations(level, report).forEach(r => {
    const item = mkEl('li', 'rec-item');
    item.innerHTML = `<span class="rec-icon">${r.icon}</span><span>${r.text}</span>`;
    recList.appendChild(item);
  });

  // Trigger fade-in for result sub-elements
  setTimeout(() => {
    section.querySelectorAll('.fade-in').forEach(e => e.classList.add('visible'));
  }, 50);
}

function animateNumber(el, from, to, duration) {
  const start = performance.now();
  function step(now) {
    const t = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(from + (to - from) * eased);
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* ─────────────────────────────────────────────────────────────
   FORM LOGIC
───────────────────────────────────────────────────────────── */
(function initForm() {
  const form       = byId('urlForm');
  const input      = byId('urlInput');
  const clearBtn   = byId('clearBtn');
  const scanBtn    = byId('scanBtn');
  const inputGroup = byId('inputGroup');
  const inputError = byId('inputError');
  const demoBtn    = byId('demoBtn');
  const demoPanel  = byId('demoPanel');

  // Show/hide clear button
  input.addEventListener('input', () => {
    clearBtn.classList.toggle('visible', input.value.length > 0);
    inputGroup.classList.remove('error');
    inputError.textContent = '';
  });

  clearBtn.addEventListener('click', () => {
    input.value = '';
    clearBtn.classList.remove('visible');
    input.focus();
    inputGroup.classList.remove('error');
    inputError.textContent = '';
  });

  // Demo panel toggle
  demoBtn.addEventListener('click', () => {
    const isHidden = demoPanel.hidden;
    demoPanel.hidden = !isHidden;
    demoBtn.textContent = isHidden ? 'Hide Demo URLs' : 'Try Demo URLs';
    // Re-add arrow SVG
    demoBtn.innerHTML = (isHidden ? 'Hide Demo URLs' : 'Try Demo URLs') +
      `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="${isHidden ? 'M18 15l-6-6-6 6' : 'M5 12h14M12 5l7 7-7 7'}"/>
      </svg>`;
  });

  // Demo URL selection
  demoPanel.addEventListener('click', e => {
    const btn = e.target.closest('.demo-url-btn');
    if (!btn) return;
    input.value = btn.dataset.url;
    clearBtn.classList.add('visible');
    demoPanel.hidden = true;
    demoBtn.innerHTML = 'Try Demo URLs <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>';
    input.focus();
  });

  // Form submit
  form.addEventListener('submit', e => {
    e.preventDefault();
    handleScan();
  });

  // Also allow Enter key
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); handleScan(); }
  });

  async function handleScan() {
    const raw = input.value.trim();

    // ── Client-side validation ──────────────────────────────
    if (!raw) {
      showError('Please enter a URL to analyze.');
      return;
    }
    const normalized = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
    try { new URL(normalized); } catch {
      showError('Please enter a valid URL (e.g. https://example.com).');
      return;
    }

    // ── Reset UI state ──────────────────────────────────────
    byId('resultsSection').hidden = true;
    byId('analysisLoader').hidden = true;
    clearErrorState();

    ['lc1','lc2','lc3','lc4','lc5'].forEach(id => {
      const lcEl = byId(id);
      if (!lcEl) return;
      lcEl.className = 'loader-check';
      const icon = lcEl.querySelector('.lc-icon');
      icon.className = 'lc-icon pending';
      icon.textContent = '○';
    });
    byId('loaderBar').style.width = '0%';
    byId('loaderStep').textContent = 'Initializing threat scanner...';

    scanBtn.classList.add('loading');
    scanBtn.disabled = true;

    // ── Run API call and loading animation in parallel ──────
    // The animation always runs for its full duration so the UI
    // feels deliberate. The API result is stored and used once
    // the animation completes.
    let apiResult   = null;   // { status, details } on success
    let apiError    = null;   // ApiError instance on failure

    const [, apiOutcome] = await Promise.allSettled([
      // Animation promise — resolves after the sequence finishes
      new Promise(resolve => runLoadingSequence(resolve)),
      // API call promise
      callBackendAPI(raw),
    ]);

    scanBtn.classList.remove('loading');
    scanBtn.disabled = false;

    if (apiOutcome.status === 'fulfilled') {
      apiResult = apiOutcome.value;
    } else {
      apiError = apiOutcome.reason;
    }

    // ── Render outcome ──────────────────────────────────────
    if (apiError) {
      renderApiError(apiError);
    } else {
      const report = buildReportFromApiResponse(raw, apiResult);
      renderResults(report);
    }
  }

  function showError(msg) {
    inputGroup.classList.add('error');
    inputError.textContent = msg;
    input.focus();
  }

  // Retry button (rendered inside error card)
  document.addEventListener('click', e => {
    if (e.target.closest('#retryBtn')) {
      byId('resultsSection').hidden = true;
      handleScan();
    }
  });

  // Scan Another
  document.addEventListener('click', e => {
    if (e.target.closest('#scanAnotherBtn')) {
      byId('resultsSection').hidden = true;
      input.value = '';
      clearBtn.classList.remove('visible');
      inputGroup.classList.remove('error');
      inputError.textContent = '';
      window.scrollTo({ top: 0, behavior: 'smooth' });
      setTimeout(() => input.focus(), 600);
    }
  });

  // Copy Report
  document.addEventListener('click', e => {
    if (!e.target.closest('#copyReportBtn')) return;
    const btn    = byId('copyReportBtn');
    const score  = byId('scoreNumber').textContent;
    const title  = byId('verdictTitle').textContent;
    const detail = byId('explanationText').textContent;
    const url    = input.value.trim();

    // Pull threat type label from the badge if present
    const threatTypeEl = document.querySelector('#threatTypeBadge [style*="font-weight:700"]');
    const threatType   = threatTypeEl ? threatTypeEl.textContent.trim() : 'N/A';

    const text = [
      '=== CyberShield URL Threat Report ===',
      `URL:            ${url}`,
      `Verdict:        ${title}`,
      `Threat Type:    ${threatType}`,
      `Security Score: ${score}/100`,
      '',
      'Analysis:',
      detail,
      '',
      `Generated: ${new Date().toLocaleString()}`,
      'CyberShield — Integrated Web Security & Threat Detection System',
    ].join('\n');

    navigator.clipboard.writeText(text).then(() => {
      const orig = btn.innerHTML;
      btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg> Copied!`;
      setTimeout(() => { btn.innerHTML = orig; }, 2000);
    }).catch(() => {
      alert('Copy failed. Please copy the report manually.');
    });
  });
})();

/* ─────────────────────────────────────────────────────────────
   SCROLL ANIMATIONS (fade-in for static elements)
───────────────────────────────────────────────────────────── */
(function initScrollFade() {
  const els = document.querySelectorAll('.fade-in');
  const obs = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        obs.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });

  els.forEach(e => {
    const delay = e.dataset.delay;
    if (delay) e.style.transitionDelay = `${delay}ms`;
    obs.observe(e);
  });
})();
