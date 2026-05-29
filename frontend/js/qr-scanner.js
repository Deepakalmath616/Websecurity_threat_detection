/**
 * CyberShield — qr-scanner.js
 * QR Code Threat Detection — decodes QR images in-browser via jsQR,
 * then sends any embedded URL to the Flask /check-url API.
 *
 * Uses byId() / mkEl() helpers to avoid conflicts with main.js $ / $$.
 */

'use strict';

/* ─────────────────────────────────────────────────────────────
   DOM HELPERS
───────────────────────────────────────────────────────────── */
const byId = id => document.getElementById(id);
const mkEl = (tag, cls, html) => {
  const e = document.createElement(tag);
  if (cls)              e.className   = cls;
  if (html !== undefined) e.innerHTML = html;
  return e;
};

/* ─────────────────────────────────────────────────────────────
   CONFIG
───────────────────────────────────────────────────────────── */
const API_ENDPOINT = 'http://127.0.0.1:5000/check-url';
const API_TIMEOUT  = 10000; // 10 s

/* ─────────────────────────────────────────────────────────────
   QR CONTENT TYPE CLASSIFIER
───────────────────────────────────────────────────────────── */
function classifyQrContent(text) {
  if (/^https?:\/\//i.test(text))                          return { type: 'URL',      label: 'URL',         isUrl: true  };
  if (/^www\./i.test(text))                                return { type: 'URL',      label: 'URL',         isUrl: true  };
  if (/^BEGIN:VCARD/i.test(text))                          return { type: 'VCARD',    label: 'Contact Card',isUrl: false };
  if (/^WIFI:/i.test(text))                                return { type: 'WIFI',     label: 'Wi-Fi Config',isUrl: false };
  if (/^BEGIN:VEVENT/i.test(text))                         return { type: 'CALENDAR', label: 'Calendar',    isUrl: false };
  if (/^(mailto:|MAILTO:)/.test(text))                     return { type: 'EMAIL',    label: 'Email',       isUrl: false };
  if (/^(tel:|TEL:)/.test(text))                           return { type: 'PHONE',    label: 'Phone',       isUrl: false };
  if (/^(smsto:|sms:|SMS:)/i.test(text))                   return { type: 'SMS',      label: 'SMS',         isUrl: false };
  if (/^(geo:|GEO:)/i.test(text))                          return { type: 'GEO',      label: 'Location',    isUrl: false };
  if (/^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(text))
                                                           return { type: 'EMAIL',    label: 'Email',       isUrl: false };
  return                                                          { type: 'TEXT',     label: 'Plain Text',  isUrl: false };
}

/* ─────────────────────────────────────────────────────────────
   QR DECODER  (uses jsQR loaded via CDN script tag)
───────────────────────────────────────────────────────────── */
function decodeQrFromFile(file) {
  return new Promise((resolve, reject) => {
    if (!window.jsQR) {
      reject(new Error('jsQR library not loaded. Check your internet connection.'));
      return;
    }

    const img    = new Image();
    const reader = new FileReader();

    reader.onload = e => { img.src = e.target.result; };
    reader.onerror = () => reject(new Error('Could not read the image file.'));

    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width  = img.naturalWidth;
      canvas.height = img.naturalHeight;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);

      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = window.jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: 'dontInvert',
      });

      if (code) {
        resolve(code.data);
      } else {
        // Try with inverted colours (some QR codes are dark-on-light)
        const code2 = window.jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: 'onlyInvert',
        });
        if (code2) {
          resolve(code2.data);
        } else {
          reject(new Error('No QR code detected in this image. Make sure the image is clear and contains a valid QR code.'));
        }
      }
    };

    img.onerror = () => reject(new Error('The image could not be loaded. Please try a different file.'));
    reader.readAsDataURL(file);
  });
}

/* ─────────────────────────────────────────────────────────────
   BACKEND API CALL  (reused from phishing-detector pattern)
───────────────────────────────────────────────────────────── */
class ApiError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
  }
}

async function callCheckUrl(rawUrl) {
  const controller = new AbortController();
  const tid = setTimeout(() => controller.abort(), API_TIMEOUT);

  let response;
  try {
    response = await fetch(API_ENDPOINT, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url: rawUrl }),
      signal:  controller.signal,
    });
  } catch (err) {
    if (err.name === 'AbortError') throw new ApiError('timeout', 'The request timed out. Make sure Flask is running on port 5000.');
    throw new ApiError('network', 'Cannot reach the backend server. Make sure Flask is running on port 5000.');
  } finally {
    clearTimeout(tid);
  }

  if (!response.ok) {
    let msg = '';
    try { const b = await response.json(); msg = b.error || b.message || ''; } catch {}
    if (response.status === 400) throw new ApiError('validation', msg || 'The server rejected the URL.');
    if (response.status === 429) throw new ApiError('ratelimit',  'Too many requests. Please wait and try again.');
    if (response.status >= 500)  throw new ApiError('server',     msg || `Server error (${response.status}).`);
    throw new ApiError('http', msg || `Unexpected HTTP ${response.status}.`);
  }

  let data;
  try { data = await response.json(); } catch { throw new ApiError('parse', 'Server returned unreadable response.'); }
  if (!data.status || !data.details) throw new ApiError('parse', 'Missing "status" or "details" in server response.');
  return data;
}

/* ─────────────────────────────────────────────────────────────
   RESPONSE → REPORT MAPPER  (same logic as phishing-detector)
───────────────────────────────────────────────────────────── */
function buildReport(rawUrl, apiData) {
  const { status, details, threat_type = null } = apiData;

  let level;
  if (!threat_type) {
    level = 'safe';
  } else if (threat_type === 'UNWANTED_SOFTWARE' || threat_type === 'POTENTIALLY_HARMFUL_APPLICATION') {
    level = 'suspicious';
  } else {
    level = 'danger';
  }

  const BASE = { null: 88, SOCIAL_ENGINEERING: 8, MALWARE: 10, UNWANTED_SOFTWARE: 38, POTENTIALLY_HARMFUL_APPLICATION: 42 };
  const baseScore  = BASE[threat_type] ?? (level === 'safe' ? 85 : level === 'suspicious' ? 40 : 10);
  const urlSignals = getUrlSignals(rawUrl);
  const score      = Math.max(0, Math.min(100, Math.round(baseScore * 0.7 + urlSignals.heuristicScore * 0.3)));

  const LABELS = { MALWARE: 'Malware', SOCIAL_ENGINEERING: 'Phishing / Social Engineering', UNWANTED_SOFTWARE: 'Unwanted Software', POTENTIALLY_HARMFUL_APPLICATION: 'Potentially Harmful App' };
  const threatLabel = threat_type ? (LABELS[threat_type] || threat_type) : null;

  const vt = level === 'safe' ? 'pass' : level === 'suspicious' ? 'warn' : 'fail';
  const indicators = [
    { text: `Google Safe Browsing: ${status}`, type: vt },
    ...(threatLabel ? [{ text: `Threat type: ${threatLabel}`, type: 'fail' }] : []),
    ...urlSignals.indicators,
  ];
  const flags = [
    { label: threatLabel || 'Google: Safe', type: vt },
    ...urlSignals.flags,
  ];

  return { score, level, flags, indicators, breakdown: urlSignals.breakdown, explanation: details, threatLabel };
}

function getUrlSignals(rawUrl) {
  const fallback = { heuristicScore: 50, indicators: [], flags: [], breakdown: { protocol: { value: '—', highlight: 'pass' }, domain: { value: rawUrl, highlight: 'pass' }, path: { value: '/', highlight: 'pass' }, query: { value: 'none', highlight: 'pass' } }, protocol: '' };
  let url;
  try { url = new URL(/^https?:\/\//i.test(rawUrl) ? rawUrl : `http://${rawUrl}`); } catch { return fallback; }

  const hostname = url.hostname.toLowerCase();
  const protocol = url.protocol;
  const indicators = [], flags = [];
  let score = 100;

  if (protocol === 'https:') { flags.push({ label: 'HTTPS', type: 'pass' }); indicators.push({ text: 'Encrypted HTTPS connection', type: 'pass' }); }
  else { score -= 25; flags.push({ label: 'No HTTPS', type: 'fail' }); indicators.push({ text: 'Unencrypted HTTP connection', type: 'fail' }); }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) { score -= 30; flags.push({ label: 'IP Address URL', type: 'fail' }); indicators.push({ text: 'URL uses raw IP address', type: 'fail' }); }

  const tld = '.' + hostname.split('.').pop();
  const badTlds = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.click','.bid','.win','.loan'];
  if (badTlds.includes(tld)) { score -= 20; flags.push({ label: `Risky TLD (${tld})`, type: 'warn' }); indicators.push({ text: `TLD "${tld}" frequently used in phishing`, type: 'warn' }); }

  const sensitiveParams = ['password','passwd','token','auth','credential','secret','key','redirect'];
  const foundParams = sensitiveParams.filter(p => url.search.toLowerCase().includes(p));
  if (foundParams.length) { score -= 15; flags.push({ label: 'Sensitive Params', type: 'warn' }); indicators.push({ text: `Sensitive query params: ${foundParams.join(', ')}`, type: 'warn' }); }

  score = Math.max(0, Math.min(100, score));
  const hasRiskyPath = ['login','verify','account','password','credential','update','confirm'].some(kw => url.pathname.toLowerCase().includes(kw));

  return {
    heuristicScore: score, indicators, flags, protocol,
    breakdown: {
      protocol: { value: protocol.replace(':', ''), highlight: protocol === 'http:' ? 'fail' : 'pass' },
      domain:   { value: hostname, highlight: /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 'fail' : badTlds.includes(tld) ? 'warn' : 'pass' },
      path:     { value: url.pathname || '/', highlight: hasRiskyPath ? 'warn' : 'pass' },
      query:    { value: url.search || 'none', highlight: foundParams.length ? 'warn' : 'pass' },
    },
  };
}

/* ─────────────────────────────────────────────────────────────
   LOADING SEQUENCE
───────────────────────────────────────────────────────────── */
const LOAD_STEPS = [
  'Decoding QR payload...',
  'Extracting embedded content...',
  'Detecting URL patterns...',
  'Querying threat intelligence...',
  'Generating security report...',
];

function runLoadingSequence(onComplete) {
  const loader  = byId('decodeLoader');
  const bar     = byId('loaderBar');
  const stepEl  = byId('loaderStep');
  const checks  = ['lc1','lc2','lc3','lc4','lc5'];

  loader.hidden = false;
  loader.scrollIntoView({ behavior: 'smooth', block: 'center' });

  let stepIdx = 0, checkIdx = 0;
  const total = 2800;

  let progress = 0;
  const barInt = setInterval(() => { progress = Math.min(progress + 1.8, 98); bar.style.width = progress + '%'; }, total / 60);

  const stepInt = setInterval(() => {
    stepIdx++;
    if (stepIdx < LOAD_STEPS.length) {
      stepEl.style.opacity = '0';
      setTimeout(() => { stepEl.textContent = LOAD_STEPS[stepIdx]; stepEl.style.opacity = '1'; }, 150);
    }
  }, total / LOAD_STEPS.length);

  const checkInt = setInterval(() => {
    if (checkIdx < checks.length) {
      const lc = byId(checks[checkIdx]);
      if (lc) { lc.classList.add('active'); lc.querySelector('.lc-icon').className = 'lc-icon active'; lc.querySelector('.lc-icon').textContent = '◉'; }
      if (checkIdx > 0) {
        const prev = byId(checks[checkIdx - 1]);
        if (prev) { prev.classList.remove('active'); prev.classList.add('done'); prev.querySelector('.lc-icon').className = 'lc-icon done'; prev.querySelector('.lc-icon').textContent = '✓'; }
      }
      checkIdx++;
    }
  }, total / checks.length);

  setTimeout(() => {
    clearInterval(barInt); clearInterval(stepInt); clearInterval(checkInt);
    const last = byId(checks[checks.length - 1]);
    if (last) { last.classList.remove('active'); last.classList.add('done'); last.querySelector('.lc-icon').className = 'lc-icon done'; last.querySelector('.lc-icon').textContent = '✓'; }
    bar.style.width = '100%';
    stepEl.textContent = 'Analysis complete.';
    setTimeout(() => { loader.hidden = true; onComplete(); }, 400);
  }, total);
}

/* ─────────────────────────────────────────────────────────────
   RENDER RESULTS
───────────────────────────────────────────────────────────── */
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function animateNumber(el, from, to, dur) {
  const t0 = performance.now();
  function step(now) {
    const t = Math.min((now - t0) / dur, 1);
    el.textContent = Math.round(from + (to - from) * (1 - Math.pow(1 - t, 3)));
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function renderQrContent(text, classification) {
  byId('qrRawContent').textContent = text;
  byId('qrTypeBadge').textContent  = classification.label;
  byId('qrContentCard').hidden     = false;
}

function renderThreatResults(report) {
  const { score, level, flags, indicators, breakdown, explanation, threatLabel } = report;

  const VERDICTS = {
    safe:       { icon: '✅', title: 'URL Appears Safe',       subtitle: 'No significant threats detected. Exercise normal caution when visiting.' },
    suspicious: { icon: '⚠️', title: 'Suspicious URL Detected', subtitle: 'Risk factors identified. Proceed with caution and verify the source.' },
    danger:     { icon: '🚨', title: 'High Threat Detected',    subtitle: 'This URL exhibits strong phishing characteristics. Do NOT visit this link.' },
  };

  const v = VERDICTS[level];
  const banner = byId('verdictBanner');
  banner.className = `verdict-banner fade-in ${level}`;
  byId('verdictIconWrap').textContent = v.icon;
  byId('verdictTitle').textContent    = v.title;
  byId('verdictSubtitle').textContent = v.subtitle;

  // Score ring
  const circ = 201;
  const fill = byId('scoreFill');
  fill.style.strokeDashoffset = circ;
  setTimeout(() => { fill.style.strokeDashoffset = circ - (score / 100) * circ; }, 80);
  animateNumber(byId('scoreNumber'), 0, score, 1000);

  // Threat bar
  const fp = 100 - score;
  setTimeout(() => { byId('threatLevelFill').style.width = fp + '%'; byId('threatLevelThumb').style.left = fp + '%'; }, 200);

  // Indicators
  const indC = byId('threatIndicators');
  indC.innerHTML = '';
  indicators.slice(0, 5).forEach(ind => {
    const row = mkEl('div', 'threat-indicator');
    row.innerHTML = `<span class="ti-dot ${ind.type}"></span><span>${escHtml(ind.text)}</span>`;
    indC.appendChild(row);
  });

  // Explanation + threat type badge
  byId('explanationText').textContent = explanation || 'No additional details available.';

  // Inject threat type badge after explanation
  let badge = byId('qrThreatTypeBadge');
  if (!badge) {
    badge = document.createElement('div');
    badge.id = 'qrThreatTypeBadge';
    badge.style.marginBottom = '14px';
    byId('explanationText').insertAdjacentElement('afterend', badge);
  }
  if (threatLabel) {
    const bc = level === 'danger' ? 'rgba(239,68,68' : 'rgba(245,158,11';
    badge.innerHTML = `<div style="display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:8px;background:${bc},.08);border:1px solid ${bc},.25);margin-bottom:4px;">
      <span style="font-size:1rem;">${level === 'danger' ? '🚨' : '⚠️'}</span>
      <div>
        <div style="font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--text-secondary);margin-bottom:2px;">Threat Type</div>
        <div style="font-size:.9rem;font-weight:700;color:${level === 'danger' ? '#ef4444' : '#f59e0b'};">${escHtml(threatLabel)}</div>
      </div>
      <span class="flag-chip ${level === 'danger' ? 'fail' : 'warn'}" style="margin-left:auto;">Google Safe Browsing</span>
    </div>`;
    badge.hidden = false;
  } else {
    badge.innerHTML = `<div style="display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:8px;background:rgba(0,255,136,.06);border:1px solid rgba(0,255,136,.2);margin-bottom:4px;">
      <span style="font-size:1rem;">✅</span>
      <div>
        <div style="font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--text-secondary);margin-bottom:2px;">Threat Type</div>
        <div style="font-size:.9rem;font-weight:700;color:var(--accent-green);">None Detected</div>
      </div>
      <span class="flag-chip pass" style="margin-left:auto;">Google Safe Browsing</span>
    </div>`;
    badge.hidden = false;
  }

  // Flags
  const flagsC = byId('explanationFlags');
  flagsC.innerHTML = '';
  flags.slice(0, 6).forEach(f => { flagsC.appendChild(mkEl('span', `flag-chip ${f.type}`, escHtml(f.label))); });

  // URL Breakdown
  const bkC = byId('urlBreakdown');
  bkC.innerHTML = '';
  [['Protocol','protocol'],['Domain','domain'],['Path','path'],['Query','query']].forEach(([lbl, key]) => {
    const p = breakdown[key];
    const w = mkEl('div', 'url-part');
    w.innerHTML = `<span class="url-part-label">${lbl}</span><span class="url-part-value highlight-${p.highlight}">${escHtml(p.value)}</span>`;
    bkC.appendChild(w);
  });

  // Recommendations
  const RECS = {
    safe:       [{ icon: '✅', text: 'This URL appears safe. Standard browsing precautions apply.' }, { icon: '🛡️', text: 'Keep your browser and security software up to date.' }],
    suspicious: [{ icon: '⚠️', text: 'Do not enter personal information or credentials on this page.' }, { icon: '🔗', text: 'Navigate directly to the official website instead of using this link.' }],
    danger:     [{ icon: '🚫', text: 'Do NOT visit this URL. Close any tabs that may have opened it.' }, { icon: '🔑', text: 'If you already visited and entered credentials, change your passwords immediately.' }, { icon: '📢', text: 'Report this URL to your IT/security team and to phishtank.com.' }],
  };
  const recList = byId('recommendationsList');
  recList.innerHTML = '';
  [...(RECS[level] || []), { icon: '🔍', text: 'Always verify QR code sources before scanning in public places.' }].forEach(r => {
    const li = mkEl('li', 'rec-item');
    li.innerHTML = `<span class="rec-icon">${r.icon}</span><span>${r.text}</span>`;
    recList.appendChild(li);
  });

  byId('urlThreatSection').hidden = false;
  setTimeout(() => { document.querySelectorAll('#resultsSection .fade-in').forEach(e => e.classList.add('visible')); }, 50);
}

function renderNonUrlContent(classification, text) {
  const msgs = {
    VCARD:    'This QR code contains a contact card (vCard). No URL threat analysis needed.',
    WIFI:     'This QR code contains Wi-Fi credentials. Verify the network name before connecting.',
    CALENDAR: 'This QR code contains a calendar event. Review the event details before accepting.',
    EMAIL:    'This QR code contains an email address. Verify the sender before composing.',
    PHONE:    'This QR code contains a phone number. Verify before calling.',
    SMS:      'This QR code contains an SMS message. Review the content before sending.',
    GEO:      'This QR code contains a geographic location.',
    TEXT:     'This QR code contains plain text. No URL threat analysis needed.',
  };
  byId('nonUrlText').textContent = msgs[classification.type] || 'This QR code does not contain a URL. No threat analysis required.';
  byId('nonUrlCard').hidden = false;
  setTimeout(() => { document.querySelectorAll('#resultsSection .fade-in').forEach(e => e.classList.add('visible')); }, 50);
}

function renderApiError(err) {
  const ERROR_TIPS = {
    network:    ['Make sure Flask is running: <code>python app.py</code>', 'Check it is on <code>http://127.0.0.1:5000</code>', 'Ensure CORS is enabled (flask-cors)'],
    timeout:    ['The server took too long — check Flask terminal for errors', 'Try again in a moment'],
    ratelimit:  ['Too many requests — wait 30 seconds and try again'],
    server:     ['Flask returned a 5xx error — check the terminal for a traceback'],
    validation: ['The URL format was rejected — try a full URL with https://'],
    http:       ['Unexpected status code — check Flask terminal'],
    parse:      ['Server response was not valid JSON — check Flask route returns jsonify(...)'],
  };
  const tips = (ERROR_TIPS[err.code] || ['Check the browser console (F12) for details.']).map(t => `<li>→ ${t}</li>`).join('');

  // Show a simple error card in the non-url slot
  byId('nonUrlText').innerHTML = `<strong style="color:#ef4444;">⚠️ API Error: ${escHtml(err.message)}</strong><br><br>
    <ul style="list-style:none;display:flex;flex-direction:column;gap:6px;font-size:.85rem;color:var(--text-secondary);">${tips}</ul>`;
  byId('nonUrlCard').hidden = false;
  setTimeout(() => { document.querySelectorAll('#resultsSection .fade-in').forEach(e => e.classList.add('visible')); }, 50);
}

/* ─────────────────────────────────────────────────────────────
   MINI MATRIX CANVAS (hero background — purple tint)
───────────────────────────────────────────────────────────── */
(function initMiniMatrix() {
  const canvas = byId('miniMatrix');
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
      ctx.fillStyle = `rgba(167,139,250,${a})`; // purple
      ctx.fillText(ch, i * FS, y);
      if (y > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }

  resize();
  window.addEventListener('resize', resize, { passive: true });
  let rafId;
  (function loop() { draw(); rafId = requestAnimationFrame(loop); })();
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) cancelAnimationFrame(rafId);
    else (function loop() { draw(); rafId = requestAnimationFrame(loop); })();
  });
})();

/* ─────────────────────────────────────────────────────────────
   MAIN CONTROLLER
───────────────────────────────────────────────────────────── */
(function initScanner() {
  const dropZone     = byId('dropZone');
  const fileInput    = byId('fileInput');
  const dropIdle     = byId('dropIdle');
  const dropOverMsg  = byId('dropOverMsg');
  const dropPreview  = byId('dropPreview');
  const previewImg   = byId('previewImg');
  const previewRemove = byId('previewRemove');
  const fileInfoRow  = byId('fileInfoRow');
  const fileInfoName = byId('fileInfoName');
  const fileInfoSize = byId('fileInfoSize');
  const uploadError  = byId('uploadError');
  const scanQrBtn    = byId('scanQrBtn');
  const resetBtn     = byId('resetBtn');
  const resultsSection = byId('resultsSection');

  let currentFile = null;

  /* ── Helpers ── */
  function formatBytes(bytes) {
    if (bytes < 1024)       return `${bytes} B`;
    if (bytes < 1048576)    return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(1)} MB`;
  }

  function showError(msg) {
    uploadError.textContent = msg;
    dropZone.style.borderColor = 'rgba(239,68,68,.5)';
    setTimeout(() => { dropZone.style.borderColor = ''; }, 2000);
  }

  function clearError() { uploadError.textContent = ''; }

  function resetAll() {
    currentFile = null;
    previewImg.src = '';
    dropIdle.hidden    = false;
    dropOverMsg.hidden = true;
    dropPreview.hidden = true;
    fileInfoRow.hidden = true;
    resetBtn.hidden    = true;
    scanQrBtn.disabled = true;
    scanQrBtn.classList.remove('loading');
    resultsSection.hidden = true;
    dropZone.classList.remove('has-file');
    clearError();

    // Reset loader checks
    ['lc1','lc2','lc3','lc4','lc5'].forEach(id => {
      const el = byId(id);
      if (!el) return;
      el.className = 'loader-check';
      const icon = el.querySelector('.lc-icon');
      icon.className = 'lc-icon pending';
      icon.textContent = '○';
    });
    byId('loaderBar').style.width = '0%';
    byId('loaderStep').textContent = 'Decoding QR payload...';
    byId('decodeLoader').hidden = true;

    // Hide result sub-sections
    byId('qrContentCard').hidden  = true;
    byId('urlThreatSection').hidden = true;
    byId('nonUrlCard').hidden     = true;
    const badge = byId('qrThreatTypeBadge');
    if (badge) badge.hidden = true;
  }

  function loadFile(file) {
    clearError();

    if (!file.type.startsWith('image/')) {
      showError('Please upload an image file (PNG, JPG, GIF, WebP, BMP).');
      return;
    }

    if (file.size > 10 * 1024 * 1024) {
      showError('File is too large. Maximum size is 10 MB.');
      return;
    }

    currentFile = file;

    // Show preview
    const reader = new FileReader();
    reader.onload = e => {
      previewImg.src = e.target.result;
      dropIdle.hidden    = false; // keep hidden below
      dropIdle.hidden    = true;
      dropOverMsg.hidden = true;
      dropPreview.hidden = false;
      dropZone.classList.add('has-file');
    };
    reader.readAsDataURL(file);

    // File info
    fileInfoName.textContent = file.name;
    fileInfoSize.textContent = formatBytes(file.size);
    fileInfoRow.hidden = false;

    scanQrBtn.disabled = false;
    resetBtn.hidden    = false;
  }

  /* ── Drop zone click ── */
  dropZone.addEventListener('click', e => {
    if (e.target === previewRemove || previewRemove.contains(e.target)) return;
    if (!currentFile) fileInput.click();
  });

  dropZone.addEventListener('keydown', e => {
    if ((e.key === 'Enter' || e.key === ' ') && !currentFile) { e.preventDefault(); fileInput.click(); }
  });

  /* ── File input change ── */
  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) { loadFile(fileInput.files[0]); fileInput.value = ''; }
  });

  /* ── Drag and drop ── */
  dropZone.addEventListener('dragenter', e => { e.preventDefault(); dropZone.classList.add('drag-over'); dropIdle.hidden = true; dropOverMsg.hidden = false; });
  dropZone.addEventListener('dragover',  e => { e.preventDefault(); });
  dropZone.addEventListener('dragleave', e => {
    if (!dropZone.contains(e.relatedTarget)) {
      dropZone.classList.remove('drag-over');
      if (!currentFile) { dropIdle.hidden = false; dropOverMsg.hidden = true; }
      else { dropOverMsg.hidden = true; }
    }
  });
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    dropOverMsg.hidden = true;
    const file = e.dataTransfer.files[0];
    if (file) loadFile(file);
    else if (!currentFile) dropIdle.hidden = false;
  });

  /* ── Remove preview ── */
  previewRemove.addEventListener('click', e => { e.stopPropagation(); resetAll(); });

  /* ── Scan button ── */
  scanQrBtn.addEventListener('click', async () => {
    if (!currentFile) return;

    clearError();
    resultsSection.hidden = true;
    byId('qrContentCard').hidden  = true;
    byId('urlThreatSection').hidden = true;
    byId('nonUrlCard').hidden     = true;

    // Reset loader
    ['lc1','lc2','lc3','lc4','lc5'].forEach(id => {
      const el = byId(id);
      if (!el) return;
      el.className = 'loader-check';
      const icon = el.querySelector('.lc-icon');
      icon.className = 'lc-icon pending';
      icon.textContent = '○';
    });
    byId('loaderBar').style.width = '0%';
    byId('loaderStep').textContent = 'Decoding QR payload...';

    scanQrBtn.classList.add('loading');
    scanQrBtn.disabled = true;

    // Decode QR and call API in parallel with the loading animation
    let qrText = null, qrError = null, apiData = null, apiError = null;

    // Step 1: decode QR (fast, local)
    try {
      qrText = await decodeQrFromFile(currentFile);
    } catch (err) {
      qrError = err;
    }

    // Step 2: if URL, fire API call immediately (runs in parallel with animation)
    let apiPromise = Promise.resolve(null);
    if (qrText && !qrError) {
      const classification = classifyQrContent(qrText);
      if (classification.isUrl) {
        const urlToCheck = /^https?:\/\//i.test(qrText) ? qrText : `http://${qrText}`;
        apiPromise = callCheckUrl(urlToCheck).catch(err => { apiError = err; return null; });
      }
    }

    // Run animation in parallel with API call
    const [, apiResult] = await Promise.allSettled([
      new Promise(resolve => runLoadingSequence(resolve)),
      apiPromise,
    ]);

    if (apiResult.status === 'fulfilled' && apiResult.value) {
      apiData = apiResult.value;
    } else if (apiResult.status === 'rejected') {
      apiError = apiResult.reason;
    }

    scanQrBtn.classList.remove('loading');
    scanQrBtn.disabled = false;

    // Show results
    if (qrError) {
      showError(qrError.message);
      return;
    }

    resultsSection.hidden = false;
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

    const classification = classifyQrContent(qrText);
    renderQrContent(qrText, classification);

    if (classification.isUrl) {
      if (apiError) {
        renderApiError(apiError);
      } else if (apiData) {
        const urlToCheck = /^https?:\/\//i.test(qrText) ? qrText : `http://${qrText}`;
        renderThreatResults(buildReport(urlToCheck, apiData));
      }
    } else {
      renderNonUrlContent(classification, qrText);
    }
  });

  /* ── Reset / Scan Another ── */
  resetBtn.addEventListener('click', resetAll);

  document.addEventListener('click', e => {
    if (e.target.closest('#scanAnotherBtn')) { resetAll(); window.scrollTo({ top: 0, behavior: 'smooth' }); }
  });

  /* ── Copy QR content ── */
  document.addEventListener('click', e => {
    if (!e.target.closest('#copyContentBtn')) return;
    const btn = byId('copyContentBtn');
    const text = byId('qrRawContent').textContent;
    navigator.clipboard.writeText(text).then(() => {
      const orig = btn.innerHTML;
      btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg> Copied!`;
      setTimeout(() => { btn.innerHTML = orig; }, 2000);
    }).catch(() => alert('Copy failed.'));
  });

  /* ── Copy Report ── */
  document.addEventListener('click', e => {
    if (!e.target.closest('#copyReportBtn')) return;
    const btn     = byId('copyReportBtn');
    const content = byId('qrRawContent')?.textContent || '—';
    const type    = byId('qrTypeBadge')?.textContent  || '—';
    const score   = byId('scoreNumber')?.textContent  || 'N/A';
    const verdict = byId('verdictTitle')?.textContent || 'N/A';
    const detail  = byId('explanationText')?.textContent || 'N/A';

    const text = [
      '=== CyberShield QR Threat Report ===',
      `QR Content Type: ${type}`,
      `QR Content:      ${content}`,
      `Verdict:         ${verdict}`,
      `Security Score:  ${score}/100`,
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
    }).catch(() => alert('Copy failed.'));
  });
})();

/* ─────────────────────────────────────────────────────────────
   SCROLL FADE-IN
───────────────────────────────────────────────────────────── */
(function initScrollFade() {
  const obs = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) { entry.target.classList.add('visible'); obs.unobserve(entry.target); }
    });
  }, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });

  document.querySelectorAll('.fade-in').forEach(e => {
    const delay = e.dataset.delay;
    if (delay) e.style.transitionDelay = `${delay}ms`;
    obs.observe(e);
  });
})();
