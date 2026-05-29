/**
 * CyberShield — password-analyzer.js
 * Real-time password strength analysis — runs entirely in the browser.
 * No data is ever sent to a server.
 *
 * Uses byId() / mkEl() helpers (not $ / $$) to avoid conflicts with main.js.
 */

'use strict';

/* ─────────────────────────────────────────────────────────────
   DOM HELPERS  (scoped to this file — no conflict with main.js)
───────────────────────────────────────────────────────────── */
const byId = id => document.getElementById(id);
const mkEl = (tag, cls, html) => {
  const e = document.createElement(tag);
  if (cls)              e.className   = cls;
  if (html !== undefined) e.innerHTML = html;
  return e;
};

/* ─────────────────────────────────────────────────────────────
   STRENGTH LEVELS
───────────────────────────────────────────────────────────── */
const LEVELS = [
  null,                                          // 0 — unused
  { key: 'very-weak',   label: 'Very Weak',   icon: '🔴', color: '#ef4444' },
  { key: 'weak',        label: 'Weak',        icon: '🟠', color: '#f97316' },
  { key: 'fair',        label: 'Fair',        icon: '🟡', color: '#f59e0b' },
  { key: 'strong',      label: 'Strong',      icon: '🟢', color: '#22c55e' },
  { key: 'very-strong', label: 'Very Strong', icon: '✅', color: '#00ff88' },
];

const VERDICT_SUBTITLES = {
  'very-weak':   'This password would be cracked almost instantly. Change it immediately.',
  'weak':        'This password offers minimal protection. Consider making it longer and more complex.',
  'fair':        'Decent start, but there is room for improvement. Add more variety.',
  'strong':      'Good password. A few more tweaks could make it excellent.',
  'very-strong': 'Excellent password. This would take an extremely long time to crack.',
};

/* ─────────────────────────────────────────────────────────────
   ANALYSIS ENGINE
───────────────────────────────────────────────────────────── */

/**
 * Analyse a password and return a full report object.
 * @param {string} pw
 * @returns {object} report
 */
function analyzePassword(pw) {
  if (!pw) return null;

  // ── 1. Character set detection ────────────────────────────
  const hasLower   = /[a-z]/.test(pw);
  const hasUpper   = /[A-Z]/.test(pw);
  const hasDigit   = /[0-9]/.test(pw);
  const hasSpecial = /[^a-zA-Z0-9]/.test(pw);

  const lowerCount   = (pw.match(/[a-z]/g)   || []).length;
  const upperCount   = (pw.match(/[A-Z]/g)   || []).length;
  const digitCount   = (pw.match(/[0-9]/g)   || []).length;
  const specialCount = (pw.match(/[^a-zA-Z0-9]/g) || []).length;

  // ── 2. Character pool size ────────────────────────────────
  let poolSize = 0;
  if (hasLower)   poolSize += 26;
  if (hasUpper)   poolSize += 26;
  if (hasDigit)   poolSize += 10;
  if (hasSpecial) poolSize += 32;

  // ── 3. Entropy (bits) ─────────────────────────────────────
  // H = L × log2(N)  where L = length, N = pool size
  const entropy = poolSize > 0
    ? Math.round(pw.length * Math.log2(poolSize) * 10) / 10
    : 0;

  // ── 4. Score (0–100) ──────────────────────────────────────
  let score = 0;

  // Length (up to 40 pts)
  if (pw.length >= 6)  score += 10;
  if (pw.length >= 8)  score += 10;
  if (pw.length >= 12) score += 10;
  if (pw.length >= 16) score += 10;

  // Character variety (up to 40 pts)
  if (hasLower)   score += 10;
  if (hasUpper)   score += 10;
  if (hasDigit)   score += 10;
  if (hasSpecial) score += 10;

  // Entropy bonus (up to 20 pts)
  if (entropy >= 28)  score += 5;
  if (entropy >= 40)  score += 5;
  if (entropy >= 60)  score += 5;
  if (entropy >= 80)  score += 5;

  // Penalties
  if (/^(.)\1+$/.test(pw))          score -= 20; // all same char
  if (/^(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(pw)) score -= 10; // sequential
  if (/^(password|qwerty|letmein|welcome|admin|login|iloveyou|monkey|dragon|master)/i.test(pw)) score -= 30; // common

  score = Math.max(0, Math.min(100, score));

  // ── 5. Strength level (1–5) ───────────────────────────────
  let level;
  if      (score < 20) level = 1;
  else if (score < 40) level = 2;
  else if (score < 60) level = 3;
  else if (score < 80) level = 4;
  else                 level = 5;

  // ── 6. Crack time estimate ────────────────────────────────
  // Assume 10 billion guesses/second (modern GPU brute-force)
  const GUESSES_PER_SEC = 1e10;
  const combinations    = Math.pow(poolSize || 1, pw.length);
  const seconds         = combinations / GUESSES_PER_SEC;
  const crackTime       = formatCrackTime(seconds);

  // ── 7. Composition checks ─────────────────────────────────
  const composition = [
    {
      label:  'Minimum length (8+)',
      pass:   pw.length >= 8,
      count:  `${pw.length} chars`,
    },
    {
      label:  'Lowercase letters (a–z)',
      pass:   hasLower,
      count:  hasLower ? `${lowerCount}` : '0',
    },
    {
      label:  'Uppercase letters (A–Z)',
      pass:   hasUpper,
      count:  hasUpper ? `${upperCount}` : '0',
    },
    {
      label:  'Numbers (0–9)',
      pass:   hasDigit,
      count:  hasDigit ? `${digitCount}` : '0',
    },
    {
      label:  'Special characters (!@#…)',
      pass:   hasSpecial,
      count:  hasSpecial ? `${specialCount}` : '0',
    },
    {
      label:  'Length 12 or more (recommended)',
      pass:   pw.length >= 12,
      count:  `${pw.length} chars`,
    },
  ];

  // ── 8. Suggestions ────────────────────────────────────────
  const suggestions = buildSuggestions(pw, { hasLower, hasUpper, hasDigit, hasSpecial, score });

  return {
    score,
    level,
    entropy,
    crackTime,
    composition,
    suggestions,
    length: pw.length,
  };
}

/* ─────────────────────────────────────────────────────────────
   CRACK TIME FORMATTER
───────────────────────────────────────────────────────────── */
function formatCrackTime(seconds) {
  if (!isFinite(seconds) || seconds > 1e30) return 'Centuries (practically uncrackable)';
  if (seconds < 0.001)   return 'Instantly';
  if (seconds < 1)       return 'Less than a second';
  if (seconds < 60)      return `${Math.round(seconds)} second${seconds >= 2 ? 's' : ''}`;
  if (seconds < 3600)    return `${Math.round(seconds / 60)} minute${seconds >= 120 ? 's' : ''}`;
  if (seconds < 86400)   return `${Math.round(seconds / 3600)} hour${seconds >= 7200 ? 's' : ''}`;
  if (seconds < 2592000) return `${Math.round(seconds / 86400)} day${seconds >= 172800 ? 's' : ''}`;
  if (seconds < 31536000) return `${Math.round(seconds / 2592000)} month${seconds >= 5184000 ? 's' : ''}`;
  const years = seconds / 31536000;
  if (years < 1000)      return `${Math.round(years)} year${years >= 2 ? 's' : ''}`;
  if (years < 1e6)       return `${(years / 1000).toFixed(1)}K years`;
  if (years < 1e9)       return `${(years / 1e6).toFixed(1)} million years`;
  if (years < 1e12)      return `${(years / 1e9).toFixed(1)} billion years`;
  return 'Centuries (practically uncrackable)';
}

/* ─────────────────────────────────────────────────────────────
   SUGGESTION BUILDER
───────────────────────────────────────────────────────────── */
function buildSuggestions(pw, { hasLower, hasUpper, hasDigit, hasSpecial, score }) {
  const tips = [];

  if (pw.length < 8)  tips.push({ icon: '📏', text: 'Use at least 8 characters — longer is always better.' });
  if (pw.length < 12) tips.push({ icon: '📐', text: 'Aim for 12+ characters for strong protection.' });
  if (!hasUpper)      tips.push({ icon: '🔠', text: 'Add uppercase letters (A–Z) to increase complexity.' });
  if (!hasLower)      tips.push({ icon: '🔡', text: 'Include lowercase letters (a–z).' });
  if (!hasDigit)      tips.push({ icon: '🔢', text: 'Mix in numbers (0–9) to expand the character pool.' });
  if (!hasSpecial)    tips.push({ icon: '✳️',  text: 'Add special characters like !@#$%^&* for maximum strength.' });

  if (/(.)\1{2,}/.test(pw))
    tips.push({ icon: '🔁', text: 'Avoid repeating the same character multiple times in a row.' });

  if (/^[a-zA-Z]+$/.test(pw))
    tips.push({ icon: '🔀', text: 'Your password is letters only — mix in numbers and symbols.' });

  if (/^[0-9]+$/.test(pw))
    tips.push({ icon: '🔀', text: 'Your password is numbers only — add letters and symbols.' });

  if (/password|qwerty|letmein|welcome|admin|login/i.test(pw))
    tips.push({ icon: '🚫', text: 'Avoid common words like "password", "admin", or "qwerty".' });

  if (score >= 80 && tips.length === 0)
    tips.push({ icon: '🏆', text: 'Excellent password! Consider using a password manager to store it safely.' });

  if (tips.length === 0)
    tips.push({ icon: '💡', text: 'Good password. Adding more length or special characters would make it even stronger.' });

  return tips;
}

/* ─────────────────────────────────────────────────────────────
   STRONG PASSWORD GENERATOR
───────────────────────────────────────────────────────────── */
function generateStrongPassword(length = 18) {
  const lower   = 'abcdefghijklmnopqrstuvwxyz';
  const upper   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const digits  = '0123456789';
  const special = '!@#$%^&*()-_=+[]{}|;:,.<>?';
  const all     = lower + upper + digits + special;

  // Guarantee at least one of each category
  let pw = [
    lower  [Math.floor(Math.random() * lower.length)],
    upper  [Math.floor(Math.random() * upper.length)],
    digits [Math.floor(Math.random() * digits.length)],
    special[Math.floor(Math.random() * special.length)],
  ];

  for (let i = pw.length; i < length; i++) {
    pw.push(all[Math.floor(Math.random() * all.length)]);
  }

  // Fisher-Yates shuffle
  for (let i = pw.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [pw[i], pw[j]] = [pw[j], pw[i]];
  }

  return pw.join('');
}

/* ─────────────────────────────────────────────────────────────
   RENDER RESULTS
───────────────────────────────────────────────────────────── */
function renderResults(report) {
  const section = byId('resultsSection');
  section.hidden = false;
  section.scrollIntoView({ behavior: 'smooth', block: 'start' });

  const { score, level, entropy, crackTime, composition, suggestions } = report;
  const lvl = LEVELS[level];

  // ── Verdict banner ──────────────────────────────────────────
  const banner = byId('verdictBanner');
  banner.className = `verdict-banner fade-in ${lvl.key}`;

  byId('verdictIconWrap').textContent = lvl.icon;
  byId('verdictTitle').textContent    = lvl.label;
  byId('verdictSubtitle').textContent = VERDICT_SUBTITLES[lvl.key];

  // Score ring
  const circumference = 201;
  const offset = circumference - (score / 100) * circumference;
  const fill = byId('scoreFill');
  fill.style.strokeDashoffset = circumference;
  setTimeout(() => { fill.style.strokeDashoffset = offset; }, 80);

  // Animate score number
  animateNumber(byId('scoreNumber'), 0, score, 1000);

  // ── Segmented bar ───────────────────────────────────────────
  for (let i = 1; i <= 5; i++) {
    const seg = byId(`seg${i}`);
    if (i <= level) {
      seg.setAttribute('data-filled', level);
    } else {
      seg.removeAttribute('data-filled');
    }
  }

  // Crack time
  byId('crackTimeValue').textContent = crackTime;

  // ── Composition list ────────────────────────────────────────
  const compList = byId('compositionList');
  compList.innerHTML = '';
  composition.forEach(c => {
    const li = mkEl('li', 'comp-item');
    li.innerHTML = `
      <span class="comp-icon ${c.pass ? 'pass' : 'fail'}">${c.pass ? '✓' : '✗'}</span>
      <span class="comp-text ${c.pass ? 'pass' : ''}">${c.label}</span>
      <span class="comp-count ${c.pass ? 'pass' : 'fail'}">${c.count}</span>
    `;
    compList.appendChild(li);
  });

  // Entropy
  byId('entropyValue').textContent = `${entropy} bits`;

  // ── Suggestions ─────────────────────────────────────────────
  const sugList = byId('suggestionsList');
  sugList.innerHTML = '';
  suggestions.forEach(s => {
    const li = mkEl('li', 'suggestion-item');
    li.innerHTML = `<span class="suggestion-icon">${s.icon}</span><span>${s.text}</span>`;
    sugList.appendChild(li);
  });

  // Trigger fade-in
  setTimeout(() => {
    section.querySelectorAll('.fade-in').forEach(e => e.classList.add('visible'));
  }, 50);
}

function animateNumber(el, from, to, duration) {
  const start = performance.now();
  function step(now) {
    const t     = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(from + (to - from) * eased);
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

/* ─────────────────────────────────────────────────────────────
   INLINE REAL-TIME FEEDBACK (updates as user types)
───────────────────────────────────────────────────────────── */
function updateInlineFeedback(pw) {
  const fill  = byId('inlineStrengthFill');
  const label = byId('inlineStrengthLabel');

  if (!pw) {
    fill.removeAttribute('data-level');
    fill.style.width = '0%';
    label.textContent = '';
    label.style.color = '';
    return;
  }

  const report = analyzePassword(pw);
  const lvl    = LEVELS[report.level];

  fill.setAttribute('data-level', report.level);
  label.textContent = lvl.label;
  label.style.color = lvl.color;
}

/* ─────────────────────────────────────────────────────────────
   MINI MATRIX CANVAS (hero background)
───────────────────────────────────────────────────────────── */
(function initMiniMatrix() {
  const canvas = byId('miniMatrix');
  if (!canvas) return;
  const ctx   = canvas.getContext('2d');
  const CHARS = '01アイウエオABCDEF<>/\\{}[]';
  const FS    = 13;
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
      ctx.fillStyle = `rgba(0,212,255,${a})`;   // blue tint for this page
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
   MAIN FORM LOGIC
───────────────────────────────────────────────────────────── */
(function initAnalyzer() {
  const pwInput    = byId('pwInput');
  const pwToggle   = byId('pwToggle');
  const pwClear    = byId('pwClear');
  const analyzeBtn = byId('analyzeBtn');
  const generateBtn = byId('generateBtn');
  const resultsSection = byId('resultsSection');

  // ── Show/hide clear button ──────────────────────────────────
  pwInput.addEventListener('input', () => {
    const hasValue = pwInput.value.length > 0;
    pwClear.classList.toggle('visible', hasValue);
    updateInlineFeedback(pwInput.value);
  });

  // ── Clear button ────────────────────────────────────────────
  pwClear.addEventListener('click', () => {
    pwInput.value = '';
    pwClear.classList.remove('visible');
    updateInlineFeedback('');
    resultsSection.hidden = true;
    pwInput.focus();
  });

  // ── Show / hide password toggle ─────────────────────────────
  pwToggle.addEventListener('click', () => {
    const isPassword = pwInput.type === 'password';
    pwInput.type = isPassword ? 'text' : 'password';

    const eyeShow = pwToggle.querySelector('.eye-show');
    const eyeHide = pwToggle.querySelector('.eye-hide');
    eyeShow.style.display = isPassword ? 'none'  : '';
    eyeHide.style.display = isPassword ? ''      : 'none';
    pwToggle.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
  });

  // ── Analyze button ──────────────────────────────────────────
  analyzeBtn.addEventListener('click', runAnalysis);
  pwInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') runAnalysis();
  });

  function runAnalysis() {
    const pw = pwInput.value;
    if (!pw) {
      pwInput.focus();
      pwInput.style.outline = '2px solid #ef4444';
      setTimeout(() => { pwInput.style.outline = ''; }, 1200);
      return;
    }
    const report = analyzePassword(pw);
    renderResults(report);
  }

  // ── Generate strong password ────────────────────────────────
  generateBtn.addEventListener('click', () => {
    const pw = generateStrongPassword(18);
    pwInput.value = pw;
    // Show as text briefly so user can see it
    pwInput.type = 'text';
    byId('pwToggle').querySelector('.eye-show').style.display = 'none';
    byId('pwToggle').querySelector('.eye-hide').style.display = '';

    pwClear.classList.add('visible');
    updateInlineFeedback(pw);
    runAnalysis();
  });

  // ── Analyze Another ─────────────────────────────────────────
  document.addEventListener('click', e => {
    if (!e.target.closest('#analyzeAnotherBtn')) return;
    resultsSection.hidden = true;
    pwInput.value = '';
    pwClear.classList.remove('visible');
    updateInlineFeedback('');
    // Reset to password type
    pwInput.type = 'password';
    byId('pwToggle').querySelector('.eye-show').style.display = '';
    byId('pwToggle').querySelector('.eye-hide').style.display = 'none';
    window.scrollTo({ top: 0, behavior: 'smooth' });
    setTimeout(() => pwInput.focus(), 600);
  });

  // ── Copy Report ─────────────────────────────────────────────
  document.addEventListener('click', e => {
    if (!e.target.closest('#copyReportBtn')) return;
    const btn   = byId('copyReportBtn');
    const score = byId('scoreNumber').textContent;
    const level = byId('verdictTitle').textContent;
    const crack = byId('crackTimeValue').textContent;
    const entropy = byId('entropyValue').textContent;

    // Gather composition items
    const compItems = [...document.querySelectorAll('.comp-item')].map(li => {
      const icon  = li.querySelector('.comp-icon').textContent.trim();
      const label = li.querySelector('.comp-text').textContent.trim();
      const count = li.querySelector('.comp-count').textContent.trim();
      return `  ${icon} ${label}: ${count}`;
    }).join('\n');

    // Gather suggestions
    const sugItems = [...document.querySelectorAll('.suggestion-item')].map(li => {
      return `  ${li.querySelector('.suggestion-icon').textContent} ${li.lastElementChild.textContent}`;
    }).join('\n');

    const text = [
      '=== CyberShield Password Strength Report ===',
      `Strength Level:  ${level}`,
      `Security Score:  ${score}/100`,
      `Entropy:         ${entropy}`,
      `Est. Crack Time: ${crack}`,
      '',
      'Composition:',
      compItems,
      '',
      'Suggestions:',
      sugItems,
      '',
      `Generated: ${new Date().toLocaleString()}`,
      'CyberShield — Integrated Web Security & Threat Detection System',
      '(Password was NOT included in this report for security reasons)',
    ].join('\n');

    navigator.clipboard.writeText(text).then(() => {
      const orig = btn.innerHTML;
      btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg> Copied!`;
      setTimeout(() => { btn.innerHTML = orig; }, 2000);
    }).catch(() => alert('Copy failed. Please copy manually.'));
  });
})();

/* ─────────────────────────────────────────────────────────────
   SCROLL FADE-IN (static page elements)
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
