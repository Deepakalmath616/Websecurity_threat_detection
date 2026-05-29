/**
 * CyberShield — dashboard.js  (Enhanced v2)
 * Real-time cybersecurity monitoring dashboard.
 * Auto-refreshes every 5 seconds.
 *
 * Uses byId() / mkEl() helpers to avoid conflicts with main.js $ / $$.
 * All existing IDs and functions are preserved for backward compatibility.
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
const API_BASE       = 'http://127.0.0.1:5000';
const REFRESH_MS     = 5_000;   // 5 seconds
const PAGE_SIZE      = 20;
const PANEL_LIMIT    = 10;
const FEED_LIMIT     = 25;
const TIMELINE_LIMIT = 20;
const EXT_LIMIT      = 8;

/* ─────────────────────────────────────────────────────────────
   STATE
───────────────────────────────────────────────────────────── */
let currentPage    = 0;
let totalRecords   = 0;
let refreshTimer   = null;
let allRecords     = [];
let filteredSource = '';
let filteredStatus = '';
let prevTotalScans = -1;
let alertDismissed = false;
let lastStats      = null;

/* ─────────────────────────────────────────────────────────────
   UTILITY HELPERS
───────────────────────────────────────────────────────────── */
function escHtml(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function formatTimestamp(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts.replace(' ','T')+'Z');
    return d.toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'});
  } catch { return ts; }
}

function timeAgo(ts) {
  if (!ts) return '';
  try {
    const secs = Math.floor((Date.now() - new Date(ts.replace(' ','T')+'Z').getTime()) / 1000);
    if (secs < 5)    return 'just now';
    if (secs < 60)   return `${secs}s ago`;
    if (secs < 3600) return `${Math.floor(secs/60)}m ago`;
    if (secs < 86400) return `${Math.floor(secs/3600)}h ago`;
    return `${Math.floor(secs/86400)}d ago`;
  } catch { return ''; }
}

function truncateUrl(url, max=55) {
  if (!url) return '—';
  return url.length > max ? url.slice(0,max)+'…' : url;
}

function classifyRecord(r) {
  const s = (r.status||'').toLowerCase();
  if (!r.threat_type || s.includes('safe')) return 'safe';
  if (s.includes('unwanted')||s.includes('harmful')||s.includes('⚠')) return 'warn';
  return 'danger';
}

function scoreClass(score) {
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

function sourceLabel(source) {
  const map = {
    website:          {label:'Website',    cls:'website'},
    chrome_extension: {label:'Extension',  cls:'extension'},
    extension:        {label:'Extension',  cls:'extension'},
    qr_scanner:       {label:'QR Scanner', cls:'qr'},
    api:              {label:'API',        cls:'website'},
  };
  return map[source] || {label: source||'Unknown', cls:''};
}

function threatTypeLabel(tt) {
  const map = {
    MALWARE:'Malware', SOCIAL_ENGINEERING:'Phishing',
    UNWANTED_SOFTWARE:'Unwanted SW', POTENTIALLY_HARMFUL_APPLICATION:'Harmful App',
    HEURISTIC_PHISHING:'Heuristic Phishing', HEURISTIC_SUSPICIOUS:'Heuristic Suspicious',
    VIRUSTOTAL_MALICIOUS:'VT Malicious', VIRUSTOTAL_SUSPICIOUS:'VT Suspicious',
    DOWNLOAD_MALICIOUS:'Download Malicious', DOWNLOAD_SUSPICIOUS:'Download Suspicious',
  };
  return map[tt] || tt || '—';
}

function threatBarClass(tt) {
  if (!tt) return 'other';
  if (tt.includes('MALWARE')||tt.includes('MALICIOUS')) return 'malware';
  if (tt.includes('SOCIAL')||tt.includes('PHISHING'))   return 'phishing';
  if (tt.includes('UNWANTED'))                          return 'unwanted';
  if (tt.includes('HARMFUL'))                           return 'harmful';
  return 'heuristic';
}

/* ─────────────────────────────────────────────────────────────
   STATUS BAR
───────────────────────────────────────────────────────────── */
function setStatus(state, text) {
  const dot = byId('statusDot'), txt = byId('statusText');
  dot.className = `status-dot ${state}`;
  txt.className = `status-text ${state}`;
  txt.textContent = text;
}

function updateLastUpdated() {
  byId('lastUpdated').textContent = new Date().toLocaleTimeString();
}

/* ─────────────────────────────────────────────────────────────
   TOAST NOTIFICATIONS
───────────────────────────────────────────────────────────── */
function showToast(msg, type='info', duration=4000) {
  const container = byId('toastContainer');
  if (!container) return;
  const toast = mkEl('div', `toast ${type}`);
  const icons = {danger:'🚨', safe:'✅', info:'ℹ️'};
  toast.innerHTML = `<span>${icons[type]||'ℹ️'}</span><span>${escHtml(msg)}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = 'toastOut .35s ease both';
    setTimeout(() => toast.remove(), 350);
  }, duration);
}

/* ─────────────────────────────────────────────────────────────
   THREAT ALERT BANNER
───────────────────────────────────────────────────────────── */
function updateThreatBanner(records) {
  if (alertDismissed) return;
  const recent = records.filter(r => r.threat_type !== null).slice(0,1)[0];
  const banner = byId('threatAlertBanner');
  if (!banner) return;
  if (recent) {
    byId('threatAlertMsg').textContent =
      `${threatTypeLabel(recent.threat_type)} detected: ${truncateUrl(recent.url, 60)}`;
    banner.hidden = false;
  } else {
    banner.hidden = true;
  }
}

/* ─────────────────────────────────────────────────────────────
   API FETCH
───────────────────────────────────────────────────────────── */
async function fetchHistory(limit=200, offset=0) {
  const params = new URLSearchParams({limit, offset});
  if (filteredSource) params.set('source', filteredSource);
  const resp = await fetch(`${API_BASE}/scan-history?${params}`, {signal: AbortSignal.timeout(8000)});
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

async function fetchStats() {
  const resp = await fetch(`${API_BASE}/scan-history/stats`, {signal: AbortSignal.timeout(8000)});
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

/* ─────────────────────────────────────────────────────────────
   ANIMATED NUMBER
───────────────────────────────────────────────────────────── */
function animateNumber(el, to, duration=800) {
  const from = parseInt(el.textContent)||0;
  const start = performance.now();
  function step(now) {
    const t = Math.min((now-start)/duration, 1);
    el.textContent = Math.round(from + (to-from)*(1-Math.pow(1-t,3)));
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

/* ─────────────────────────────────────────────────────────────
   STATS CARDS
───────────────────────────────────────────────────────────── */
function renderStats(stats) {
  const total    = stats.total_scans  || 0;
  const safe     = stats.safe_count   || 0;
  const threats  = stats.threat_count || 0;
  const avgScore = Math.round(stats.average_score || 0);

  animateNumber(byId('statTotalValue'),     total);
  animateNumber(byId('statSafeValue'),      safe);
  animateNumber(byId('statMaliciousValue'), threats);
  animateNumber(byId('statAvgScoreValue'),  avgScore);

  if (total > 0) {
    setTimeout(() => {
      byId('statSafeBar').style.width      = `${(safe/total)*100}%`;
      byId('statMaliciousBar').style.width = `${(threats/total)*100}%`;
    }, 100);
  }

  const circ = 100.5;
  setTimeout(() => {
    byId('miniRingFill').style.strokeDashoffset = circ - (avgScore/100)*circ;
  }, 100);

  // Detect new scans
  if (prevTotalScans >= 0 && total > prevTotalScans) {
    const diff = total - prevTotalScans;
    const wrap = byId('newScansBadgeWrap');
    const badge = byId('newScansBadge');
    if (wrap && badge) {
      badge.textContent = `+${diff} new`;
      wrap.hidden = false;
      setTimeout(() => { wrap.hidden = true; }, 6000);
    }
    if (diff > 0) showToast(`${diff} new scan${diff>1?'s':''} detected`, 'info', 3000);
  }
  prevTotalScans = total;
  lastStats = stats;
}

/* ─────────────────────────────────────────────────────────────
   SECURITY SCORE GAUGE
───────────────────────────────────────────────────────────── */
function renderScoreGauge(avgScore) {
  const score = Math.round(avgScore || 0);

  // Animate score number
  const numEl = byId('sgcScoreNum');
  if (numEl) animateNumber(numEl, score, 1000);

  // Risk level
  let riskKey, riskLabel, riskColor;
  if (score >= 70) {
    riskKey = 'low'; riskLabel = 'Low Risk'; riskColor = '#00ff88';
  } else if (score >= 40) {
    riskKey = 'medium'; riskLabel = 'Medium Risk'; riskColor = '#f59e0b';
  } else {
    riskKey = 'high'; riskLabel = 'High Risk'; riskColor = '#ef4444';
  }

  const badge = byId('riskLevelBadge');
  if (badge) { badge.textContent = riskLabel; badge.className = `sgc-badge ${riskKey}`; }

  const riskLbl = byId('sgcRiskLabel');
  if (riskLbl) { riskLbl.textContent = riskLabel; riskLbl.style.color = riskColor; }

  // SVG arc fill — semicircle path from 20,100 to 180,100 (radius 80)
  // stroke-dasharray = arc length ≈ 251.2 (π × 80)
  const fill = byId('sgcFill');
  if (fill) {
    const arcLen = 251.2;
    const offset = arcLen - (score / 100) * arcLen;
    fill.style.strokeDashoffset = offset;
    fill.style.stroke = riskColor;
    setTimeout(() => { fill.style.strokeDashoffset = offset; }, 80);
  }

  // Needle rotation: 0% = -90deg (left), 100% = +90deg (right)
  const needle = byId('sgcNeedle');
  if (needle) {
    const deg = -90 + (score / 100) * 180;
    needle.style.transform = `rotate(${deg}deg)`;
    needle.style.stroke = riskColor;
    const hub = document.querySelector('.sgc-needle-hub');
    if (hub) hub.style.fill = riskColor;
  }
}

/* ─────────────────────────────────────────────────────────────
   THREAT DISTRIBUTION CHART
───────────────────────────────────────────────────────────── */
function renderThreatDist(byThreatType) {
  const container = byId('threatDistChart');
  if (!container) return;
  container.innerHTML = '';

  if (!byThreatType || byThreatType.length === 0) {
    container.innerHTML = '<div class="tdc-empty">No threat data yet</div>';
    return;
  }

  const maxCount = Math.max(...byThreatType.map(t => t.count), 1);

  byThreatType.slice(0, 6).forEach(t => {
    const pct = (t.count / maxCount) * 100;
    const cls = threatBarClass(t.threat_type);
    const label = threatTypeLabel(t.threat_type);
    const row = mkEl('div', 'tdc-row');
    row.innerHTML = `
      <div class="tdc-label-row">
        <span class="tdc-name">${escHtml(label)}</span>
        <span class="tdc-count">${t.count}</span>
      </div>
      <div class="tdc-bar-track">
        <div class="tdc-bar-fill ${cls}" style="width:0%"></div>
      </div>`;
    container.appendChild(row);
    setTimeout(() => {
      row.querySelector('.tdc-bar-fill').style.width = `${pct}%`;
    }, 100);
  });
}

/* ─────────────────────────────────────────────────────────────
   SAFE VS MALICIOUS DONUT
───────────────────────────────────────────────────────────── */
function renderDonut(safe, threats) {
  const total = safe + threats;
  if (total === 0) return;

  const circ = 289; // 2π × 46
  const safePct   = safe   / total;
  const threatPct = threats / total;

  const safeOffset   = circ - safePct   * circ;
  const threatOffset = circ - threatPct * circ;

  // Safe arc starts at 0
  const safeEl = byId('donutSafe');
  if (safeEl) {
    safeEl.style.strokeDashoffset = circ;
    setTimeout(() => { safeEl.style.strokeDashoffset = safeOffset; }, 100);
  }

  // Threat arc starts where safe ends
  const threatEl = byId('donutThreat');
  if (threatEl) {
    const threatStart = safePct * 360;
    threatEl.setAttribute('transform', `rotate(${-90 + threatStart} 60 60)`);
    threatEl.style.strokeDashoffset = circ;
    setTimeout(() => { threatEl.style.strokeDashoffset = threatOffset; }, 100);
  }

  const pctEl = byId('donutSafePct');
  if (pctEl) pctEl.textContent = `${Math.round(safePct * 100)}%`;
}

/* ─────────────────────────────────────────────────────────────
   SOURCE BREAKDOWN BARS
───────────────────────────────────────────────────────────── */
function renderSourceBars(bySource) {
  const container = byId('sourceBars');
  if (!container) return;
  container.innerHTML = '';

  if (!bySource || bySource.length === 0) {
    container.innerHTML = '<div class="tdc-empty">No source data yet</div>';
    return;
  }

  const maxCount = Math.max(...bySource.map(s => s.count), 1);

  bySource.forEach(s => {
    const pct = (s.count / maxCount) * 100;
    const src = sourceLabel(s.source);
    const row = mkEl('div', 'sb-row');
    row.innerHTML = `
      <div class="sb-label-row">
        <span class="sb-name">${escHtml(src.label)}</span>
        <span class="sb-count">${s.count}</span>
      </div>
      <div class="sb-track">
        <div class="sb-fill ${src.cls}" style="width:0%"></div>
      </div>`;
    container.appendChild(row);
    setTimeout(() => {
      row.querySelector('.sb-fill').style.width = `${pct}%`;
    }, 100);
  });
}


/* ─────────────────────────────────────────────────────────────
   LIVE ACTIVITY FEED
───────────────────────────────────────────────────────────── */
function renderLiveFeed(records) {
  const body = byId('liveFeedBody');
  const countEl = byId('liveFeedCount');
  if (!body) return;

  const items = records.slice(0, FEED_LIMIT);
  countEl.textContent = `${items.length} events`;

  body.innerHTML = '';

  if (items.length === 0) {
    body.innerHTML = `<div class="dash-empty-state">
      <span class="dash-empty-icon">📡</span>
      <p>Waiting for activity...</p>
      <span>Scans will appear here in real-time</span>
    </div>`;
    return;
  }

  items.forEach(r => {
    const cls = classifyRecord(r);
    const src = sourceLabel(r.source);
    const ev  = mkEl('div', 'feed-event');
    ev.innerHTML = `
      <span class="feed-dot ${cls}"></span>
      <div class="feed-body">
        <span class="feed-url" title="${escHtml(r.url)}">${escHtml(truncateUrl(r.url, 50))}</span>
        <div class="feed-meta">
          <span class="feed-status ${cls}">${escHtml(r.status)}</span>
          <span class="feed-source-badge ${src.cls}">${escHtml(src.label)}</span>
          <span class="feed-time">${timeAgo(r.timestamp)}</span>
        </div>
      </div>`;
    body.appendChild(ev);
  });
}

/* ─────────────────────────────────────────────────────────────
   SCAN TIMELINE
───────────────────────────────────────────────────────────── */
function renderTimeline(records) {
  const body = byId('timelineBody');
  if (!body) return;

  const items = records.slice(0, TIMELINE_LIMIT);
  body.innerHTML = '';

  if (items.length === 0) {
    body.innerHTML = `<div class="dash-empty-state">
      <span class="dash-empty-icon">��</span>
      <p>No timeline data yet</p>
    </div>`;
    return;
  }

  items.forEach(r => {
    const cls = classifyRecord(r);
    const item = mkEl('div', 'tl-item');
    item.innerHTML = `
      <span class="tl-dot ${cls}"></span>
      <div class="tl-body">
        <span class="tl-url" title="${escHtml(r.url)}">${escHtml(truncateUrl(r.url, 48))}</span>
        <div class="tl-meta">
          <span class="tl-status ${cls}">${escHtml(r.status)}</span>
          <span class="tl-time">${formatTimestamp(r.timestamp)}</span>
        </div>
      </div>`;
    body.appendChild(item);
  });
}

/* ─────────────────────────────────────────────────────────────
   SIDE PANELS (threats + safe) — preserved from v1
───────────────────────────────────────────────────────────── */
function renderPanels(records) {
  const threats = records.filter(r => r.threat_type !== null).slice(0, PANEL_LIMIT);
  const safe    = records.filter(r => r.threat_type === null).slice(0, PANEL_LIMIT);

  byId('threatsPanelCount').textContent = threats.length;
  const threatsList = byId('threatsList');
  byId('threatsEmpty').hidden = threats.length > 0;
  [...threatsList.querySelectorAll('.panel-row')].forEach(n => n.remove());

  threats.forEach(r => {
    const cls = classifyRecord(r);
    const row = mkEl('div', 'panel-row');
    row.innerHTML = `
      <span class="panel-row-dot ${cls}"></span>
      <div class="panel-row-body">
        <span class="panel-row-url" title="${escHtml(r.url)}">${escHtml(truncateUrl(r.url, 48))}</span>
        <div class="panel-row-meta">
          <span class="panel-row-status ${cls}">${escHtml(r.status)}</span>
          <span class="panel-row-time">${timeAgo(r.timestamp)}</span>
        </div>
      </div>
      <span class="panel-row-score">${r.security_score}/100</span>`;
    threatsList.appendChild(row);
  });

  byId('safePanelCount').textContent = safe.length;
  const safeList = byId('safeList');
  byId('safeEmpty').hidden = safe.length > 0;
  [...safeList.querySelectorAll('.panel-row')].forEach(n => n.remove());

  safe.forEach(r => {
    const row = mkEl('div', 'panel-row');
    row.innerHTML = `
      <span class="panel-row-dot safe"></span>
      <div class="panel-row-body">
        <span class="panel-row-url" title="${escHtml(r.url)}">${escHtml(truncateUrl(r.url, 48))}</span>
        <div class="panel-row-meta">
          <span class="panel-row-status safe">${escHtml(r.status)}</span>
          <span class="panel-row-time">${timeAgo(r.timestamp)}</span>
        </div>
      </div>
      <span class="panel-row-score">${r.security_score}/100</span>`;
    safeList.appendChild(row);
  });
}

/* ─────────────────────────────────────────────────────────────
   EXTENSION ACTIVITY PANEL
───────────────────────────────────────────────────────────── */
function renderExtensionPanel(records) {
  const extRecords = records.filter(r =>
    r.source === 'chrome_extension' || r.source === 'extension'
  );

  const extBadge = byId('extTotalBadge');
  if (extBadge) extBadge.textContent = `${extRecords.length} extension scan${extRecords.length !== 1 ? 's' : ''}`;

  const extThreats = extRecords.filter(r => r.threat_type !== null).slice(0, EXT_LIMIT);
  const extSafe    = extRecords.filter(r => r.threat_type === null).slice(0, EXT_LIMIT);
  // Browser alerts = high-severity extension threats
  const extAlerts  = extRecords.filter(r =>
    r.threat_type && (r.threat_type.includes('MALWARE') || r.threat_type.includes('SOCIAL') || r.threat_type.includes('MALICIOUS'))
  ).slice(0, EXT_LIMIT);

  const countEl = id => byId(id);
  if (countEl('extThreatCount')) countEl('extThreatCount').textContent = extThreats.length;
  if (countEl('extSafeCount'))   countEl('extSafeCount').textContent   = extSafe.length;
  if (countEl('extAlertCount'))  countEl('extAlertCount').textContent  = extAlerts.length;

  function fillExtList(listId, items, emptyMsg) {
    const list = byId(listId);
    if (!list) return;
    list.innerHTML = '';
    if (items.length === 0) {
      list.innerHTML = `<div class="dash-empty-state">
        <span class="dash-empty-icon" style="font-size:1.4rem">🔍</span>
        <p>${emptyMsg}</p>
      </div>`;
      return;
    }
    items.forEach(r => {
      const cls = classifyRecord(r);
      const row = mkEl('div', 'panel-row');
      row.innerHTML = `
        <span class="panel-row-dot ${cls}"></span>
        <div class="panel-row-body">
          <span class="panel-row-url" title="${escHtml(r.url)}">${escHtml(truncateUrl(r.url, 42))}</span>
          <div class="panel-row-meta">
            <span class="panel-row-status ${cls}">${escHtml(r.status)}</span>
            <span class="panel-row-time">${timeAgo(r.timestamp)}</span>
          </div>
        </div>
        <span class="panel-row-score">${r.security_score}/100</span>`;
      list.appendChild(row);
    });
  }

  fillExtList('extThreatList', extThreats, 'No extension threats');
  fillExtList('extSafeList',   extSafe,    'No extension safe scans');
  fillExtList('extAlertList',  extAlerts,  'No browser alerts');
}

/* ─────────────────────────────────────────────────────────────
   SECURITY RECOMMENDATIONS
───────────────────────────────────────────────────────────── */
function renderRecommendations(stats, records) {
  const grid = byId('recGrid');
  if (!grid) return;

  const total   = stats.total_scans  || 0;
  const threats = stats.threat_count || 0;
  const avg     = stats.average_score || 0;
  const threatPct = total > 0 ? (threats / total) * 100 : 0;

  const recs = [];

  if (avg < 40) {
    recs.push({icon:'🚨', title:'Critical: High Threat Rate', text:'Your average security score is critically low. Review all flagged URLs immediately and avoid visiting them.'});
  } else if (avg < 70) {
    recs.push({icon:'⚠️', title:'Moderate Risk Detected', text:'Several scans show suspicious patterns. Consider using HTTPS-only browsing and verify link sources.'});
  } else {
    recs.push({icon:'✅', title:'Good Security Posture', text:'Your scans show a healthy security score. Keep monitoring regularly to maintain this level.'});
  }

  if (threatPct > 20) {
    recs.push({icon:'🔴', title:'High Threat Percentage', text:`${Math.round(threatPct)}% of scans detected threats. Enable real-time protection and avoid suspicious links.`});
  }

  const extRecords = records.filter(r => r.source === 'chrome_extension' || r.source === 'extension');
  if (extRecords.length > 0) {
    const extThreats = extRecords.filter(r => r.threat_type !== null);
    if (extThreats.length > 0) {
      recs.push({icon:'🧩', title:'Extension Threats Blocked', text:`The browser extension blocked ${extThreats.length} threat${extThreats.length>1?'s':''}. Keep the extension active for continuous protection.`});
    } else {
      recs.push({icon:'🧩', title:'Extension Active', text:'Your browser extension is scanning URLs in real-time. All recent extension scans are clean.'});
    }
  } else {
    recs.push({icon:'🧩', title:'Install Browser Extension', text:'Install the CyberShield browser extension for automatic real-time URL scanning while you browse.'});
  }

  recs.push({icon:'🔐', title:'Use Strong Passwords', text:'Regularly analyze your passwords with the Password Analyzer to ensure they meet security standards.'});
  recs.push({icon:'📷', title:'Verify QR Codes', text:'Always scan QR codes with the QR Threat Detector before visiting embedded URLs, especially in public places.'});
  recs.push({icon:'🔄', title:'Regular Scanning', text:'Scan URLs before clicking links in emails or messages. Phishing attacks often use convincing-looking domains.'});

  grid.innerHTML = '';
  recs.slice(0, 6).forEach((r, i) => {
    const card = mkEl('div', 'rec-card');
    card.style.animationDelay = `${i * 60}ms`;
    card.innerHTML = `
      <span class="rec-card-icon">${r.icon}</span>
      <div class="rec-card-body">
        <div class="rec-card-title">${escHtml(r.title)}</div>
        <div class="rec-card-text">${escHtml(r.text)}</div>
      </div>`;
    grid.appendChild(card);
  });
}


/* ─────────────────────────────────────────────────────────────
   HISTORY TABLE — preserved from v1
───────────────────────────────────────────────────────────── */
function getFilteredRecords() {
  return allRecords.filter(r => {
    if (filteredStatus === 'safe'   && r.threat_type !== null) return false;
    if (filteredStatus === 'threat' && r.threat_type === null) return false;
    return true;
  });
}

function renderTable() {
  const filtered   = getFilteredRecords();
  totalRecords     = filtered.length;

  byId('historyTotal').textContent = `${totalRecords} record${totalRecords !== 1 ? 's' : ''}`;

  const tbody      = byId('historyTableBody');
  const tableLoad  = byId('tableLoading');
  const tableEmpty = byId('tableEmpty');
  const tableError = byId('tableError');
  const pagination = byId('pagination');

  tableLoad.hidden  = true;
  tableError.hidden = true;

  if (totalRecords === 0) {
    tbody.innerHTML   = '';
    tableEmpty.hidden = false;
    pagination.hidden = true;
    return;
  }

  tableEmpty.hidden = true;

  const start = currentPage * PAGE_SIZE;
  const page  = filtered.slice(start, Math.min(start + PAGE_SIZE, totalRecords));

  tbody.innerHTML = '';
  page.forEach(r => {
    const cls     = classifyRecord(r);
    const sc      = scoreClass(r.security_score);
    const src     = sourceLabel(r.source);
    const ttLabel = threatTypeLabel(r.threat_type);
    const hasThreat = r.threat_type !== null;

    const tr = mkEl('tr');
    tr.innerHTML = `
      <td class="td-url" title="${escHtml(r.url)}">${escHtml(truncateUrl(r.url, 50))}</td>
      <td><span class="td-status-badge ${cls}">${escHtml(r.status)}</span></td>
      <td><span class="td-threat-type ${hasThreat ? 'has-threat' : ''}">${escHtml(ttLabel)}</span></td>
      <td>
        <div class="td-score">
          <span class="td-score-num ${sc}">${r.security_score}</span>
          <div class="td-score-bar">
            <div class="td-score-fill ${sc}" style="width:${r.security_score}%"></div>
          </div>
        </div>
      </td>
      <td><span class="td-source-badge ${src.cls}">${escHtml(src.label)}</span></td>
      <td class="td-timestamp">${formatTimestamp(r.timestamp)}</td>`;
    tbody.appendChild(tr);
  });

  const totalPages = Math.ceil(totalRecords / PAGE_SIZE);
  if (totalPages > 1) {
    pagination.hidden = false;
    byId('pageInfo').textContent = `Page ${currentPage + 1} of ${totalPages}`;
    byId('prevPageBtn').disabled = currentPage === 0;
    byId('nextPageBtn').disabled = currentPage >= totalPages - 1;
  } else {
    pagination.hidden = true;
  }
}

/* ─────────────────────────────────────────────────────────────
   MAIN REFRESH CYCLE
───────────────────────────────────────────────────────────── */
async function refresh(isManual = false) {
  if (isManual) {
    const btn = byId('manualRefreshBtn');
    if (btn) { btn.classList.add('spinning'); setTimeout(() => btn.classList.remove('spinning'), 600); }
  }

  setStatus('loading', 'Fetching data...');

  try {
    const [historyData, statsData] = await Promise.all([
      fetchHistory(200, 0),
      fetchStats(),
    ]);

    allRecords = historyData.results || [];

    // ── Render all sections ──────────────────────────────────
    renderStats(statsData);
    renderScoreGauge(statsData.average_score || 0);
    renderThreatDist(statsData.by_threat_type || []);
    renderDonut(statsData.safe_count || 0, statsData.threat_count || 0);
    renderSourceBars(statsData.by_source || []);
    renderLiveFeed(allRecords);
    renderTimeline(allRecords);
    renderPanels(allRecords);
    renderExtensionPanel(allRecords);
    renderRecommendations(statsData, allRecords);
    renderTable();
    updateThreatBanner(allRecords);

    // Toast for new threats
    const latestThreat = allRecords.find(r => r.threat_type !== null);
    if (latestThreat && prevTotalScans > 0) {
      const newThreats = allRecords.filter(r => {
        if (!r.threat_type) return false;
        try {
          const age = (Date.now() - new Date(r.timestamp.replace(' ','T')+'Z').getTime()) / 1000;
          return age < REFRESH_MS / 1000 + 2;
        } catch { return false; }
      });
      if (newThreats.length > 0) {
        showToast(`🚨 ${newThreats.length} new threat${newThreats.length>1?'s':''} detected!`, 'danger', 5000);
      }
    }

    setStatus('online', `Connected — ${allRecords.length} records`);
    updateLastUpdated();
    byId('tableLoading').hidden = true;

  } catch (err) {
    setStatus('offline', 'Backend offline');
    byId('tableLoading').hidden = true;
    byId('tableEmpty').hidden   = true;
    byId('tableError').hidden   = false;
    byId('tableErrorMsg').textContent =
      err.name === 'TimeoutError'
        ? 'Request timed out — is Flask running?'
        : `Could not connect: ${err.message}`;
  }
}

/* ─────────────────────────────────────────────────────────────
   AUTO-REFRESH
───────────────────────────────────────────────────────────── */
function startAutoRefresh() {
  stopAutoRefresh();
  refreshTimer = setInterval(() => refresh(false), REFRESH_MS);
}

function stopAutoRefresh() {
  if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
}

/* ─────────────────────────────────────────────────────────────
   CSV EXPORT
───────────────────────────────────────────────────────────── */
function exportCsv() {
  const records = getFilteredRecords();
  if (!records.length) { alert('No records to export.'); return; }

  const headers = ['ID','URL','Status','Threat Type','Source','Security Score','Timestamp'];
  const rows    = records.map(r => [
    r.id,
    `"${(r.url||'').replace(/"/g,'""')}"`,
    `"${(r.status||'').replace(/"/g,'""')}"`,
    r.threat_type || '',
    r.source || '',
    r.security_score,
    r.timestamp || '',
  ].join(','));

  const csv  = [headers.join(','), ...rows].join('\n');
  const blob = new Blob([csv], {type:'text/csv;charset=utf-8;'});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `cybershield-history-${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

/* ─────────────────────────────────────────────────────────────
   MINI MATRIX CANVAS
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
      ctx.fillStyle = `rgba(6,182,212,${a})`;
      ctx.fillText(ch, i * FS, y);
      if (y > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }

  resize();
  window.addEventListener('resize', resize, {passive:true});
  let rafId;
  (function loop() { draw(); rafId = requestAnimationFrame(loop); })();
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) cancelAnimationFrame(rafId);
    else (function loop() { draw(); rafId = requestAnimationFrame(loop); })();
  });
})();

/* ─────────────────────────────────────────────────────────────
   EVENT LISTENERS
───────────────────────────────────────────────────────────── */
(function initEvents() {
  byId('manualRefreshBtn').addEventListener('click', () => refresh(true));

  byId('sourceFilter').addEventListener('change', e => {
    filteredSource = e.target.value;
    currentPage    = 0;
    refresh(false);
  });

  byId('statusFilter').addEventListener('change', e => {
    filteredStatus = e.target.value;
    currentPage    = 0;
    renderTable();
  });

  byId('prevPageBtn').addEventListener('click', () => {
    if (currentPage > 0) { currentPage--; renderTable(); }
  });

  byId('nextPageBtn').addEventListener('click', () => {
    const totalPages = Math.ceil(getFilteredRecords().length / PAGE_SIZE);
    if (currentPage < totalPages - 1) { currentPage++; renderTable(); }
  });

  byId('exportCsvBtn').addEventListener('click', exportCsv);

  // Threat alert banner dismiss
  const dismissBtn = byId('threatAlertDismiss');
  if (dismissBtn) {
    dismissBtn.addEventListener('click', () => {
      alertDismissed = true;
      byId('threatAlertBanner').hidden = true;
    });
  }

  // Pause/resume on tab visibility
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) stopAutoRefresh();
    else { refresh(false); startAutoRefresh(); }
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
  }, {threshold: 0.08, rootMargin: '0px 0px -30px 0px'});
  document.querySelectorAll('.fade-in').forEach(e => obs.observe(e));
})();

/* ─────────────────────────────────────────────────────────────
   BOOT
───────────────────────────────────────────────────────────── */
refresh(false);
startAutoRefresh();
