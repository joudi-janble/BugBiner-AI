// ─── State ────────────────────────────────────────────────────────────────────
let eventCount = 0;
let running = false;
let _scannerAbort = null;
let _scanPaused = false;     // is the scan paused (unified Pause/Resume button)?
let roundCount = 0;

// Mute repeated intro/summary lines on pause/resume (shown once on the first scan only)
let _quietScan = false;
const _SCAN_NOISE = [
  'Node.js crawler', 'Launching browser', 'Crawling http', 'Wordlist done',
  'Browser ready', 'Connected to the running', 'Resuming scan', 'Will scan:', 'skipping already-scanned',
  'Scan Paused', 'Crawled:', 'AI tested:', 'Findings:', 'Scan stopped',
  'Pausing', '═', '─ Scan', 'Paused — progress saved',
];
function _isScanNoise(msg) {
  msg = String(msg || '');
  return _SCAN_NOISE.some(p => msg.includes(p));
}

// Unified Pause <-> Resume button
function _setPauseBtn(mode) {
  const bp = document.getElementById('btnPause');
  if (!bp) return;
  if (mode === 'pause')       { bp.disabled = false; bp.textContent = '⏸ Pause'; }
  else if (mode === 'resume') { bp.disabled = false; bp.textContent = '▶ Resume'; }
  else                        { bp.disabled = true;  bp.textContent = '⏸ Pause'; }  // idle
}

// Unified button click: pause if scanning, resume if paused
function togglePauseResume() {
  if (_scanPaused) {
    resumeScan();            // re-attach to the SAME live task (no re-crawl, no restart)
  } else {
    pauseScan();
  }
}

// Live scan
const _liveDashUrls = new Map();
let _currentTestUrl = null;
let _lscanRowNum = 0;
let _lscanCounts = { total: 0, scanning: 0, done: 0, vulns: 0 };
const _LSCAN_KEY = 'exploitiq_lscan';
const _APP_STATE_KEY = 'exploitiq_app_state';
let _pendingStateSave = null;

function _scheduleStateSave() {
  if (_pendingStateSave !== null) return;
  _pendingStateSave = window.setTimeout(() => {
    _pendingStateSave = null;
    _saveAppState();
  }, 200);
}

// ── Findings Polling (SSE fallback) ──────────────────────────────────────────
// Periodically fetches findings from the backend to guarantee they appear,
// bypassing any SSE delivery issues in the event chain.
let _findingsPollTimer = null;
let _findingsPollTarget = '';

function _startFindingsPoll(url) {
  _stopFindingsPoll();
  if (!url) return;
  _findingsPollTarget = url;
  _findingsPollTimer = setInterval(async () => {
    if (!running) { _stopFindingsPoll(); return; }
    try {
      const resp = await fetch('/api/aicrawl/findings?target=' + encodeURIComponent(_findingsPollTarget));
      if (!resp.ok) return;
      const data = await resp.json();
      const findings = Array.isArray(data) ? data : (data.findings || []);
      for (const f of findings) {
        _addFinding(f);
      }
    } catch(_) {}
  }, 3000);
}

function _stopFindingsPoll() {
  if (_findingsPollTimer) { clearInterval(_findingsPollTimer); _findingsPollTimer = null; }
  _findingsPollTarget = '';
}

// Crawl batching
let _crawlBuf = [];
let _crawlTotal = 0;
let _crawlRow = null;
let _crawlRafPending = false;

// Findings
const _findings = [];
// Track in-progress operations so _renderVulnPanel restores correct button state
const _analyzingSet = new Set();  // finding indices currently being AI-analyzed
const _exploitingSet = new Set(); // finding indices currently being exploit-tested

// Site map (Burp-style tree + table)
const _smData = [];
const _smTree = {};
let _smTotal = 0;
let _smFilterVal = '';
let _smSortKey = 'time';
let _smRafPending = false;
let _smSelectedPath = null;

// AI output accumulator (stream word-by-word → collect into one block)
let _aiBuffer = '';
let _aiFlushTimer = null;

// ── Manual vulnerability selection ──
const _ALL_SCAN_TYPES = ['xss','sqli','lfi','cmdi','ssrf','ssti','xxe','redirect','idor'];
// Display names for each vulnerability type
const _VULN_LABELS = {
  xss:'XSS', sqli:'SQL Injection', lfi:'LFI / Path Traversal',
  cmdi:'Command Injection (RCE)', ssrf:'SSRF', ssti:'SSTI',
  xxe:'XXE', redirect:'Open Redirect', idor:'IDOR',
};
// Types selected for scanning (all by default)
let _selectedVulns = new Set(_ALL_SCAN_TYPES);
let _vulnPickerRendered = false;

// Open/close the vulnerability picker panel (builds it the first time)
function toggleVulnPicker() {
  const panel = document.getElementById('vulnPickerPanel');
  if (!panel) return;
  if (!_vulnPickerRendered) { _renderVulnPicker(); _vulnPickerRendered = true; }
  panel.style.display = (panel.style.display === 'none' || !panel.style.display) ? 'block' : 'none';
}

// Builds the checkboxes next to each vulnerability
function _renderVulnPicker() {
  const panel = document.getElementById('vulnPickerPanel');
  if (!panel) return;
  let html = `<div style="display:flex;gap:8px;margin-bottom:6px">
    <button type="button" onclick="_setAllVulns(true)" style="flex:1;padding:3px 6px;background:var(--bg3);border:1px solid var(--border);color:var(--text2);border-radius:4px;cursor:pointer;font-size:.64rem">Select All</button>
    <button type="button" onclick="_setAllVulns(false)" style="flex:1;padding:3px 6px;background:var(--bg3);border:1px solid var(--border);color:var(--text2);border-radius:4px;cursor:pointer;font-size:.64rem">Clear All</button>
  </div>`;
  for (const t of _ALL_SCAN_TYPES) {
    const checked = _selectedVulns.has(t) ? 'checked' : '';
    html += `<label style="display:flex;align-items:center;gap:8px;padding:4px 2px;cursor:pointer">
      <input type="checkbox" value="${t}" ${checked} onchange="_onVulnToggle(this)" style="cursor:pointer;width:14px;height:14px"/>
      <span style="color:var(--text2)">${escHtml(_VULN_LABELS[t] || t)}</span>
    </label>`;
  }
  panel.innerHTML = html;
  _updateVulnCount();
}

// Update the set when a checkbox is toggled
function _onVulnToggle(cb) {
  if (cb.checked) _selectedVulns.add(cb.value); else _selectedVulns.delete(cb.value);
  _updateVulnCount();
}

// Select / clear all
function _setAllVulns(on) {
  _selectedVulns = on ? new Set(_ALL_SCAN_TYPES) : new Set();
  document.querySelectorAll('#vulnPickerPanel input[type=checkbox]').forEach(cb => { cb.checked = on; });
  _updateVulnCount();
}

// Update the button counter
function _updateVulnCount() {
  const span = document.getElementById('vulnPickerCount');
  if (!span) return;
  const n = _selectedVulns.size;
  span.textContent = (n === 0) ? '(None)' : (n === _ALL_SCAN_TYPES.length) ? '(All)' : `(${n})`;
}

// Selected types as an array
function _getSelectedVulns() {
  return _ALL_SCAN_TYPES.filter(t => _selectedVulns.has(t));
}

// Chat
let _chatHistory = [];
let _chatStreaming = false;
let _chatMode = 'ask';
let _chatImgs = [];
let _chatStopCtrl = null;

// Terminal emulator
let _termRunning = false;
let _termAbort = null;
const _termHistory = [];
let _termHistIdx = -1;

// File browser
let _fbSelectedPath = '';

// ─── Utilities ────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function appendLog(level, msg) {
  const term = document.getElementById('terminal');
  if (!term) return;
  while (term.children.length >= 400) {
    const rm = Math.min(100, term.children.length - 300);
    for (let i = 0; i < rm; i++) if (term.firstChild) term.removeChild(term.firstChild);
  }
  const row = document.createElement('div');
  row.className = `log ${level}`;
  const ts = new Date().toTimeString().slice(0, 8);
  row.innerHTML = `<span class="ts">${ts}</span><span class="tag">${level}</span><span class="msg">${escHtml(String(msg))}</span>`;
  term.appendChild(row);
  eventCount++;
  const ctr = document.getElementById('termCounter');
  if (ctr) ctr.textContent = `${eventCount} events`;
  term.scrollTop = term.scrollHeight;
  if (running || _chatStreaming) _scheduleStateSave();
}

function setStatus(state, text) {
  const dot = document.getElementById('statusDot');
  const txt = document.getElementById('statusText');
  if (dot) {
    dot.className = 'status-dot';
    if (state === 'running') dot.classList.add('running');
    else if (state === 'connected') dot.classList.add('connected');
  }
  if (txt) txt.textContent = text;
}

function clearTerminal() {
  const term = document.getElementById('terminal');
  if (term) term.innerHTML = '';
  eventCount = 0;
  _crawlTotal = 0;
  _crawlRow = null;
  _crawlBuf = [];
  _scanTotal = 0;
  _scanDoneTotal = 0;
  _scanRow = null;
  _scanDoneRow = null;
  _scanBuf = [];
  _scanDoneBuf = [];
  const ctr = document.getElementById('termCounter');
  if (ctr) ctr.textContent = '0 events';
}

async function resetApp() {
  // Reset = full ZERO, immediately: disconnect the local stream, tell the server to hard-stop
  // EVERY scan AND delete the saved scan_state.json on disk (so the next Start is FRESH and never
  // resumes/replays old findings), then wipe the whole UI back to a clean idle state.
  const btnR = document.getElementById('btnReset');
  if (btnR) { btnR.disabled = true; btnR.textContent = '🔄 Resetting…'; }
  try { running = false; if (_scannerAbort) { _scannerAbort.abort(); _scannerAbort = null; } } catch (_) {}
  // wipe browser-side state FIRST so the 5s autosave can't re-persist the old findings mid-reset
  localStorage.removeItem(_APP_STATE_KEY);
  localStorage.removeItem(_LSCAN_KEY);
  _findings.length = 0;
  try {
    await fetch('/api/aicrawl/reset', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
    });
  } catch (_) {}
  clearTerminal();
  _smData.length = 0;
  Object.keys(_smTree).forEach(k => delete _smTree[k]);
  _liveDashUrls.clear();
  _lscanCounts = { total: 0, scanning: 0, done: 0, vulns: 0 };
  _lscanRowNum = 0;
  const tbody = document.getElementById('lscanBody');
  if (tbody) tbody.innerHTML = '';
  const empty = document.getElementById('lscanEmpty');
  if (empty) empty.style.display = 'block';
  const findingsContainer = document.getElementById('findingsContainer');
  if (findingsContainer) findingsContainer.innerHTML = '';
  // zero every badge/counter so nothing stale lingers (Vulns / findings / sitemap)
  ['vulnBadge', 'findingsBadge', 'lscanVulns', 'lscanBadge', 'lscanTotal', 'roundsBadge']
    .forEach(id => { const e = document.getElementById(id); if (e) e.textContent = '0'; });
  const smB = document.getElementById('sitemapBadge'); if (smB) smB.textContent = '0';
  _smTotal = 0;
  const projList = document.getElementById('projList');
  if (projList) projList.innerHTML = projList.innerHTML; // preserve project list if loaded
  _chatHistory = [];
  _chatImgs = [];
  newChat();
  _chatMode = 'ask';
  setStatus('', 'Idle');
  _scanPaused = false;
  _quietScan = false;
  const btnSt = document.getElementById('btnStop'); if (btnSt) btnSt.disabled = true;
  _setPauseBtn('disabled');
  const btnEx = document.getElementById('btnExploit');
  if (btnEx) btnEx.disabled = false;
  const liveInd = document.getElementById('lscanLiveInd');
  if (liveInd) liveInd.style.display = 'none';
  _refreshResumeLabel();
  _saveAppState();
  if (btnR) { btnR.disabled = false; btnR.textContent = '🔄 Reset'; }
  appendLog('saved', '✓ Reset — everything cleared (memory + disk). Next scan starts fresh.');
}

// ─── Tabs ─────────────────────────────────────────────────────────────────────

function _openSiteMap() {
  const ov = document.getElementById('smOverlay');
  if (!ov) return;
  ov.style.display = 'flex';
  const url = (document.getElementById('urlInput')?.value || '').trim();
  const tgt = document.getElementById('smOvTarget');
  if (tgt) tgt.textContent = url || '—';
  _smRender();
}

function _closeSiteMap() {
  const ov = document.getElementById('smOverlay');
  if (ov) ov.style.display = 'none';
}

// ─── Vulnerabilities Panel ────────────────────────────────────────────────────
let _vulnFilter = 'all';

const _SEV_COLOR = { critical: '#ff2244', high: '#ff6600', medium: '#ffaa00', low: '#4488ff', info: '#888888' };
const _SEV_BG    = { critical: '#2a0a10', high: '#1f1000', medium: '#1f1600', low: '#0a1020', info: '#141414' };
const _TYPE_ICON = { xss:'⚡', sqli:'💉', lfi:'📂', cmdi:'💻', ssrf:'🌐', ssti:'🧪', xxe:'📄', redirect:'↗', idor:'🔑', headers:'🛡', verbs:'🔀', unknown:'🔴' };

function _openVulnPanel() {
  const ov = document.getElementById('vulnOverlay');
  if (!ov) return;
  ov.style.display = 'flex';
  _renderVulnPanel();
}

function _closeVulnPanel() {
  const ov = document.getElementById('vulnOverlay');
  if (ov) ov.style.display = 'none';
}

function _vulnSetFilter(sev) {
  _vulnFilter = sev;
  document.querySelectorAll('.vsf-btn').forEach(b => b.classList.remove('vsf-active'));
  const btn = document.querySelector(`.vsf-${sev === 'all' ? 'all' : sev.slice(0,4)}`);
  if (btn) btn.classList.add('vsf-active');
  _renderVulnPanel();
}

function _renderVulnPanel() {
  const list  = document.getElementById('vulnPanelList');
  const empty = document.getElementById('vulnPanelEmpty');
  const cnt   = document.getElementById('vulnOvCount');
  if (!list) return;

  const data = _vulnFilter === 'all' ? _findings
    : _findings.filter(f => (f.severity || 'info').toLowerCase() === _vulnFilter);

  if (cnt) cnt.textContent = data.length + ' vulnerabilit' + (data.length === 1 ? 'y' : 'ies');

  if (!data.length) {
    if (empty) empty.style.display = 'block';
    list.querySelectorAll('.vuln-card').forEach(c => c.remove());
    return;
  }
  if (empty) empty.style.display = 'none';

  // Re-render all cards fresh
  list.querySelectorAll('.vuln-card').forEach(c => c.remove());
  const frag = document.createDocumentFragment();
  [...data].reverse().forEach((f, ri) => {
    const sev   = (f.severity || 'info').toLowerCase();
    const color = _SEV_COLOR[sev] || '#888';
    const bg    = _SEV_BG[sev]    || '#111';
    const typeKey = (f.vuln_type || '').toLowerCase().replace(/[^a-z]/g,'');
    const icon  = _TYPE_ICON[typeKey] || _TYPE_ICON.unknown;
    const time  = f.time || '';

    const card = document.createElement('div');
    card.className = 'vuln-card';
    card.style.cssText = `border-left:3px solid ${color};background:${bg}`;

    let reqHtml = '';
    if (f.request || f.evidence) {
      const raw = f.request || f.evidence || '';
      reqHtml = `<details class="vuln-req-details">
        <summary class="vuln-req-summary">📋 Request / Evidence</summary>
        <pre class="vuln-req-pre">${escHtml(raw.slice(0, 1200))}</pre>
      </details>`;
    }
    const payloadHtml = f.payload
      ? `<div class="vuln-payload"><span class="vuln-label">Payload:</span><code class="vuln-code">${escHtml(f.payload)}</code></div>`
      : '';

    card.innerHTML = ''
      + '<div class="vuln-card-hdr">'
      + '<span class="vuln-sev-pill" style="background:' + color + '15;color:' + color + ';border:1px solid ' + color + '40">' + sev.toUpperCase() + '</span>'
      + '<span class="vuln-icon">' + icon + '</span>'
      + '<span class="vuln-type-lbl">' + escHtml(f.vuln_type || 'Unknown') + '</span>'
      + (f.ai_analysis ? '<span class="ai-badge ' + (f.ai_analysis.real ? 'ai-real' : 'ai-fp') + '" style="margin-left:auto;font-size:.6rem">' + (f.ai_analysis.real ? 'REAL' : 'FP') + '</span>' : '')
      + (time ? '<span class="vuln-time">' + escHtml(time) + '</span>' : '')
      + '</div>'
      + '<div class="vuln-url" style="cursor:pointer" title="' + escHtml(f.url||'') + '" onclick="window.open(' + JSON.stringify(f.url||'') + ',\'_blank\',\'noopener\')">' + escHtml(f.url || '—') + '</div>'
      + (f.detail ? '<div class="vuln-detail">' + escHtml(f.detail) + '</div>' : '')
      + payloadHtml
      + reqHtml
      + (f.exploit_result ? _exploitResultHtml(f.exploit_result) : '')
      + (f.ai_analysis ? _aiAnalysisHtml(f.ai_analysis) : '')
      + (function(){
        const _fi = _findings.indexOf(f);
        const _ia = _analyzingSet.has(_fi);
        const _ie = _exploitingSet.has(_fi);
        return '<div style="margin-top:6px;padding-top:5px;border-top:1px solid var(--border)">'
          + '<button class="ai-analyze-btn"' + (_ia ? ' disabled' : '') + ' onclick="var idx=' + _fi + ';_analyzeFinding(idx,this)">' + (_ia ? '⏳ Analyzing…' : '🤖 Analyze with AI') + '</button>'
          + ' <button class="exploit-btn"' + (_ie ? ' disabled' : '') + ' onclick="var idx=' + _fi + ';_exploitFinding(idx,this)">' + (_ie ? '⏳ Testing…' : '⚡ Exploit & Test') + '</button>'
          + '</div>';
      })()
    frag.appendChild(card);
  });
  list.insertBefore(frag, list.firstChild);
}


// ─── Crawl batching ───────────────────────────────────────────────────────────
function _flushCrawl() {
  _crawlRafPending = false;
  if (!_crawlBuf.length) return;
  const batch = _crawlBuf.splice(0);
  const term = document.getElementById('terminal');
  if (!term) return;
  if (!_crawlRow || !_crawlRow.isConnected) {
    _crawlRow = document.createElement('div');
    _crawlRow.className = 'log crawl';
    const ts = new Date().toTimeString().slice(0, 8);
    _crawlRow.innerHTML = `<span class="ts">${ts}</span><span class="tag">crawl</span><span class="msg" id="crawl-counter"></span>`;
    term.appendChild(_crawlRow);
  }
  _crawlTotal += batch.length;
  const cEl = document.getElementById('crawl-counter');
  if (cEl) cEl.textContent = `${_crawlTotal} URLs  |  ${(batch[batch.length - 1] || '').slice(0, 80)}`;
  eventCount += batch.length;
  const ctr = document.getElementById('termCounter');
  if (ctr) ctr.textContent = `${eventCount} events`;
  term.scrollTop = term.scrollHeight;
  while (term.children.length > 400) term.removeChild(term.firstChild);
}

function _scheduleCrawlFlush() {
  if (!_crawlRafPending) {
    _crawlRafPending = true;
    requestAnimationFrame(_flushCrawl);
  }
}

// ─── Scan batching (rolling single row per scan/scan_done) ────────────────────
let _scanBuf = [];
let _scanDoneBuf = [];
let _scanRow = null;
let _scanDoneRow = null;
let _scanTotal = 0;
let _scanDoneTotal = 0;
let _scanRafPending = false;

function _flushScan() {
  _scanRafPending = false;
  const term = document.getElementById('terminal');
  if (!term) return;

  if (_scanBuf.length) {
    const batch = _scanBuf.splice(0);
    _scanTotal += batch.length;
    if (!_scanRow || !_scanRow.isConnected) {
      _scanRow = document.createElement('div');
      _scanRow.className = 'log scan';
      const ts = new Date().toTimeString().slice(0, 8);
      _scanRow.innerHTML = `<span class="ts">${ts}</span><span class="tag">SCAN</span><span class="msg" id="scan-counter"></span>`;
      term.appendChild(_scanRow);
    }
    const el = document.getElementById('scan-counter');
    if (el) el.textContent = `🔍 Testing ${_scanTotal} URLs…  |  ${(batch[batch.length-1]||'').slice(0,80)}`;
  }

  if (_scanDoneBuf.length) {
    const batch = _scanDoneBuf.splice(0);
    _scanDoneTotal += batch.length;
    if (!_scanDoneRow || !_scanDoneRow.isConnected) {
      _scanDoneRow = document.createElement('div');
      _scanDoneRow.className = 'log scan_done';
      const ts = new Date().toTimeString().slice(0, 8);
      _scanDoneRow.innerHTML = `<span class="ts">${ts}</span><span class="tag">DONE</span><span class="msg" id="scan-done-counter"></span>`;
      term.appendChild(_scanDoneRow);
    }
    const el = document.getElementById('scan-done-counter');
    if (el) el.textContent = `✓ ${_scanDoneTotal} URLs scanned  |  last: ${(batch[batch.length-1]||'').slice(0,70)}`;
  }

  const ctr = document.getElementById('termCounter');
  if (ctr) ctr.textContent = `${eventCount + _scanTotal + _scanDoneTotal} events`;
  term.scrollTop = term.scrollHeight;
  while (term.children.length > 600) term.removeChild(term.firstChild);
}

function _scheduleScanFlush() {
  if (!_scanRafPending) {
    _scanRafPending = true;
    requestAnimationFrame(_flushScan);
  }
}
function _buildLscanRow(url, httpStatus, codeClass, num) {
  const tr = document.createElement('tr');
  tr.className = 'lscan-row';
  tr.dataset.url = url;
  const safe = escHtml(url);
  const scanTd = document.createElement('td');
  scanTd.className = 'lscan-status lscan-status-queued';
  scanTd.textContent = '⏳ Queued';
  tr.innerHTML = `<td class="lscan-num">${num}</td><td class="lscan-code ${codeClass}">${httpStatus}</td><td class="lscan-url" title="${safe}">${safe}</td>`;
  tr.appendChild(scanTd);
  return tr;
}

function _addToLiveDashQueued(url, httpStatus) {
  if (_liveDashUrls.has(url)) return;
  const tbody = document.getElementById('lscanBody');
  if (!tbody) return;
  const empty = document.getElementById('lscanEmpty');
  if (empty) empty.style.display = 'none';
  _lscanRowNum++;
  const cc = httpStatus >= 200 && httpStatus < 300 ? 'lscan-code-2xx'
           : httpStatus === 401 || httpStatus === 403 ? 'lscan-code-auth'
           : 'lscan-code-other';
  const tr = _buildLscanRow(url, httpStatus, cc, _lscanRowNum);
  const scanTd = tr.querySelector('td:last-child');
  tbody.appendChild(tr);
  _liveDashUrls.set(url, { rowEl: tr, scanEl: scanTd, scanStatus: 'queued', httpStatus, codeClass: cc });
  _lscanCounts.total++;
  _updateLscanStats();
  _lscanSave();
  const wrap = document.querySelector('.lscan-table-wrap');
  if (wrap) wrap.scrollTop = wrap.scrollHeight;
}

function _markLiveDashScanning(url) {
  const entry = _liveDashUrls.get(url);
  if (!entry) return;
  entry.scanStatus = 'scanning';
  if (entry.scanEl) {
    entry.scanEl.textContent = '⟺ Testing…';
    entry.scanEl.className = 'lscan-status lscan-status-scanning';
  }
  _lscanCounts.scanning++;
  _updateLscanStats();
}

function _markLiveDashDone(url) {
  const entry = _liveDashUrls.get(url);
  if (!entry || entry.scanStatus === 'vuln') return;
  entry.scanStatus = 'done';
  if (entry.scanEl) {
    entry.scanEl.textContent = '✓ Done';
    entry.scanEl.className = 'lscan-status lscan-status-done';
  }
  if (_lscanCounts.scanning > 0) _lscanCounts.scanning--;
  _lscanCounts.done++;
  _updateLscanStats();
  _lscanSave();
}

function _markLiveDashVuln(url) {
  const entry = _liveDashUrls.get(url);
  if (!entry) return;
  const wasScanning = entry.scanStatus === 'scanning';
  entry.scanStatus = 'vuln';
  if (entry.scanEl) {
    entry.scanEl.textContent = '🚨 Vuln!';
    entry.scanEl.className = 'lscan-status lscan-status-vuln';
  }
  if (entry.rowEl) entry.rowEl.classList.add('lscan-row-vuln');
  if (wasScanning && _lscanCounts.scanning > 0) _lscanCounts.scanning--;
  _lscanCounts.done++;
  _lscanCounts.vulns++;
  const fb = document.getElementById('findingsBadge');
  if (fb) fb.textContent = _lscanCounts.vulns;
  _updateLscanStats();
  _lscanSave();
}

function _updateLscanStats() {
  const el = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
  el('lscanTotal',    _lscanCounts.total);
  el('lscanScanning', _lscanCounts.scanning);
  el('lscanDone',     _lscanCounts.done);
  el('lscanVulns',    _lscanCounts.vulns);
  el('lscanBadge',    _lscanCounts.total);
}

function _lscanSave() {
  try {
    const rows = [];
    _liveDashUrls.forEach((e, url) => {
      rows.push({ url, httpStatus: e.httpStatus, codeClass: e.codeClass, scanStatus: e.scanStatus });
    });
    localStorage.setItem(_LSCAN_KEY, JSON.stringify({ counts: _lscanCounts, rowNum: _lscanRowNum, rows }));
    _scheduleStateSave();
  } catch(_) {}
}

function _saveAppState() {
  try {
    const term = document.getElementById('terminal');
    const logs = [];
    if (term) {
      const rows = Array.from(term.children).slice(-100);
      for (const row of rows) {
        logs.push({
          ts: row.querySelector('.ts')?.textContent || '',
          level: row.querySelector('.tag')?.textContent || '',
          msg: row.querySelector('.msg')?.textContent || '',
        });
      }
    }

    const state = {
      running,
      urlInput: document.getElementById('urlInput')?.value || '',
      chatInput: document.getElementById('chatInput')?.value || '',
      findings: _findings,
      smData: _smData,
      smSelectedPath: _smSelectedPath,
      lscanCounts: _lscanCounts,
      lscanRows: [],
      lscanRowNum: _lscanRowNum,
      chatHistory: _chatHistory,
      chatMode: _chatMode,
      terminalLogs: logs,
      // Ollama settings
      ollama_enabled: document.getElementById('ollamaPanel') ? true : false,
      ollama_base: document.getElementById('ollamaBase')?.value || 'http://localhost:11434',
      ollama_model: document.getElementById('ollamaModel')?.value || 'qwen2.5:7b',
    };
    _liveDashUrls.forEach((e, url) => {
      state.lscanRows.push({ url, httpStatus: e.httpStatus, codeClass: e.codeClass, scanStatus: e.scanStatus });
    });
    localStorage.setItem(_APP_STATE_KEY, JSON.stringify(state));
  } catch(_) {}
}

function _restoreAppState() {
  try {
    const raw = localStorage.getItem(_APP_STATE_KEY);
    if (!raw) return false;
    const state = JSON.parse(raw);
    if (!state) return false;

    const urlEl = document.getElementById('urlInput');
    if (urlEl && state.urlInput) urlEl.value = state.urlInput;

    const chatInput = document.getElementById('chatInput');
    if (chatInput && state.chatInput) chatInput.value = state.chatInput;

    // Restore Ollama settings
    if (state.ollama_enabled) {
      const ollamaBase = document.getElementById('ollamaBase');
      if (ollamaBase && state.ollama_base) ollamaBase.value = state.ollama_base;
      
      const ollamaModel = document.getElementById('ollamaModel');
      if (ollamaModel && state.ollama_model) ollamaModel.value = state.ollama_model;
    }

    if (Array.isArray(state.findings) && state.findings.length) {
      _findings.length = 0;
      state.findings.forEach(f => _addFinding(f));
    }

    if (Array.isArray(state.smData) && state.smData.length) {
      _smData.length = 0;
      Object.keys(_smTree).forEach(k => delete _smTree[k]);
      state.smData.forEach(entry => _smData.push(entry));
      _smRender();
    }

    if (Array.isArray(state.lscanRows) && state.lscanRows.length) {
      _lscanCounts = state.lscanCounts || { total: 0, scanning: 0, done: 0, vulns: 0 };
      _lscanRowNum = state.lscanRowNum || 0;
      _lscanCounts.scanning = 0;
      const tbody = document.getElementById('lscanBody');
      const empty = document.getElementById('lscanEmpty');
      if (tbody) {
        state.lscanRows.forEach(r => {
          const st = r.scanStatus === 'scanning' ? 'done' : r.scanStatus;
          const tr = _buildLscanRow(r.url, r.httpStatus, r.codeClass || 'lscan-code-2xx', 0);
          const scanTd = tr.querySelector('td:last-child');
          if (st === 'done' && scanTd)  { scanTd.textContent = '✓ Done';   scanTd.className = 'lscan-status lscan-status-done'; }
          if (st === 'vuln' && scanTd)  { scanTd.textContent = '🚨 Vuln!'; scanTd.className = 'lscan-status lscan-status-vuln'; tr.classList.add('lscan-row-vuln'); }
          tbody.appendChild(tr);
          _liveDashUrls.set(r.url, { rowEl: tr, scanEl: scanTd, scanStatus: st, httpStatus: r.httpStatus, codeClass: r.codeClass });
        });
        if (state.lscanRows.length && empty) empty.style.display = 'none';
      }
      _updateLscanStats();
    }

    if (state.running) {
      running = true;
      setStatus('running', 'Scanning…');
      const btnSt = document.getElementById('btnStop');  if (btnSt) btnSt.disabled = false;
      _setPauseBtn('pause');
      const liveInd = document.getElementById('lscanLiveInd');
      if (liveInd) liveInd.style.display = 'inline';
      const btnEx = document.getElementById('btnExploit');
      if (btnEx) btnEx.disabled = true;
    }

    if (Array.isArray(state.chatHistory) && state.chatHistory.length) {
      _chatHistory = state.chatHistory;
      const msgs = document.getElementById('chatMsgs');
      if (msgs) {
        msgs.innerHTML = '';
        state.chatHistory.forEach(item => {
          const row = document.createElement('div');
          row.className = item.role === 'user' ? 'chat-row-user' : 'chat-row-ai';
          const bubble = document.createElement('div');
          bubble.className = 'chat-bubble ' + (item.role === 'user' ? 'user msg-bubble' : 'ai');
          bubble.textContent = item.content;
          row.appendChild(bubble);
          msgs.appendChild(row);
        });
        msgs.scrollTop = msgs.scrollHeight;
      }
    }

    if (Array.isArray(state.terminalLogs) && state.terminalLogs.length) {
      const term = document.getElementById('terminal');
      if (term) {
        term.innerHTML = '';
        state.terminalLogs.forEach(log => {
          const row = document.createElement('div');
          row.className = `log ${escHtml(log.level || '')}`;
          row.innerHTML = `<span class="ts">${escHtml(log.ts || '')}</span><span class="tag">${escHtml(log.level || '')}</span><span class="msg">${escHtml(log.msg || '')}</span>`;
          term.appendChild(row);
        });
        eventCount = term.children.length;
        const ctr = document.getElementById('termCounter');
        if (ctr) ctr.textContent = `${eventCount} events`;
        term.scrollTop = term.scrollHeight;
      }
    }

    _smSelectedPath = state.smSelectedPath || null;
    if (_smSelectedPath) {
      _smRender();
    }

    return true;
  } catch(_) {
    return false;
  }
}

function _lscanRestore() {
  try {
    const raw = localStorage.getItem(_LSCAN_KEY);
    if (!raw) return;
    const state = JSON.parse(raw);
    if (!state || !Array.isArray(state.rows) || !state.rows.length) return;
    _lscanCounts = state.counts || { total: 0, scanning: 0, done: 0, vulns: 0 };
    _lscanRowNum = state.rowNum || 0;
    _lscanCounts.scanning = 0;
    const tbody = document.getElementById('lscanBody');
    const empty = document.getElementById('lscanEmpty');
    if (!tbody) return;
    state.rows.forEach(r => {
      const st = r.scanStatus === 'scanning' ? 'done' : r.scanStatus;
      const tr = _buildLscanRow(r.url, r.httpStatus, r.codeClass || 'lscan-code-2xx', 0);
      const scanTd = tr.querySelector('td:last-child');
      if (st === 'done' && scanTd)  { scanTd.textContent = '✓ Done';   scanTd.className = 'lscan-status lscan-status-done'; }
      if (st === 'vuln' && scanTd)  { scanTd.textContent = '🚨 Vuln!'; scanTd.className = 'lscan-status lscan-status-vuln'; tr.classList.add('lscan-row-vuln'); }
      tbody.appendChild(tr);
      _liveDashUrls.set(r.url, { rowEl: tr, scanEl: scanTd, scanStatus: st, httpStatus: r.httpStatus, codeClass: r.codeClass });
    });
    if (state.rows.length && empty) empty.style.display = 'none';
    _updateLscanStats();
  } catch(_) {}
}

function clearLiveDash() {
  _liveDashUrls.clear();
  _currentTestUrl = null;
  _lscanRowNum = 0;
  _lscanCounts = { total: 0, scanning: 0, done: 0, vulns: 0 };
  const tbody = document.getElementById('lscanBody');
  if (tbody) tbody.innerHTML = '';
  const empty = document.getElementById('lscanEmpty');
  if (empty) empty.style.display = 'block';
  const ind = document.getElementById('lscanLiveInd');
  if (ind) ind.style.display = 'none';
  _updateLscanStats();
  try { sessionStorage.removeItem(_LSCAN_KEY); } catch(_) {}
}

// ─── Site Map (Burp-style tree + table) ───────────────────────────────────────
function _smAdd(url, method, status, mimeType, contentLength, hasParams, time) {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname;
    const path = parsed.pathname;
    const entry = { url, host, path, method: method || 'GET', status: status || 0,
                    mimeType: mimeType || '', contentLength: contentLength || 0,
                    hasParams: hasParams || false, time, vulns: [],
                    scanned: false, scanStatus: 'pending' };
    _smData.push(entry);
    _smTotal++;

    const badge = document.getElementById('sitemapBadge');
    if (badge) badge.textContent = _smTotal;
    const ovFound = document.getElementById('smOvFound');
    if (ovFound) ovFound.textContent = _smTotal;

    if (!_smTree[host]) {
      _smTree[host] = { name: host, path: '', host, count: 0, children: {}, entries: [], _open: true };
    }
    _smTree[host].count++;
    _smTree[host].entries.push(entry);

    const parts = path.split('/').filter(Boolean);
    let node = _smTree[host];
    let cur = '';
    for (const part of parts) {
      cur += '/' + part;
      if (!node.children[part]) {
        node.children[part] = { name: part, path: cur, host, count: 0, children: {}, entries: [], _open: false };
      }
      node = node.children[part];
      node.count++;
      node.entries.push(entry);
    }

    if (!_smRafPending) {
      _smRafPending = true;
      requestAnimationFrame(_smRender);
    }
    _scheduleStateSave();
  } catch(_) {}
}

// Mark a site-map link's scan state ('scanning' | 'scanned') so the map shows which were tested
function _smSetScan(url, st) {
  let changed = false;
  for (const e of _smData) {
    if (e.url === url) {
      if (st === 'scanned') { if (!e.scanned) { e.scanned = true; e.scanStatus = 'scanned'; changed = true; } }
      else if (e.scanStatus !== 'scanned' && e.scanStatus !== st) { e.scanStatus = st; changed = true; }
    }
  }
  if (changed && !_smRafPending) { _smRafPending = true; requestAnimationFrame(_smRender); }
}

function _smRender() {
  _smRafPending = false;
  _smRenderTree();
  _smRenderTable();
}

function _smRenderTree() {
  const el = document.getElementById('smTree');
  if (!el) return;
  const hosts = Object.keys(_smTree).sort();
  if (!hosts.length) {
    el.innerHTML = '<div class="sm-tree-empty">No URLs yet</div>';
    return;
  }
  el.innerHTML = hosts.map(h => _smNodeHtml(_smTree[h], 0)).join('');
}

function _smDirectEntries(node) {
  const npath = node.path.replace(/\/$/, '') || '/';
  return node.entries.filter(e => (e.path.replace(/\/$/, '') || '/') === npath);
}

function _smLeafHtml(entry, depth) {
  const pad = 4 + depth * 14;
  const stCls = entry.status >= 200 && entry.status < 300 ? 'sm-s-2xx'
              : entry.status >= 300 && entry.status < 400 ? 'sm-s-3xx' : 'sm-s-err';
  let fname;
  try {
    const u = new URL(entry.url);
    fname = u.pathname.split('/').filter(Boolean).pop() || '/';
    if (u.search) fname += u.search;
  } catch { fname = entry.url; }
  const safeUrl = JSON.stringify(entry.url);
  const vulnCount = (entry.vulns || []).length;
  const vulnBadge = vulnCount ? `<span class="sm-leaf-vuln">🚨</span>` : '';
  return `<div class="sm-tree-leaf" style="padding-left:${pad}px;cursor:pointer"
    title="${escHtml(entry.url)} — click to open in a new tab"
    onclick="event.stopPropagation();window.open(${safeUrl},'_blank','noopener')">
    <span class="sm-tn-arrow sm-tn-arrow-none">▸</span>
    <span class="sm-tn-ficon sm-tn-file">📄</span>
    <span class="sm-tn-lbl">${escHtml(fname)}</span>
    ${vulnBadge}
    <span class="sm-tn-st ${stCls}">${entry.status}</span>
  </div>`;
}

function _smNodeHtml(node, depth) {
  const key = node.host + ':' + node.path;
  const isSel = _smSelectedPath === key;
  const hasKids = Object.keys(node.children).length > 0;
  const directEntries = _smDirectEntries(node);
  const selCls = isSel ? ' sm-tree-sel' : '';
  const safeKey = key.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  const pad = 4 + depth * 14;

  const arrowHtml = hasKids
    ? `<span class="sm-tn-arrow" onclick="event.stopPropagation();_smToggle('${safeKey}')">${node._open ? '▾' : '▸'}</span>`
    : `<span class="sm-tn-arrow sm-tn-arrow-none">▸</span>`;
  const folderIcon = node._open ? '📂' : '📁';

  let h = `<div class="sm-tree-node${selCls}" style="padding-left:${pad}px"
    onclick="event.stopPropagation();_smClickNode('${safeKey}')"
    ondblclick="event.stopPropagation();_smToggle('${safeKey}')">
    ${arrowHtml}<span class="sm-tn-ficon">${folderIcon}</span>
    <span class="sm-tn-lbl">${escHtml(node.name || node.host)}</span>
    <span class="sm-tn-cnt">${node.count}</span>
  </div>`;

  if (node._open) {
    if (hasKids) {
      const kids = Object.values(node.children).sort((a, b) => a.name.localeCompare(b.name));
      h += kids.map(c => _smNodeHtml(c, depth + 1)).join('');
    }
    if (directEntries.length) {
      h += directEntries.map(e => _smLeafHtml(e, depth + 1)).join('');
    }
  }
  return h;
}

function _smClickNode(key) {
  _smSelectedPath = _smSelectedPath === key ? null : key;
  _smRenderTree();
  _smRenderTable();
}

function _smToggle(key) {
  const colonIdx = key.indexOf(':');
  const host = key.slice(0, colonIdx);
  const path = key.slice(colonIdx + 1);
  const node = _smFindNode(_smTree[host], path);
  if (node) { node._open = !node._open; _smRenderTree(); }
}

function _smFindNode(node, path) {
  if (!node) return null;
  if (node.path === path) return node;
  for (const child of Object.values(node.children)) {
    const found = _smFindNode(child, path);
    if (found) return found;
  }
  return null;
}

function _smRenderTable() {
  const tbody = document.getElementById('smBody');
  if (!tbody) return;
  const empty   = document.getElementById('smEmpty');
  const countEl = document.getElementById('smCount');

  let data = _smData;
  if (_smSelectedPath) {
    const colonIdx = _smSelectedPath.indexOf(':');
    const host = _smSelectedPath.slice(0, colonIdx);
    const path = _smSelectedPath.slice(colonIdx + 1);
    const node = _smTree[host] ? _smFindNode(_smTree[host], path) : null;
    if (node) data = node.entries;
  }

  if (_smFilterVal) {
    data = data.filter(r => r.url.toLowerCase().includes(_smFilterVal) || r.host.toLowerCase().includes(_smFilterVal));
  }

  if (_smSortKey === 'host')        data = [...data].sort((a, b) => a.host.localeCompare(b.host) || a.url.localeCompare(b.url));
  else if (_smSortKey === 'status') data = [...data].sort((a, b) => a.status - b.status);
  else if (_smSortKey === 'length') data = [...data].sort((a, b) => b.contentLength - a.contentLength);
  else if (_smSortKey === 'mime')   data = [...data].sort((a, b) => a.mimeType.localeCompare(b.mimeType));

  if (countEl) countEl.textContent = data.length + ' items';
  const visible = data.slice(0, 2000);
  const html = visible.map(r => {
    let upath;
    try { const u = new URL(r.url); upath = u.pathname + (u.search || ''); } catch { upath = r.url; }
    const mime  = (r.mimeType || '').replace('application/', '').replace('text/', '');
    const stCls = r.status >= 200 && r.status < 300 ? 'sm-2xx' : r.status >= 400 ? 'sm-4xx' : 'sm-3xx';
    const lenTxt = r.contentLength > 1048576 ? (r.contentLength / 1048576).toFixed(1) + 'M'
                 : r.contentLength > 1024    ? (r.contentLength / 1024).toFixed(1) + 'k'
                 : r.contentLength > 0       ? String(r.contentLength) : '';
    const vulnCount = (r.vulns || []).length;
    const sevColors = { critical: '#ff2244', high: '#ff6600', medium: '#ffaa00', low: '#4488ff', info: '#888' };
    const vulnHtml = vulnCount
      ? `<span class="sm-vuln-badge" title="${escHtml((r.vulns).map(v=>v.vuln_type).join(', '))}" style="color:${sevColors[(r.vulns[0].severity||'high').toLowerCase()]||'#ff6600'}">🚨 ${vulnCount}</span>`
      : r.scanStatus === 'scanned'
        ? '<span class="sm-scanned-tick" title="Scanned — no vuln found">✓</span>'
        : r.scanStatus === 'scanning'
          ? '<span class="sm-scanning-dot" title="Scanning…"></span>'
          : '';
    const rowCls = vulnCount ? ' sm-row-vuln' : (r.scanned ? ' sm-row-scanned' : '');
    return `<tr class="sm-row${rowCls}" onclick="window.open(${JSON.stringify(r.url)},'_blank')" title="${escHtml(r.url)}">
      <td class="sm-host-cell">${escHtml(r.host)}</td>
      <td class="sm-method${r.method === 'POST' ? ' sm-post' : ''}">${escHtml(r.method)}</td>
      <td class="sm-url">${escHtml(upath)}</td>
      <td class="sm-center">${r.hasParams ? '<span class="sm-params-tick">✓</span>' : ''}</td>
      <td class="sm-center sm-status ${stCls}">${r.status}</td>
      <td class="sm-right sm-len">${lenTxt}</td>
      <td class="sm-mime">${escHtml(mime)}</td>
      <td class="sm-center sm-vuln-cell">${vulnHtml}</td>
      <td class="sm-time">${r.time}</td>
    </tr>`;
  }).join('');
  tbody.innerHTML = html;
  if (empty) empty.style.display = visible.length ? 'none' : 'block';
}

function _filterSiteMap(val) {
  _smFilterVal = val.toLowerCase();
  if (!_smRafPending) { _smRafPending = true; requestAnimationFrame(_smRender); }
}

function _sortSiteMap(key) {
  _smSortKey = key;
  if (!_smRafPending) { _smRafPending = true; requestAnimationFrame(_smRender); }
}

// ─── SSE Handler ──────────────────────────────────────────────────────────────
function handleMsg(d) {
  const level = d.level || 'info';

  if (level === 'stats') {
    const el = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
    el('lscanQueue', d.queued || 0);
    el('lscanRps',   d.rps    || 0);
    el('smOvFound',  _smTotal);
    el('smOvQueue',  d.queued || 0);
    el('smOvRps',    d.rps    || 0);
    return;
  }

  if (level === 'live_url') {
    const url = d.url;
    const st  = d.status || 0;
    if (d.state === 'found') {
      _addToLiveDashQueued(url, st);
      _smAdd(url, d.method || 'GET', st, d.mimeType || '', d.contentLength || 0,
             d.hasParams || false, new Date().toLocaleTimeString());
      // batch crawl URLs into a single rolling line in the terminal
      _crawlBuf.push(url);
      _scheduleCrawlFlush();
    } else if (d.state === 'scanning') {
      _markLiveDashScanning(url);
      _smSetScan(url, 'scanning');
    } else if (d.state === 'done') {
      _markLiveDashDone(url);
      _smSetScan(url, 'scanned');
    }
    return;
  }

  if (level === 'vuln') {
    const f = d.finding;
    if (f && _addFinding(f)) {
      _markLiveDashVuln(f.url || '');
      const furl = f.url || '';
      const smEntry = _smData.find(e => e.url === furl || furl.startsWith(e.url));
      if (smEntry) { smEntry.vulns.push(f); if (!_smRafPending) { _smRafPending = true; requestAnimationFrame(_smRender); } }
    }
    return;
  }

  if (level === 'eof' || level === 'done') { stopExploit(true); return; }
  if (level === 'phase')  {
    const _pm = d.message || d.phase || '';
    if (_quietScan && _isScanNoise(_pm)) return;   // do not repeat the intro/summary on resume
    appendLog('phase', _pm); return;
  }
  if (level === 'ai') {
    // Accumulate AI tokens silently, flush to sidebar panel after idle
    _aiBuffer += (d.message || d.content || '');
    if (_aiFlushTimer) clearTimeout(_aiFlushTimer);
    _aiFlushTimer = setTimeout(() => {
      const panel = document.getElementById('aiOutputPanel');
      const wrap  = document.getElementById('aiScanPanel');
      if (panel && _aiBuffer.trim()) {
        if (wrap) wrap.style.display = 'flex';
        panel.textContent = _aiBuffer;
        panel.scrollTop = panel.scrollHeight;
      }
      _aiBuffer = '';
    }, 500);
    return;
  }
  if (level === 'crawl')  { _crawlBuf.push(d.url || d.message || ''); _scheduleCrawlFlush(); return; }
  if (level === 'scan')   { _scanBuf.push(d.message || ''); _scheduleScanFlush(); return; }
  if (level === 'scan_done') { _scanDoneBuf.push(d.message || ''); _scheduleScanFlush(); return; }
  if (level === 'info')   { /* suppress info noise */ return; }
  if (level === 'saved')  { appendLog('saved', d.message || ''); return; }
  if (level === 'error')  { appendLog('error', d.message || ''); return; }
  if (level === 'warn')   { appendLog('warn',  d.message || ''); return; }
}

// ─── Scan Control ─────────────────────────────────────────────────────────────
async function startExploit() {
  const url = (document.getElementById('urlInput')?.value || '').trim();
  if (!url) { alert('Enter the target URL'); return; }

  // ── Scan types = the manually selected vulnerabilities ──
  const _scanTypes = _getSelectedVulns();
  if (!_scanTypes.length) { alert('Select at least one vulnerability type from "Select Vulnerabilities"'); return; }

  // ── Is there saved progress for this target? → resume from where it stopped ──
  let _doResume = false;
  try {
    const _st = await fetch('/api/aicrawl/state?target=' + encodeURIComponent(url)).then(r => r.json());
    if (_st.exists && _st.resumable && _st.tested_count > 0) {
      _doResume = true;
    }
  } catch(_) {}

  // On resume: clear nothing and don't print the intro → silent resume continues as-is
  if (_doResume) {
    _quietScan = true;   // mute the repeated intro/summary throughout this scan
  } else {
    _quietScan = false;  // new scan for a target → show the intro once
    clearTerminal();
    clearLiveDash();
    const _rb = document.getElementById('roundsBody'); if (_rb) _rb.innerHTML = '';
    const _nr = document.getElementById('noResults'); if (_nr) _nr.style.display = 'block';
    const _fc = document.getElementById('findingsContainer'); if (_fc) _fc.innerHTML = '<span class="no-data">Scanning…</span>';
    _findings.length = 0;
    const fb = document.getElementById('findingsBadge'); if (fb) fb.textContent = '0';
    _updateFindingsDisplay();
    roundCount = 0;
    const rb = document.getElementById('roundsBadge'); if (rb) rb.textContent = '0';
    appendLog('scan', '🎯 Will scan: ' + _scanTypes.map(t => _VULN_LABELS[t] || t).join(', '));
  }

  running = true;
  _scanPaused = false;
  const _be = document.getElementById('btnExploit'); if (_be) _be.disabled = true;
  const _bs = document.getElementById('btnStop');    if (_bs) _bs.disabled = false;
  _setPauseBtn('pause');
  setStatus('running', _doResume ? 'Resuming…' : 'Scanning…');
  const liveInd = document.getElementById('lscanLiveInd');
  if (liveInd) liveInd.style.display = 'inline';
  // showTab removed - terminal is always visible
  _scheduleStateSave();
  _startFindingsPoll(url);

  if (_scannerAbort) _scannerAbort.abort();
  _scannerAbort = new AbortController();

  const cookies = document.getElementById('scannerCookies')?.value?.trim() || '';
  const cookiesB = document.getElementById('scannerCookiesB')?.value?.trim() || '';

  try {
    const resp = await fetch('/api/aicrawl/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: url,
        cookies_str: cookies,
        cookies_b: cookiesB,   // 2nd account → real IDOR/BOLA confirmation (optional)
        vuln_types: _scanTypes,
        resume: _doResume,
        max_pages: 20000,
        max_depth: 15,
      }),
      signal: _scannerAbort.signal,
    });
    await _pumpScanStream(resp);
  } catch(e) {
    if (e.name !== 'AbortError') appendLog('error', 'Error: ' + e.message);
    stopExploit(true);
  }
}

// SSE debug counters
let _sseCount = 0, _sseVuln = 0;

// Read the scan stream (SSE) and process events — shared between start and reconnect
async function _pumpScanStream(resp) {
  const reader  = resp.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  const pump = async () => {
    const { done, value } = await reader.read();
    if (done) { stopExploit(true); return; }
    buf += decoder.decode(value, { stream: true });
    const lines = buf.split('\n');
    buf = lines.pop();
    for (const line of lines) {
      if (!line.startsWith('data: ')) continue;
      try {
        const d = JSON.parse(line.slice(6));
        _sseCount++;
        if (d.level === 'vuln') _sseVuln++;
        document.getElementById('sseTotal').textContent = _sseCount;
        document.getElementById('sseVuln').textContent = 'vuln:' + _sseVuln;
        if (d.level === 'eof') { stopExploit(true); return; }
        handleMsg(d);
        if (d.level === 'vuln' && Notification.permission === 'granted') {
          new Notification('🚨 Vuln — BugBîner AI', { body: (d.message || '').slice(0, 120) });
        }
      } catch(e) { console.warn('SSE err', line.slice(0, 80), e.message); }
    }
    await pump();
  };
  await pump();
}

// Silently attach to a scan running in the background after a page refresh — no clearing, no restart.
// The UI is restored from storage as it was, and this function only continues the live stream on top of it
// → a page refresh is fully transparent and does not affect the scan at all.
async function reconnectScan(url) {
  if (!url) return;
  running = true;
  _scanPaused = false;
  _quietScan = true;   // reconnect after refresh → don't print a snapshot/intro, just continue
  const _be = document.getElementById('btnExploit'); if (_be) _be.disabled = true;
  const _bs = document.getElementById('btnStop');    if (_bs) _bs.disabled = false;
  _setPauseBtn('pause');
  setStatus('running', 'Scanning…');
  const liveInd = document.getElementById('lscanLiveInd'); if (liveInd) liveInd.style.display = 'inline';
  _startFindingsPoll(url);
  if (_scannerAbort) _scannerAbort.abort();
  _scannerAbort = new AbortController();
  try {
    const resp = await fetch('/api/aicrawl/run', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: url, reconnect: true }), signal: _scannerAbort.signal,
    });
    await _pumpScanStream(resp);
  } catch(e) {
    if (e.name !== 'AbortError') { /* silent — don't disturb the restored UI */ }
    stopExploit(true);
  }
}

function stopExploit(auto = false) {
  running = false;
  _stopFindingsPoll();
  if (_scannerAbort) { _scannerAbort.abort(); _scannerAbort = null; }
  const btnEx = document.getElementById('btnExploit');
  const btnSt = document.getElementById('btnStop');
  if (btnEx) btnEx.disabled = false;
  if (btnSt) btnSt.disabled = true;
  const liveInd = document.getElementById('lscanLiveInd');
  if (liveInd) liveInd.style.display = 'none';
  if (_scanPaused) {
    // paused → the unified button becomes "▶ Resume" to continue
    _setPauseBtn('resume');
    setStatus('idle', 'Paused');
  } else {
    _setPauseBtn('disabled');
    setStatus('idle', 'Idle');
    if (auto) appendLog('saved', `✓ Scan complete — ${_lscanCounts.total} URLs, ${_lscanCounts.vulns} vulns`);
  }
  _scheduleStateSave();
  _refreshResumeLabel();
}

async function stopAll() {
  // the scan runs in the background → tell the server to actually stop it (aborting the stream is not enough).
  // The server now kills the crawler + aborts the AI workers immediately, so this is a real, full halt.
  const url = (document.getElementById('urlInput')?.value || '').trim();
  _scanPaused = false;   // Stop is a full halt, not a pause → button returns to idle (not "Resume")
  const bs = document.getElementById('btnStop');
  if (bs) { bs.disabled = true; bs.textContent = '■ Stopping…'; }
  try {
    await fetch('/api/aicrawl/stop', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: url }),
    });
  } catch(_) {}
  try { stopExploit(); } catch(_) {}
  if (bs) bs.textContent = '■ Stop';
}

// ─── Pause / Resume ────────────────────────────────────────────────────────────
// Pause: ask the server to stop the background scan and save progress. The scan stops itself
// and sends eof → stopExploit switches the button to "▶ Resume". Progress stays on disk.
async function pauseScan() {
  const url = (document.getElementById('urlInput')?.value || '').trim();
  _scanPaused = true;
  _quietScan = true;   // mute the pause summary and the later resume intro
  const bp = document.getElementById('btnPause'); if (bp) { bp.disabled = true; bp.textContent = '⏸ Pausing…'; }
  setStatus('running', 'Pausing…');
  try {
    await fetch('/api/aicrawl/pause', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: url }),
    });
  } catch(_) {}
  // The scan is now SUSPENDED in place on the server (all state kept in memory). There is no eof.
  // Close only the local display stream; the background scan stays frozen until Resume.
  running = false;
  if (_scannerAbort) { _scannerAbort.abort(); _scannerAbort = null; }
  const be = document.getElementById('btnExploit'); if (be) be.disabled = false;
  const bs = document.getElementById('btnStop');    if (bs) bs.disabled = true;
  const li = document.getElementById('lscanLiveInd'); if (li) li.style.display = 'none';
  _setPauseBtn('resume');
  setStatus('idle', 'Paused');
  _scheduleStateSave();
}

// Resume: ask the server to un-suspend the SAME live task and re-attach to its stream.
// This is NOT a reconnect-that-restarts and does NOT re-crawl — the crawler + queue were
// frozen in memory and simply continue. Only if the program was closed (no live task) do
// we fall back to a disk-resume run that skips everything already crawled/scanned.
async function resumeScan() {
  const url = (document.getElementById('urlInput')?.value || '').trim();
  if (!url) return;
  _scanPaused = false;
  _quietScan = true;   // continue silently — no intro/snapshot, just keep going
  const bp = document.getElementById('btnPause'); if (bp) { bp.disabled = true; bp.textContent = '▶ Resuming…'; }
  setStatus('running', 'Resuming…');
  let mode = 'disk';
  try {
    const r = await fetch('/api/aicrawl/resume', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: url }),
    }).then(r => r.json());
    mode = r.resumed || 'disk';
  } catch(_) {}
  _setPauseBtn('pause');
  if (mode === 'live') {
    reconnectScan(url);   // same live task continues — re-attach to its event stream
  } else {
    startExploit();       // program was closed → disk-resume (crawler skips already-seen URLs)
  }
}

// The start button always stays "Start Scan" (resume happens automatically on click if progress exists)
function _refreshResumeLabel() {
  const btn = document.getElementById('btnExploit');
  if (btn) btn.textContent = '🔍 Start Scan';
}

// ─── Findings ─────────────────────────────────────────────────────────────────
function _updateFindingsDisplay() {
  const bar = document.getElementById('findingsBar');
  if (!bar) return;
  if (!_findings.length) { bar.style.display = 'none'; return; }
  bar.style.display = 'flex';
  bar.classList.remove('fb-flash');
  void bar.offsetWidth;
  bar.classList.add('fb-flash');
  const sevs = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of _findings) {
    const s = (f.severity || 'info').toLowerCase();
    if (sevs[s] !== undefined) sevs[s]++; else sevs.info++;
  }
  const el = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
  el('fbTotal', _findings.length);
  el('fbCritical', sevs.critical); el('fbHigh', sevs.high);
  el('fbMedium', sevs.medium); el('fbLow', sevs.low); el('fbInfo', sevs.info);
}

function _addFinding(f) {
  const _k = (f.vuln_type || '') + '|' + (f.url || '');
  if (_findings.some(x => ((x.vuln_type || '') + '|' + (x.url || '')) === _k)) return false;
  f.time = new Date().toLocaleTimeString();
  _findings.push(f);
  const idx = _findings.length;

  const vb = document.getElementById('vulnBadge');
  if (vb) { vb.textContent = idx; vb.classList.add('vuln-badge-pulse'); setTimeout(() => vb.classList.remove('vuln-badge-pulse'), 600); }

  _updateFindingsDisplay();

  const ov = document.getElementById('vulnOverlay');
  if (ov && ov.style.display !== 'none') _renderVulnPanel();

  return true;
}

function _aiAnalysisHtml(a) {
  if (!a) return '';
  const isReal = a.real;
  const conf   = (a.confidence != null) ? a.confidence : '?';
  const expl   = a.exploitability || '';
  const explColor = {none:'#888',low:'#00c8ff',medium:'#ffaa00',high:'#ff6600',critical:'#ff2222'}[expl.toLowerCase()] || '#888';
  const badgeColor = isReal ? '#ff3333' : '#00ff88';
  const badgeLabel = isReal ? '⚠ REAL VULN' : '✓ FALSE POSITIVE';
  return '<details class="vuln-req-details" style="margin-top:5px" open>'
    + '<summary class="vuln-req-summary" style="color:' + badgeColor + ';font-size:.7rem;font-weight:700">🤖 AI Analysis — ' + badgeLabel + ' (' + conf + '% confidence)</summary>'
    + '<div style="padding:6px 8px;font-size:.68rem;color:var(--text2);line-height:1.55;display:flex;flex-direction:column;gap:3px">'
    + (a.reason ? '<div><span style="color:var(--text1);font-weight:600">Verdict:</span> ' + escHtml(a.reason) + '</div>' : '')
    + (expl ? '<div><span style="color:var(--text1);font-weight:600">Exploitability:</span> <span style="color:' + explColor + ';font-weight:600">' + escHtml(expl.toUpperCase()) + '</span></div>' : '')
    + (a.attack_scenario ? '<div><span style="color:var(--text1);font-weight:600">Attack Scenario:</span> ' + escHtml(a.attack_scenario) + '</div>' : '')
    + (a.impact ? '<div><span style="color:var(--text1);font-weight:600">Impact:</span> ' + escHtml(a.impact) + '</div>' : '')
    + (a.remediation ? '<div><span style="color:#00ff88;font-weight:600">Fix:</span> ' + escHtml(a.remediation) + '</div>' : '')
    + '</div></details>';
}

function _exploitResultHtml(data) {
  const vuln = data && data.vulnerable;
  const color = vuln ? '#ff3333' : '#00ff88';
  const label = vuln ? '⚠ VULNERABLE' : '✓ SAFE';
  const cls = vuln ? 'ai-fp' : 'ai-real';
  const svg = vuln
    ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="' + color + '" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>'
    : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="' + color + '" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>';
  return '<div class="exploit-result" style="margin-top:4px;padding:5px 8px;border-radius:4px;font-size:.68rem;background:#0a0e1a;border:1px solid ' + color + '40">'
    + '<span style="display:flex;align-items:center;gap:5px">'
    + svg
    + '<span class="ai-badge ' + cls + '">' + label + '</span>'
    + '<span style="color:var(--text2)">' + escHtml(data.reason || '') + '</span>'
    + '</span>'
    + (data.evidence ? '<pre style="margin:4px 0 0;font-size:.65rem;color:var(--text2);white-space:pre-wrap;word-break:break-all">' + escHtml(data.evidence) + '</pre>' : '')
    + (data.impact ? '<div style="margin-top:2px;color:var(--orange);font-size:.65rem">Impact: ' + escHtml(data.impact) + '</div>' : '')
    + '</div>';
}

async function _analyzeFinding(idx, btnEl) {
  const f = _findings[idx];
  if (!f || _analyzingSet.has(idx)) return;
  _analyzingSet.add(idx);
  if (btnEl) { btnEl.textContent = '⏳ Analyzing…'; btnEl.disabled = true; }
  try {
    const resp = await fetch('/api/aicrawl/analyze-finding', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({finding: f}),
    });
    const data = await resp.json();
    if (data.ai_analysis) f.ai_analysis = data.ai_analysis;
  } catch(e) { /* swallow — state restored in finally */ }
  finally {
    _analyzingSet.delete(idx);
    const _ov = document.getElementById('vulnOverlay');
    if (_ov && _ov.style.display !== 'none') _renderVulnPanel();
    else if (btnEl && btnEl.isConnected) { btnEl.textContent = '🤖 Analyze with AI'; btnEl.disabled = false; }
  }
}

async function _exploitFinding(idx, btnEl) {
  const f = _findings[idx];
  if (!f || _exploitingSet.has(idx)) return;
  _exploitingSet.add(idx);
  if (btnEl) { btnEl.textContent = '⏳ Testing…'; btnEl.disabled = true; }
  try {
    const resp = await fetch('/api/aicrawl/exploit-finding', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({finding: f}),
    });
    const data = await resp.json();
    f.exploit_result = data;
  } catch(e) { /* swallow — state restored in finally */ }
  finally {
    _exploitingSet.delete(idx);
    const _ov = document.getElementById('vulnOverlay');
    if (_ov && _ov.style.display !== 'none') _renderVulnPanel();
    else if (btnEl && btnEl.isConnected) { btnEl.textContent = '⚡ Exploit & Test'; btnEl.disabled = false; }
  }
}

// ─── Projects ─────────────────────────────────────────────────────────────────
async function loadProjects() {
  const list = document.getElementById('projList');
  const cnt  = document.getElementById('projCount');
  if (!list) return;
  try {
    const projects = await fetch('/api/projects').then(r => r.json());
    if (cnt) cnt.textContent = projects.length + ' projects';
    if (!projects.length) { list.innerHTML = '<div class="proj-empty">No projects yet.</div>'; return; }
    list.innerHTML = projects.map(p =>
      `<div class="proj-item" onclick="loadProjFiles('${escHtml(p.name)}')">
        <span class="proj-icon">📁</span>
        <span class="proj-name">${escHtml(p.name)}</span>
        <span class="proj-meta">${p.file_count} files</span>
      </div>`
    ).join('');
  } catch(_) {
    if (list) list.innerHTML = '<div class="proj-empty">Error loading.</div>';
  }
}

async function loadProjFiles(name) {
  const fb = document.getElementById('projFileBrowser');
  if (fb) fb.style.display = 'block';
  const fileList = document.getElementById('projFileList');
  if (!fileList) return;
  try {
    const data = await fetch(`/api/projects/${encodeURIComponent(name)}`).then(r => r.json());
    fileList.innerHTML = _renderFileTree(data.files || []);
  } catch(_) {}
}

function _renderFileTree(files, depth = 0) {
  return files.map(f => {
    const pad = depth * 12;
    if (f.is_dir) {
      return `<div class="pf-dir" style="padding-left:${pad}px">📁 ${escHtml(f.name)}${f.children ? _renderFileTree(f.children, depth + 1) : ''}</div>`;
    }
    return `<div class="pf-file" style="padding-left:${pad}px">📄 ${escHtml(f.name)}</div>`;
  }).join('');
}

function closeProjBrowser() { const fb = document.getElementById('projFileBrowser'); if (fb) fb.style.display = 'none'; }
function projTaskAll() { const ci = document.getElementById('chatInput'); if (ci) { ci.value = 'Analyze findings and suggest next exploitation steps.'; sendChat(); } }
function projOpenFolder() { openFileBrowser(); }

// ─── File Browser ─────────────────────────────────────────────────────────────
function openFileBrowser() { const m = document.getElementById('fbOverlay'); if (m) { m.style.display = 'flex'; fbLoadPath(''); } }
function closeFileBrowser() { const m = document.getElementById('fbOverlay'); if (m) m.style.display = 'none'; }

async function fbLoadPath(path) {
  const list  = document.getElementById('fbList');
  const drivs = document.getElementById('fbDrives');
  const pi    = document.getElementById('fbPathInput');
  const upBtn = document.getElementById('fbUpBtn');
  if (!list) return;
  list.innerHTML = '<div style="padding:8px;color:var(--text3)">Loading…</div>';
  try {
    const data = await fetch('/api/browse?path=' + encodeURIComponent(path)).then(r => r.json());
    if (pi) pi.value = data.path || '';
    if (upBtn) upBtn.disabled = !data.parent;
    if (drivs && data.drives) {
      drivs.style.display = 'flex';
      drivs.innerHTML = data.drives.map(d => `<button class="fb-drive-btn" onclick="fbLoadPath('${d}')">${d}</button>`).join('');
    } else if (drivs) { drivs.style.display = 'none'; }
    list.innerHTML = (data.items || []).map(item => {
      const icon = item.is_dir ? '📁' : '📄';
      const safe = item.path.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
      const click = item.is_dir ? `fbLoadPath('${safe}')` : `fbSelectFile('${safe}')`;
      return `<div class="fb-item" onclick="${click}">
        <span>${icon}</span><span>${escHtml(item.name)}</span>
        ${!item.is_dir && item.size ? `<span style="margin-left:auto;color:var(--text3);font-size:.68rem">${(item.size/1024).toFixed(1)}k</span>` : ''}
      </div>`;
    }).join('') || '<div style="padding:8px;color:var(--text3)">Empty</div>';
  } catch(e) { list.innerHTML = `<div style="padding:8px;color:var(--red)">${escHtml(e.message)}</div>`; }
}

function fbNavigateUp() {
  const pi = document.getElementById('fbPathInput');
  if (pi?.value) {
    const parts = pi.value.replace(/\\/g, '/').split('/').filter(Boolean);
    parts.pop();
    fbLoadPath(parts.length ? parts.join('\\') + '\\' : '');
  } else { fbLoadPath(''); }
}
function fbGoToPath(path) { if (path) fbLoadPath(path); }
function fbSelectFile(path) {
  _fbSelectedPath = path;
  const sp = document.getElementById('fbSelectedPath'); if (sp) sp.textContent = path;
  const btn = document.getElementById('fbSelectBtn'); if (btn) btn.disabled = false;
}
function fbSelectFolder() { if (_fbSelectedPath) { appendLog('info', 'Selected: ' + _fbSelectedPath); closeFileBrowser(); } }

// ─── Chat ─────────────────────────────────────────────────────────────────────
function newChat() {
  if (_chatStreaming) return;
  const msgs = document.getElementById('chatMsgs');
  if (!msgs) return;
  _chatHistory = [];
  _chatImgs = [];
  msgs.innerHTML = '';
  const welcome = document.createElement('div');
  welcome.className = 'chat-row-ai';
  const _wIcon = document.createElement('div');
  _wIcon.className = 'chat-ai-icon'; _wIcon.textContent = '✦';
  const _wContent = document.createElement('div');
  _wContent.className = 'chat-ai-content';
  _wContent.innerHTML = '<div class="chat-bubble ai">مرحباً! أنا مساعدك للأمن السيبراني. أرسل سؤالاً أو أرفق صورة 🔍</div>';
  welcome.appendChild(_wIcon);
  welcome.appendChild(_wContent);
  msgs.appendChild(welcome);
}

function chatKeydown(e) { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); } }
function setMode(mode) {
  _chatMode = mode;
  document.getElementById('modePillAsk')?.classList.toggle('active-ask',   mode === 'ask');
  document.getElementById('modePillAgent')?.classList.toggle('active-agent', mode === 'agent');
}

function onImageSelected(input) {
  for (const file of input.files) {
    const reader = new FileReader();
    reader.onload = ev => {
      _chatImgs.push({ base64: ev.target.result.split(',')[1], mediaType: file.type, name: file.name });
      _updateImgPreview();
    };
    reader.readAsDataURL(file);
  }
  input.value = '';
}

function _updateImgPreview() {
  const prev = document.getElementById('chatImgPreview');
  if (!prev) return;
  if (_chatImgs.length === 0) {
    prev.classList.remove('visible');
    prev.innerHTML = '';
    return;
  }
  prev.classList.add('visible');
  prev.innerHTML = _chatImgs.map((img, i) =>
    `<div class="chat-img-item">
      <img class="chat-img-thumb" src="data:${img.mediaType};base64,${img.base64}" title="${escHtml(img.name)}">
      <button class="chat-img-remove" onclick="_removeImg(${i})">✕</button>
    </div>`
  ).join('');
}
function _removeImg(i) { _chatImgs.splice(i, 1); _updateImgPreview(); }

// Ollama functions
async function testOllamaConnection() {
  const base = document.getElementById('ollamaBase')?.value || 'http://localhost:11434';
  const statusEl = document.getElementById('ollamaStatus');
  const model = document.getElementById('ollamaModel')?.value || 'qwen2.5:7b';
  
  if (statusEl) {
    statusEl.textContent = 'Testing...';
    statusEl.style.color = '#ffaa00';
  }
  
  try {
    const resp = await fetch(`${base}/api/tags`, { signal: AbortSignal.timeout(5000) });
    if (resp.ok) {
      const data = await resp.json();
      const models = data.models || [];
      const hasModel = models.some(m => m.name === model || m.name === model.replace(':8b', ''));
      
      if (hasModel) {
  if (statusEl) {
    statusEl.textContent = 'Connected';
    statusEl.style.color = '#00c878';
    return;
  }
        appendLog('info', `Ollama connected — model ${model} available`);
        _scheduleStateSave();
      } else {
        if (statusEl) {
          statusEl.textContent = 'Model not found';
          statusEl.style.color = '#ff4444';
        }
        appendLog('warn', `Ollama connected but model ${model} not found`);
      }
    } else {
      throw new Error('Connection failed');
    }
  } catch (e) {
    if (statusEl) {
      statusEl.textContent = 'Disconnected';
      statusEl.style.color = '#ff4444';
    }
    appendLog('error', `Ollama connection test failed: ${e.message}`);
  }
}

function _updateOllamaStatus() {
  const statusEl = document.getElementById('ollamaStatus');
  if (!statusEl) return;
  
  const base = document.getElementById('ollamaBase')?.value || 'http://localhost:11434';
  const model = document.getElementById('ollamaModel')?.value || 'qwen2.5:7b';
  
  // Check if Ollama settings exist in localStorage
  const appState = localStorage.getItem(_APP_STATE_KEY);
  if (appState) {
    try {
      const state = JSON.parse(appState);
      if (state.ollama_enabled) {
        statusEl.textContent = 'Ready';
        statusEl.style.color = '#00c878';
        return;
      }
    } catch (_) {}
  }
  
  statusEl.textContent = 'Disconnected';
  statusEl.style.color = '#ff4444';
}

function _checkProviderAvailability() {
  const ollamaPanel = document.getElementById('ollamaPanel');
  
  let provider = 'ollama';
  let model = 'qwen2.5:7b';
  
  // Check if Ollama is available
  const ollamaAvailable = ollamaPanel && ['Connected','Ready'].includes(document.getElementById('ollamaStatus')?.textContent);
  
  if (ollamaAvailable) {
    // Use Ollama (local operation)
    provider = 'ollama';
    model = document.getElementById('ollamaModel')?.value || 'qwen2.5:7b';
  } else {
    // Fallback to default model if Ollama not available
    provider = 'ollama';
    model = 'qwen2.5:7b';
  }
  
  return { provider, model };
}

async function sendChat() {
  const input = document.getElementById('chatInput');
  const msgs  = document.getElementById('chatMsgs');
  if (!input || !msgs || _chatStreaming) return;
  _openAiPanel();
  const text = input.value.trim();
  if (!text && !_chatImgs.length) return;
  input.value = '';
  const imgs = [..._chatImgs];
  _chatImgs = [];
  _updateImgPreview();

  // Show user message — image thumbnail + text inside one bubble
  const userDiv = document.createElement('div');
  userDiv.className = 'chat-row-user';
  let userInner = '';
  if (imgs.length) {
    userInner += `<div class="chat-user-imgs">${imgs.map(img =>
      `<img src="data:${img.mediaType};base64,${img.base64}" class="chat-user-img-thumb" title="${escHtml(img.name||'')}">` 
    ).join('')}</div>`;
  }
  if (text) userInner += `<div class="chat-user-text">${escHtml(text)}</div>`;
  userDiv.innerHTML = `<div class="chat-bubble user msg-bubble">${userInner}</div>`;
  msgs.appendChild(userDiv);

  // AI response row
  const aiDiv = document.createElement('div');
  aiDiv.className = 'chat-row-ai';
  const _aiIcon = document.createElement('div');
  _aiIcon.className = 'chat-ai-icon'; _aiIcon.textContent = '✦';
  const _aiContent = document.createElement('div');
  _aiContent.className = 'chat-ai-content';
  const bubble = document.createElement('div');
  bubble.className = 'chat-bubble ai';
  _aiContent.appendChild(bubble);
  aiDiv.appendChild(_aiIcon);
  aiDiv.appendChild(_aiContent);
  msgs.appendChild(aiDiv);
  msgs.scrollTop = msgs.scrollHeight;

  _chatStreaming = true;
  const stop = document.getElementById('chatStop');
  if (stop) stop.classList.add('active');
  _chatStopCtrl = new AbortController();
  _chatHistory.push({ role: 'user', content: text });

  // Build FULL program context — all sections
  let _ctx = '';
  const _tgt = document.getElementById('urlInput')?.value?.trim() || '';

  // === Section 1: Scan state ===
  _ctx += `=== BugBîner AI Program State ===\n`;
  _ctx += `Target URL: ${_tgt || '(not set)'}\n`;
  _ctx += `Scan running: ${running ? 'YES' : 'NO'}\n`;
  _ctx += `URLs in site map: ${_smTotal}\n`;
  _ctx += `Vulnerabilities found: ${_findings.length}\n`;
  _ctx += `Events in terminal: ${eventCount}\n\n`;

  // === Section 2: Terminal output (last 80 lines) ===
  const _termEl = document.getElementById('terminal');
  if (_termEl && _termEl.children.length > 0) {
    const termLines = Array.from(_termEl.children).slice(-80).map(row => {
      const tag = row.querySelector('.tag')?.textContent || '';
      const msg = row.querySelector('.msg')?.textContent || '';
      return `[${tag}] ${msg}`;
    }).join('\n');
    _ctx += `=== Terminal Output (last ${Math.min(80, _termEl.children.length)} lines) ===\n`;
    _ctx += termLines + '\n\n';
  }

  // === Section 3: Vulnerabilities ===
  if (_findings.length) {
    _ctx += `=== Discovered Vulnerabilities ===\n`;
    _findings.forEach((f, i) => {
      _ctx += `[${i+1}] [${(f.severity||'info').toUpperCase()}] ${f.vuln_type||''}\n`;
      _ctx += `  URL: ${f.url||''}\n`;
      if (f.detail)   _ctx += `  Detail: ${f.detail}\n`;
      if (f.payload)  _ctx += `  Payload: ${f.payload}\n`;
      if (f.evidence) _ctx += `  Evidence: ${f.evidence.slice(0,300)}\n`;
      _ctx += '\n';
    });
  }

  // === Section 4: Site map summary ===
  if (_smData.length) {
    const hosts = [...new Set(_smData.map(e => e.host))];
    _ctx += `=== Site Map Summary ===\n`;
    _ctx += `Hosts: ${hosts.join(', ')}\n`;
    const interesting = _smData.filter(e => e.status === 200 && e.hasParams).slice(0, 20);
    if (interesting.length) {
      _ctx += `Interesting URLs (200 + params):\n`;
      interesting.forEach(e => { _ctx += `  ${e.method} ${e.url}\n`; });
    }
    _ctx += '\n';
  }

  // Determine provider and model based on availability
  const { provider, model } = _checkProviderAvailability();

  // ── AGENT MODE: silent execution, show results only ──────────────────────
  if (_chatMode === 'agent') {
    bubble.innerHTML = '<span style="color:#00c878;font-size:.8rem">⚡ الأجنت يعمل…</span>';
    msgs.scrollTop = msgs.scrollHeight;

    // If images attached, prepend instruction so AI knows to extract URL from image
    const agentMsg = imgs.length > 0
      ? `[IMAGE ATTACHED: analyze the image, extract any URL found, then immediately write a Python verification script for the vulnerability shown]\n\n${text || 'تحقق من الثغرة في الصورة'}`
      : text;

    try {
      const resp = await fetch('/api/chat/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: agentMsg, images: imgs, mode: 'agent', model, provider, context: _ctx, conversation: _chatHistory.slice(-10) }),
        signal: _chatStopCtrl.signal,
      });
      const reader = resp.body.getReader();
      const dec = new TextDecoder();
      let buf = '', full = '';
      // direct streaming of replies — to show the model's typing progress
      bubble.innerHTML = '<span style="color:#8ba4ff;font-size:.78rem">⚡ الأجنت يحلل…</span>';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n'); buf = lines.pop();
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const data = line.slice(6);
          if (data === '[DONE]') break;
          try {
            const d = JSON.parse(data);
            if (d.delta) {
              full += d.delta;
              // render the streamed text directly with immediate security coloring
              bubble.innerHTML = _colorSecurity(_renderMd(full)) + '<span class="chat-cursor">▌</span>';
              msgs.scrollTop = msgs.scrollHeight;
            }
            if (d.error) { bubble.innerHTML = `<span style="color:#ff4444">❌ ${escHtml(d.error)}</span>`; break; }
          } catch(_) {}
        }
      }
      if (full) {
        _chatHistory.push({ role: 'assistant', content: full });
        // the server-side agent runs the scripts itself (run_python) and streams the results,
        // so we render the streamed content as-is (steps + final verdict) without client-side execution.
        bubble.innerHTML = _colorSecurity(_renderMd(full));
        msgs.scrollTop = msgs.scrollHeight;
      }
    } catch(e) {
      bubble.innerHTML = e.name === 'AbortError'
        ? '<span style="color:#888">⏹ Stopped.</span>'
        : `<span style="color:#ff4444">❌ ${escHtml(e.message)}</span>`;
    } finally {
      _chatStreaming = false;
      _chatStopCtrl = null;
      if (stop) stop.classList.remove('active');
    }
    return;
  }

  // ── ASK MODE: normal streaming ────────────────────────────────────────────
  bubble.textContent = '⏳…';
  try {
    const resp = await fetch('/api/chat/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text, images: imgs, mode: 'ask', model, provider, context: _ctx, conversation: _chatHistory.slice(-10) }),
      signal: _chatStopCtrl.signal,
    });
    const reader = resp.body.getReader();
    const dec = new TextDecoder();
    let buf = '', full = '';
    bubble.textContent = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      const lines = buf.split('\n'); buf = lines.pop();
      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const data = line.slice(6);
        if (data === '[DONE]') break;
        try {
          const d = JSON.parse(data);
          if (d.delta) { full += d.delta; bubble.innerHTML = _colorSecurity(_renderMd(full)); msgs.scrollTop = msgs.scrollHeight; }
          if (d.error) { bubble.textContent = '❌ ' + d.error; break; }
        } catch(_) {}
      }
    }
    if (full) {
      _chatHistory.push({ role: 'assistant', content: full });
      _scheduleStateSave();
    }
  } catch(e) {
    bubble.textContent = e.name === 'AbortError' ? '⏹ Stopped.' : '❌ ' + e.message;
  } finally {
    _chatStreaming = false;
    _chatStopCtrl = null;
    if (stop) stop.classList.remove('active');
  }
}

function stopChatRun() { if (_chatStopCtrl) { _chatStopCtrl.abort(); _chatStopCtrl = null; } }

function _openAiPanel() { /* chat is always visible */ }


// Helper: append to main terminal with exec styling
function _termExec(level, msg) {
  const term = document.getElementById('terminal');
  if (!term) return;
  const row = document.createElement('div');
  row.className = `log ${level}`;
  const ts = new Date().toTimeString().slice(0, 8);
  const tagText = level === 'exec_start' ? 'RUN' : level === 'exec_out' ? 'OUT' : level === 'exec_done' ? 'DONE' : 'ERR';
  row.innerHTML = `<span class="ts">${ts}</span><span class="tag">${tagText}</span><span class="msg">${escHtml(String(msg))}</span>`;
  term.appendChild(row);
  while (term.children.length > 600) term.removeChild(term.firstChild);
  term.scrollTop = term.scrollHeight;
}

// ─── Agent: code block store (avoids HTML-attribute quoting issues) ──────────
const _codeBlocks = {};
let _cbId = 0;

async function _execBlock(btnEl, id, lang) {
  const code = _codeBlocks[id];
  if (!code) { alert('Code not found'); return; }
  btnEl.disabled = true;
  btnEl.textContent = '⏳ Running…';

  let outPre = btnEl.closest('.chat-code-block')?.querySelector('.exec-out');
  if (!outPre) {
    outPre = document.createElement('pre');
    outPre.className = 'exec-out';
    btnEl.closest('.chat-code-block').appendChild(outPre);
  }
  outPre.textContent = '';
  outPre.style.display = 'block';

  try {
    const resp = await fetch('/api/exec', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, lang }),
    });
    const reader = resp.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      const lines = buf.split('\n'); buf = lines.pop();
      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const data = line.slice(6);
        if (data === '[DONE]') break;
        try {
          const d = JSON.parse(data);
          if (d.message !== undefined) {
            outPre.textContent += d.message + '\n';
            outPre.scrollTop = outPre.scrollHeight;
            const msgs = document.getElementById('chatMsgs');
            if (msgs) msgs.scrollTop = msgs.scrollHeight;
          }
        } catch(_) {}
      }
    }
    btnEl.textContent = '✅ Done';
  } catch(e) {
    outPre.textContent += '\n❌ ' + e.message;
    btnEl.textContent = '▶ Run';
    btnEl.disabled = false;
  }
}

function _inlineFmt(s) {
  return s
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>');
}

// Colorize important security keywords
function _colorSecurity(html) {
  return html
    .replace(/\b(VULNERABLE|مصاب|EXPLOITABLE|PWNED|COMPROMISED)\b/gi,
      '<span style="color:#ff3355;font-weight:800;background:rgba(255,50,80,.12);padding:0 3px;border-radius:3px">$1</span>')
    .replace(/\b(NOT VULNERABLE|SAFE|غير مصاب|PROTECTED|SECURED)\b/gi,
      '<span style="color:#00e87a;font-weight:700;background:rgba(0,232,122,.1);padding:0 3px;border-radius:3px">$1</span>')
    .replace(/\b(CRITICAL)\b/gi,
      '<span style="color:#ff2244;font-weight:800;text-transform:uppercase">$1</span>')
    .replace(/\b(HIGH)\b/g,
      '<span style="color:#ff6600;font-weight:700">$1</span>')
    .replace(/\b(MEDIUM)\b/g,
      '<span style="color:#ffaa00;font-weight:700">$1</span>')
    .replace(/\b(LOW|INFO)\b/g,
      '<span style="color:#4488ff;font-weight:600">$1</span>')
    .replace(/\b(XSS|SQLi|SQL Injection|SSRF|LFI|RCE|IDOR|SSTI|XXE|CSRF|CMDi|Command Injection|Path Traversal)\b/gi,
      '<code style="color:#c084fc;background:#1e1030;padding:1px 5px;border-radius:3px;font-weight:700">$1</code>')
    .replace(/\b(FOUND|LEAKED|EXPOSED|BYPASS|VULNERABLE)\b/gi,
      s => s.includes('NOT') ? s : '<span style="color:#ff8800;font-weight:700">' + s + '</span>')
    .replace(/=== VERDICT: (VULNERABLE) ===/gi,
      '<div style="background:rgba(255,40,60,.18);border:1px solid #ff3355;border-radius:6px;padding:6px 12px;margin:4px 0;color:#ff3355;font-weight:800;font-size:.9rem">🚨 === VERDICT: VULNERABLE ===</div>')
    .replace(/=== VERDICT: (SAFE) ===/gi,
      '<div style="background:rgba(0,232,122,.12);border:1px solid #00e87a;border-radius:6px;padding:6px 12px;margin:4px 0;color:#00e87a;font-weight:800;font-size:.9rem">✅ === VERDICT: SAFE ===</div>')
    .replace(/=== VERDICT: (INCONCLUSIVE|NEEDS REVIEW) ===/gi,
      '<div style="background:rgba(255,170,0,.1);border:1px solid #ffaa00;border-radius:6px;padding:6px 12px;margin:4px 0;color:#ffaa00;font-weight:800;font-size:.9rem">⚠️ === VERDICT: $1 ===</div>')
    .replace(/\[FOUND\]/g, '<span style="color:#ff8800;font-weight:700">[FOUND]</span>')
    .replace(/\[SAFE\]/g,  '<span style="color:#00e87a;font-weight:700">[SAFE]</span>')
    .replace(/\[INFO\]/g,  '<span style="color:#8ba4ff">[INFO]</span>')
    .replace(/\[PHASE\]/g, '<span style="color:#a78bfa">[PHASE]</span>')
    .replace(/\[ERR\]|\[ERROR\]/gi, '<span style="color:#ff4444;font-weight:700">$&</span>');
}

function _renderMd(text) {
  const parts = [];
  let lastIdx = 0;
  const codeRe = /```(\w*)\n?([\s\S]*?)```/g;
  let m;
  while ((m = codeRe.exec(text)) !== null) {
    if (m.index > lastIdx) parts.push({ type: 'text', content: text.slice(lastIdx, m.index) });
    parts.push({ type: 'code', lang: m[1] || '', code: m[2].trim() });
    lastIdx = codeRe.lastIndex;
  }
  if (lastIdx < text.length) parts.push({ type: 'text', content: text.slice(lastIdx) });

  return parts.map(p => {
    if (p.type === 'code') {
      const id = ++_cbId;
      _codeBlocks[id] = p.code;
      const langLabel = p.lang || 'text';
      const runnable = /^(python|powershell|bash|batch)$/i.test(p.lang);
      const displayCode = p.code.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      return `<div class="chat-code-block">` +
        `<div class="chat-code-actions">` +
          `<span class="chat-code-lang">${escHtml(langLabel)}</span>` +
          (runnable ? `<button class="chat-code-btn run-btn" onclick="_execBlock(this,${id},'${langLabel.toLowerCase()}')">&#x25B6; Run</button>` : '') +
        `</div>` +
        `<pre><code>${displayCode}</code></pre>` +
        `</div>`;
    }
    const lines = p.content.split('\n');
    let inUl = false, inOl = false;
    const out = [];
    for (const line of lines) {
      const e = line.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      if (/^### /.test(line)) {
        if (inUl) { out.push('</ul>'); inUl = false; } if (inOl) { out.push('</ol>'); inOl = false; }
        out.push(`<h3 class="md-h3">${_inlineFmt(e.replace(/^### /,''))}</h3>`);
      } else if (/^## /.test(line)) {
        if (inUl) { out.push('</ul>'); inUl = false; } if (inOl) { out.push('</ol>'); inOl = false; }
        out.push(`<h2 class="md-h2">${_inlineFmt(e.replace(/^## /,''))}</h2>`);
      } else if (/^# /.test(line)) {
        if (inUl) { out.push('</ul>'); inUl = false; } if (inOl) { out.push('</ol>'); inOl = false; }
        out.push(`<h1 class="md-h1">${_inlineFmt(e.replace(/^# /,''))}</h1>`);
      } else if (/^[-*] /.test(line)) {
        if (inOl) { out.push('</ol>'); inOl = false; }
        if (!inUl) { out.push('<ul class="md-ul">'); inUl = true; }
        out.push(`<li>${_inlineFmt(e.replace(/^[-*] /,''))}</li>`);
      } else if (/^\d+\. /.test(line)) {
        if (inUl) { out.push('</ul>'); inUl = false; }
        if (!inOl) { out.push('<ol class="md-ol">'); inOl = true; }
        out.push(`<li>${_inlineFmt(e.replace(/^\d+\. /,''))}</li>`);
      } else if (line.trim() === '') {
        if (inUl) { out.push('</ul>'); inUl = false; } if (inOl) { out.push('</ol>'); inOl = false; }
        out.push('<br>');
      } else {
        if (inUl) { out.push('</ul>'); inUl = false; } if (inOl) { out.push('</ol>'); inOl = false; }
        out.push(_inlineFmt(e) + '<br>');
      }
    }
    if (inUl) out.push('</ul>');
    if (inOl) out.push('</ol>');
    return out.join('');
  }).join('');
}
// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  _updateOllamaStatus();
  setInterval(_updateOllamaStatus, 10000);
  const restored = _restoreAppState();
  if (!restored) _lscanRestore();
  loadProjects();
  // Resume button: updates based on the saved progress for the current target
  _refreshResumeLabel();
  let _resumeLblT = null;
  document.getElementById('urlInput')?.addEventListener('input', () => {
    clearTimeout(_resumeLblT); _resumeLblT = setTimeout(_refreshResumeLabel, 400);
  });
  // ── Auto-reconnect to a scan running in the background (after refreshing/opening the page) ──
  (async () => {
    const url = (document.getElementById('urlInput')?.value || '').trim();
    let st = null;
    if (url) {
      try { st = await fetch('/api/aicrawl/state?target=' + encodeURIComponent(url)).then(r => r.json()); } catch(_) {}
    }
    const liveRunning = !!(st && st.exists && st.live && st.status === 'running');
    const pausedResumable = !!(st && st.exists && st.status !== 'running' && st.resumable && st.tested_count > 0);
    // after a refresh the old stream is broken; the running flag restored from storage is "stale" — ignore it
    // and rely on the server state: if it's alive we reconnect, if it's stopped we show Resume.
    if (liveRunning) {
      running = false;              // clear the stale flag so reconnect can proceed
      reconnectScan(url);
    } else {
      running = false;
      const be = document.getElementById('btnExploit'); if (be) be.disabled = false;
      const bs = document.getElementById('btnStop');    if (bs) bs.disabled = true;
      const li = document.getElementById('lscanLiveInd'); if (li) li.style.display = 'none';
      if (pausedResumable) {
        _scanPaused = true;
        _setPauseBtn('resume');     // paused scan → "▶ Resume" button ready
        setStatus('idle', 'Paused');
      } else {
        _scanPaused = false;
        _setPauseBtn('disabled');
        setStatus('idle', 'Idle');
      }
      _refreshResumeLabel();
    }
  })();
  if (!(_chatHistory && _chatHistory.length)) newChat();
  if (Notification.permission === 'default') Notification.requestPermission();
  // the scan runs in the background on the server — refresh/close is safe and won't stop it (auto-reconnect)
  window.addEventListener('beforeunload', _saveAppState);
  window.addEventListener('unload', _saveAppState);
  setInterval(_saveAppState, 5000);
});

