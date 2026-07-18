/**
 * crawler.js v3 — Puppeteer-based crawler with Cloudflare bypass
 *
 * Strategy: Use real Chrome (puppeteer) for all page navigation so
 * Cloudflare challenges are solved automatically. Intercept every
 * network request the browser makes to discover API endpoints.
 */
'use strict';

const { URL }  = require('url');
const readline = require('readline');
const path     = require('path');

// ── Pause control (kept in memory so a pause never loses crawl state) ──────────
// The parent process sends the config as the FIRST stdin line, then keeps stdin
// open to send "PAUSE"/"RESUME" commands. On PAUSE the workers stop pulling new
// pages but all in-memory state (visited sets + queue) is preserved, so RESUME
// continues from exactly where it stopped — no re-crawl from zero.
const _ctrl = { paused: false, resolvers: [] };
function _waitIfPaused() {
  if (!_ctrl.paused) return Promise.resolve();
  return new Promise(res => _ctrl.resolvers.push(res));
}
function _setPaused(p) {
  _ctrl.paused = p;
  if (!p && _ctrl.resolvers.length) {
    const rs = _ctrl.resolvers; _ctrl.resolvers = [];
    rs.forEach(r => r());
  }
}

let _started = false;
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on('line', line => {
  const s = line.trim();
  if (!_started) {
    _started = true;
    let cfg;
    try { cfg = JSON.parse(s); }
    catch (e) { emit({ type: 'error', message: 'Bad config JSON: ' + e.message }); process.exit(1); }
    // stdin is kept open for commands → exit explicitly once the crawl finishes
    run(cfg).then(() => process.exit(0))
            .catch(e => { emit({ type: 'error', message: String(e) }); process.exit(1); });
  } else if (s === 'PAUSE') {
    _setPaused(true);
  } else if (s === 'RESUME') {
    _setPaused(false);
  }
});
rl.on('close', () => { /* parent closed stdin (killing) — run() exits on its own */ });

function emit(obj) { process.stdout.write(JSON.stringify(obj) + '\n'); }

const SKIP_EXTS = new Set([
  'jpg','jpeg','png','gif','svg','ico','webp','bmp','tiff','avif',
  'css','woff','woff2','ttf','eot','otf',
  'pdf','zip','tar','gz','rar','7z','exe','msi','dmg',
  'mp4','mp3','avi','mov','wmv','flv','webm','wav','ogg',
  'doc','docx','xls','xlsx','ppt','pptx',
]);
const RESOURCE_SKIP = new Set(['image','stylesheet','font','media','websocket','other']);

function getExt(href) {
  try { const p = new URL(href).pathname; const i = p.lastIndexOf('.'); return i === -1 ? '' : p.slice(i+1).toLowerCase(); }
  catch { return ''; }
}
function urlFp(href) {
  try { const u = new URL(href); const params = [...u.searchParams.keys()].sort().join(','); return u.hostname + u.pathname.replace(/\/+$/,'') + (params ? '?'+params : ''); }
  catch { return href; }
}
function sameOrigin(href, baseHost, baseDomain) {
  try { const h = new URL(href).hostname; return h === baseHost || h.endsWith('.'+baseHost) || h === baseDomain || h.endsWith('.'+baseDomain); }
  catch { return false; }
}
function inScope(href, outScopeIds) {
  if (!outScopeIds || !outScopeIds.length) return true;
  try { const u = new URL(href); return !outScopeIds.some(id => u.hostname.includes(id) || u.pathname.startsWith(id)); }
  catch { return true; }
}
function normalize(href, base) {
  try { const u = new URL(href, base); u.hash = ''; return u.href.replace(/\/+$/,'') || u.href; }
  catch { return null; }
}

async function run(cfg) {
  const {
    target, maxPages = 500, maxDepth = 4, cookies = '',
    outScopeIds = [], wordlist = [], dirWordlist = [], concurrency = 3,
    skipUrls = [],
  } = cfg;

  let targetUrl;
  try { targetUrl = new URL(target); }
  catch (e) { emit({ type: 'error', message: 'Invalid target: ' + e.message }); return; }

  const baseHost   = targetUrl.hostname;
  const hostParts  = baseHost.split('.');
  const baseDomain = hostParts.length >= 2 ? hostParts.slice(-2).join('.') : baseHost;
  const baseUrl    = `${targetUrl.protocol}//${targetUrl.host}`;

  let puppeteer;
  try { puppeteer = require(path.join(__dirname, 'node_modules', 'puppeteer')); }
  catch (e) { emit({ type: 'error', message: 'puppeteer not found: ' + e.message }); return; }

  emit({ type: 'phase', message: `🌐 Launching browser → ${target}` });

  const browser = await puppeteer.launch({
    headless: true,
    defaultViewport: { width: 1440, height: 900 },
    args: [
      '--no-sandbox','--disable-setuid-sandbox','--disable-dev-shm-usage',
      '--disable-blink-features=AutomationControlled',
      '--disable-features=IsolateOrigins,site-per-process',
      '--no-first-run','--disable-infobars',
    ],
    ignoreDefaultArgs: ['--enable-automation'],
  });

  // ── Page Pool — reusable pre-warmed pages (eliminates newPage() overhead per URL) ─
  const POOL_SIZE    = 8;
  const _pagePool    = [];
  const _pageWaiters = [];
  function _acquirePage() {
    if (_pagePool.length > 0) return Promise.resolve(_pagePool.pop());
    return new Promise(res => _pageWaiters.push(res));
  }
  function _releasePage(p) {
    if (_pageWaiters.length > 0) { _pageWaiters.shift()(p); }
    else { _pagePool.push(p); }
  }

  const visitedFps  = new Set();
  const visitedRaw  = new Set([target]);
  const emittedUrls = new Set();
  const emittedForms = new Set();
  const queue       = [];

  // ── Resume after the program was closed: skip URLs already emitted in the
  // previous run so they are not re-sent to the UI nor re-scanned by the AI. ──
  for (const u of skipUrls) {
    emittedUrls.add(u);
    try { visitedFps.add(urlFp(u)); } catch {}
  }
  let   crawled     = 0;
  let   totalReqs   = 0;
  let   lastReqSnap = 0;
  let   allDone     = false;
  let   wlDone      = false;
  let   activeWorkers = 0;  // tracks pages being visited right now — prevents premature allDone

  function enqueue(url, depth) {
    if (visitedFps.size >= maxPages || depth > maxDepth) return;
    const fp = urlFp(url);
    if (visitedFps.has(fp)) return;
    visitedFps.add(fp);
    queue.push({ url, depth });
  }

  function emitUrl(url, status, method, mimeType, contentLength, hasParams) {
    if (emittedUrls.has(url)) return;
    if (status === 403 || status === 404 || status === 0) return;
    emittedUrls.add(url);
    emit({ type: 'url', url, originalUrl: url, status: status||0, depth: 0,
           method: method||'GET', mimeType: mimeType||'', contentLength: contentLength||0,
           hasParams: hasParams||url.includes('?'), headers: {}, body: '', forms: [], links: [], error: null });
  }

  // ── POST/GET forms: emitted as a standalone event so the backend scans their fields (body injection) ──
  function emitForm(fm, pageUrl) {
    if (!fm || !fm.action || !fm.inputs || !fm.inputs.length) return;
    if (!sameOrigin(fm.action, baseHost, baseDomain)) return;
    if (!inScope(fm.action, outScopeIds)) return;
    const key = fm.method + ' ' + fm.action + ' ' + fm.inputs.map(i => i.name).sort().join(',');
    if (emittedForms.has(key)) return;
    emittedForms.add(key);
    emit({ type: 'form', page: pageUrl, action: fm.action, method: fm.method,
           enctype: fm.enctype, inputs: fm.inputs });
  }

  async function extractForms(page, url) {
    const forms = await page.evaluate((base) => {
      const out = [];
      document.querySelectorAll('form').forEach(f => {
        let action; try { action = new URL(f.getAttribute('action') || '', base).href; } catch { action = base; }
        const method  = (f.getAttribute('method') || 'GET').toUpperCase();
        const enctype = (f.getAttribute('enctype') || 'application/x-www-form-urlencoded').toLowerCase();
        const inputs = [];
        f.querySelectorAll('input,textarea,select').forEach(el => {
          const name = el.getAttribute('name'); if (!name) return;
          const type = (el.getAttribute('type') || el.tagName || 'text').toLowerCase();
          if (['submit','button','image','reset','file'].includes(type)) return;
          inputs.push({ name, type, value: el.value || '' });
        });
        if (inputs.length) out.push({ action, method, enctype, inputs });
      });
      return out;
    }, url).catch(() => []);
    for (const fm of forms) emitForm(fm, url);
  }

  async function applyAntiDetect(page) {
    await page.evaluateOnNewDocument(() => {
      Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
      Object.defineProperty(navigator, 'plugins', { get: () => [1,2,3,4,5] });
      Object.defineProperty(navigator, 'languages', { get: () => ['en-US','en'] });
      window.chrome = { runtime: {} };
    });
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36');
    await page.setExtraHTTPHeaders({ 'Accept-Language': 'en-US,en;q=0.9' });
    if (cookies) {
      const arr = cookies.split(';').map(c => c.trim()).filter(Boolean).map(c => {
        const [n,...v] = c.split('='); return { name: n.trim(), value: v.join('=').trim(), domain: baseHost, path: '/' };
      });
      try { await page.setCookie(...arr); } catch {}
    }
  }

  async function setupInterception(page) {
    await page.setRequestInterception(true);
    page.on('request', req => {
      if (RESOURCE_SKIP.has(req.resourceType())) { req.abort(); return; }
      req.continue(); totalReqs++;
    });
    page.on('response', async res => {
      try {
        const reqUrl = res.url();
        if (!reqUrl.startsWith('http')) return;
        const u = new URL(reqUrl);
        if (!sameOrigin(reqUrl, baseHost, baseDomain)) return;
        if (!inScope(reqUrl, outScopeIds)) return;
        if (SKIP_EXTS.has(getExt(reqUrl))) return;
        const status = res.status();
        if (status === 403 || status === 404) return;
        const ct      = res.headers()['content-type'] || '';
        const mime    = ct.split(';')[0].trim();
        const len     = parseInt(res.headers()['content-length']||'0')||0;
        emitUrl(reqUrl, status, res.request().method(), mime, len, u.search.length > 1);
        if (status >= 200 && status < 400 && (ct.includes('html')||ct.includes('json')) && !visitedRaw.has(reqUrl)) {
          visitedRaw.add(reqUrl); enqueue(reqUrl, 1);
        }
      } catch {}
    });
  }

  async function visitPage(url, depth) {
    crawled++;
    const page = await browser.newPage();
    try {
      await applyAntiDetect(page);
      await setupInterception(page);
      try { await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 18000 }); }
      catch (e) { if (!e.message.includes('timeout')) throw e; }
      await new Promise(r => setTimeout(r, 1500));
      const links = await page.evaluate((base) => {
        const s = new Set();
        document.querySelectorAll('a[href],area[href]').forEach(el => { try { s.add(new URL(el.href, base).href); } catch {} });
        document.querySelectorAll('[data-href],[data-url]').forEach(el => {
          const v = el.dataset.href || el.dataset.url; if (v) try { s.add(new URL(v, base).href); } catch {}
        });
        document.querySelectorAll('script:not([src])').forEach(sc => {
          for (const m of sc.textContent.matchAll(/["'`](\/[a-zA-Z0-9/_\-\.?=&%]{2,150})["'`]/g))
            try { s.add(new URL(m[1], base).href); } catch {}
        });
        return [...s];
      }, url).catch(() => []);

      for (const lnk of links) {
        if (SKIP_EXTS.has(getExt(lnk))) continue;
        if (!sameOrigin(lnk, baseHost, baseDomain)) continue;
        if (!inScope(lnk, outScopeIds)) continue;
        if (!visitedRaw.has(lnk)) { visitedRaw.add(lnk); enqueue(lnk, depth+1); }
      }
      await extractForms(page, url);     // discover POST/GET forms on the page
    } catch (e) {
      emit({ type: 'warn', message: `⚠ ${url.slice(0,60)}: ${e.message.slice(0,80)}` });
    } finally {
      await page.close().catch(() => {});
    }
  }

  // ── Initial load (solve Cloudflare) ──────────────────────────────────────
  const initPage = await browser.newPage();
  await applyAntiDetect(initPage);
  await setupInterception(initPage);
  emit({ type: 'phase', message: `Crawling ${target}` });
  try {
    await initPage.goto(target, { waitUntil: 'networkidle2', timeout: 40000 });
    await new Promise(r => setTimeout(r, 3000));
    const ck = await initPage.cookies();
    const hasCf = ck.some(c => c.name === 'cf_clearance');
    emit({ type: 'phase', message: `🔓 ${hasCf ? 'Cloudflare bypassed' : 'Browser ready'} — ${ck.length} cookies` });
    const initLinks = await initPage.evaluate((base) => {
      const s = new Set();
      document.querySelectorAll('a[href]').forEach(a => { try { s.add(new URL(a.href, base).href); } catch {} });
      document.querySelectorAll('script:not([src])').forEach(sc => {
        for (const m of sc.textContent.matchAll(/["'`](\/[a-zA-Z0-9/_\-\.?=&%]{2,120})["'`]/g))
          try { s.add(new URL(m[1], base).href); } catch {}
      });
      return [...s];
    }, target).catch(() => []);
    for (const lnk of initLinks) {
      if (SKIP_EXTS.has(getExt(lnk))) continue;
      if (!sameOrigin(lnk, baseHost, baseDomain)) continue;
      if (!inScope(lnk, outScopeIds)) continue;
      if (!visitedRaw.has(lnk)) { visitedRaw.add(lnk); enqueue(lnk, 1); }
    }
    await extractForms(initPage, target);   // homepage forms
  } catch (e) {
    emit({ type: 'warn', message: `⚠ Initial load: ${e.message.slice(0,100)}` });
  } finally {
    await initPage.close().catch(() => {});
  }

  // ── Pre-warm page pool (inherits CF cookies from current browser session) ──
  emit({ type: 'phase', message: `⚡ Warming page pool (${POOL_SIZE} pages)…` });
  await Promise.all(Array.from({ length: POOL_SIZE }, async () => {
    try {
      const _pp = await browser.newPage();
      await applyAntiDetect(_pp);
      await setupInterception(_pp);
      _pagePool.push(_pp);
    } catch (_pe) {
      emit({ type: 'warn', message: 'Pool init: ' + _pe.message.slice(0, 60) });
    }
  }));
  emit({ type: 'phase', message: `✅ Page pool ready — ${_pagePool.length}/${POOL_SIZE} workers` });

  // ── Wordlist probing via browser fetch (stays in CF session) ─────────────
  const wlPage = await browser.newPage();
  await applyAntiDetect(wlPage);

  const probeWordlist = async () => {
    const allWords = [...new Set([...wordlist, ...dirWordlist])];
    const batchSize = 25;
    for (let i = 0; i < allWords.length && !allDone; i += batchSize) {
      await _waitIfPaused();          // suspend the wordlist prober too while paused
      const batch = allWords.slice(i, i+batchSize);
      const results = await wlPage.evaluate(async (words, base) => {
        const out = [];
        await Promise.all(words.map(async w => {
          const url = `${base}/${w}`;
          try {
            const r = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: AbortSignal.timeout(5000) });
            if (r.status !== 403 && r.status !== 404 && r.status > 0) out.push({ url, status: r.status });
          } catch {}
        }));
        return out;
      }, batch, baseUrl).catch(() => []);
      for (const { url, status } of results) {
        totalReqs += 1;
        emitUrl(url, status, 'HEAD', '', 0, false);
        if (status >= 200 && status < 400 && !visitedRaw.has(url)) { visitedRaw.add(url); enqueue(url, 1); }
      }
    }
    wlDone = true;
    emit({ type: 'phase', message: `Wordlist done — ${emittedUrls.size} paths discovered` });
    await wlPage.close().catch(() => {});
  };

  const wlProm = probeWordlist();

  // ── Stats ─────────────────────────────────────────────────────────────────
  const statsTimer = setInterval(() => {
    const rps = totalReqs - lastReqSnap; lastReqSnap = totalReqs;
    emit({ type: 'stats', crawled, queued: queue.length, active: 0, rps, total: emittedUrls.size, requests: totalReqs });
  }, 1000);

  // Heartbeat — Python detects frozen crawler (silence ≠ done)
  const heartbeatTimer = setInterval(() => {
    if (!allDone) emit({ type: 'heartbeat', ts: Date.now() });
  }, 5000);

  // ── Workers ───────────────────────────────────────────────────────────────
  async function crawlWorker() {
    while (!allDone) {
      await _waitIfPaused();          // suspend without losing the queue/visited state
      const item = queue.shift();
      if (!item) {
        // Only mark done when queue is empty AND wordlist is done AND no worker is mid-page.
        // Without the activeWorkers check a worker visiting a page that adds 20 new URLs
        // could be racing against other workers that see an empty queue and set allDone=true.
        if (wlDone && queue.length === 0 && activeWorkers === 0) { allDone = true; break; }
        await new Promise(r => setTimeout(r, 200));
        continue;
      }
      if (emittedUrls.size >= maxPages) { allDone = true; break; }
      activeWorkers++;
      try {
        // Hard 35-second ceiling per page so a single stuck/hanging page never
        // blocks a worker indefinitely (browser.newPage() + goto + evaluate).
        await Promise.race([
          visitPage(item.url, item.depth),
          new Promise((_, rej) => setTimeout(() => rej(new Error('page-timeout 15s')), 15000)),
        ]);
      } catch (e) {
        emit({ type: 'warn', message: 'Worker: ' + e.message.slice(0, 80) });
      } finally {
        activeWorkers--;
      }
    }
  }

  await Promise.all([
    wlProm,
    Promise.allSettled(Array.from({ length: Math.min(concurrency, POOL_SIZE) }, () => crawlWorker())),
  ]);

  clearInterval(statsTimer);
  clearInterval(heartbeatTimer);
  await Promise.allSettled(_pagePool.splice(0).map(p => p.close().catch(() => {})));
  await browser.close().catch(() => {});
  emit({ type: 'done', crawled, total: emittedUrls.size, requests: totalReqs });
}
