// ═══════════════════════════════════════════════════════════════════════════════
// server.js — VPS Video Decryptor v2
// ═══════════════════════════════════════════════════════════════════════════════
//
// Fix: Cloudflare blocks heavy automated requests
// Solution: Block images/fonts/css → lightweight requests → faster CF pass
//
// Deploy:
//   sudo apt update && sudo apt install -y chromium-browser
//   npm install
//   node server.js
//
// ═══════════════════════════════════════════════════════════════════════════════

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');

puppeteer.use(StealthPlugin());

const app = express();
app.use(cors());
app.use(express.json({ limit: '5mb' }));

const PORT = process.env.PORT || 3000;
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

// ─── AES-256-GCM Decrypt ────────────────────────────────────────────────────

function b64urlDecode(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = (4 - (b64.length % 4)) % 4;
  return Buffer.from(b64 + '='.repeat(pad), 'base64');
}

function concatKeyParts(parts) {
  return Buffer.concat(parts.map(p => b64urlDecode(p)));
}

function decryptPayload(pb) {
  const key = concatKeyParts(pb.key_parts);
  const iv = b64urlDecode(pb.iv);
  const ct = b64urlDecode(pb.payload);
  const tag = ct.subarray(-16);
  const ciphertext = ct.subarray(0, -16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  let dec = decipher.update(ciphertext);
  dec = Buffer.concat([dec, decipher.final()]);
  return JSON.parse(dec.toString('utf8'));
}

// ─── Puppeteer Browser ─────────────────────────────────────────────────────

let browser = null;
let browserLaunching = false;
let cfPassed = false; // track if CF challenge was passed

async function getBrowser() {
  if (browser && browser.connected) return browser;
  if (browserLaunching) {
    while (browserLaunching) await new Promise(r => setTimeout(r, 200));
    return browser;
  }
  browserLaunching = true;
  try {
    browser = await puppeteer.launch({
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-software-rasterizer',
        '--disable-extensions',
        '--disable-default-apps',
        '--no-first-run',
        '--window-size=1920,1080',
        '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows',
        '--disable-renderer-backgrounding',
        '--disable-features=TranslateUI',
        '--disable-ipc-flooding-protection',
      ],
    });
    console.log('[browser] Launched');
    browser.on('disconnected', () => {
      console.log('[browser] Disconnected');
      browser = null;
      cfPassed = false;
    });
  } catch (e) {
    console.error('[browser] Launch failed:', e.message);
    throw new Error('Puppeteer launch failed: ' + e.message +
      '\n\nInstall Chromium:\n  sudo apt update && sudo apt install -y chromium-browser\n');
  }
  browserLaunching = false;
  return browser;
}

// Block heavy resources to keep requests lightweight
async function blockHeavyResources(page) {
  await page.setRequestInterception(true);
  page.on('request', req => {
    const type = req.resourceType();
    // Only allow: document, script, xhr, fetch — block everything else
    if (['image', 'font', 'stylesheet', 'media', 'manifest', 'other'].includes(type)) {
      req.abort();
    } else {
      req.continue();
    }
  });
}

// Wait for Cloudflare challenge to pass
async function waitForCF(page, logStep) {
  // Check if CF challenge page is shown
  const body = await page.content();
  if (body.includes('challenge-platform') || body.includes('cf-browser-verification') || body.includes('Just a moment')) {
    logStep('Cloudflare challenge detected, waiting...');
    // Wait for CF to set cf_clearance cookie or page to change
    for (let i = 0; i < 30; i++) {
      await new Promise(r => setTimeout(r, 1000));
      try {
        const cookies = await page.cookies('https://f75s.com');
        const hasCF = cookies.some(c => c.name === 'cf_clearance');
        if (hasCF) {
          logStep('CF challenge passed (cf_clearance cookie set)');
          cfPassed = true;
          return true;
        }
        const currentBody = await page.content();
        if (!currentBody.includes('challenge-platform') && !currentBody.includes('cf-browser-verification')) {
          logStep('CF challenge passed (page changed)');
          cfPassed = true;
          return true;
        }
      } catch (e) {}
    }
    logStep('CF challenge timeout after 30s');
    return false;
  }
  cfPassed = true;
  return true;
}

// ─── Main: Fetch + Decrypt via Puppeteer ───────────────────────────────────

async function fetchAndDecrypt(code, debugMode) {
  const log = [];
  const t0 = Date.now();

  function logStep(msg) {
    const elapsed = Date.now() - t0;
    const line = '[' + elapsed + 'ms] ' + msg;
    log.push(line);
    console.log(line);
  }

  let page = null;
  let allRequests = [];
  let allResponses = [];
  let playbackData = null;
  let challengeData = null;
  let attestData = null;
  let pageError = null;
  let pageTitle = '';
  let pageUrl = '';

  try {
    const br = await getBrowser();

    // 1. Create page with resource blocking
    logStep('Opening page...');
    page = await br.newPage();
    await page.setViewport({ width: 1920, height: 1080, deviceScaleFactor: 1 });
    await page.setUserAgent(UA);
    await blockHeavyResources(page);

    // 2. Set extra headers to look real
    await page.setExtraHTTPHeaders({
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
      'sec-ch-ua': '"Chromium";v="131", "Not-A.Brand";v="24", "Google Chrome";v="131"',
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
    });

    // 3. Navigate to homepage first to pass CF (if not already passed)
    if (!cfPassed) {
      logStep('Warming up homepage to pass CF...');
      try {
        await page.goto('https://f75s.com/', {
          waitUntil: 'domcontentloaded',
          timeout: 20000,
        });
        await waitForCF(page, logStep);
        if (!cfPassed) {
          logStep('Homepage CF not passed, trying anyway...');
        }
      } catch (e) {
        logStep('Homepage: ' + e.message.substring(0, 100));
      }
      await new Promise(r => setTimeout(r, 2000));
    } else {
      logStep('CF already passed from previous request, skipping warmup');
    }

    // 4. Now set up API interception BEFORE navigating to video
    page.removeAllListeners('request');
    page.removeAllListeners('response');

    // Re-enable interception for API capture only
    await page.setRequestInterception(true);
    page.on('request', req => {
      const url = req.url();
      const type = req.resourceType();

      // Block heavy stuff
      if (['image', 'font', 'stylesheet', 'media', 'manifest', 'other'].includes(type)) {
        req.abort();
        return;
      }

      // Log API requests
      if (url.includes('f75s.com/api/')) {
        const entry = {
          ts: Date.now() - t0,
          method: req.method(),
          url: url,
        };
        if (req.method() === 'POST' && req.postData()) {
          try { entry.body = JSON.parse(req.postData()); } catch (e) { entry.bodyRaw = req.postData().substring(0, 500); }
        }
        allRequests.push(entry);
        logStep('>> ' + req.method() + ' ' + url.replace('https://f75s.com', ''));
      }

      req.continue();
    });

    page.on('response', async (resp) => {
      const url = resp.url();
      if (!url.includes('f75s.com/api/')) return;

      const entry = { ts: Date.now() - t0, status: resp.status(), url: url };

      try {
        const ct = resp.headers()['content-type'] || '';
        if (ct.includes('json')) {
          entry.body = await resp.json();
        } else {
          const text = await resp.text();
          entry.bodyRaw = text.substring(0, 1000);
        }
      } catch (e) {
        entry.parseError = e.message;
      }

      allResponses.push(entry);
      logStep('<< ' + resp.status() + ' ' + url.replace('https://f75s.com', ''));

      if (url.includes('access/challenge') && resp.status() === 200) challengeData = entry.body;
      if (url.includes('access/attest') && resp.status() === 200) attestData = entry.body;
      if (url.includes('/api/videos/') && url.includes('playback') && resp.status() === 200) {
        playbackData = entry.body;
        logStep('GOT PLAYBACK!');
      }
    });

    // 5. Navigate to video page (use domcontentloaded — fast, don't wait for networkidle)
    const videoUrl = 'https://f75s.com/ei4/' + code;
    logStep('Navigating to ' + videoUrl);

    try {
      await page.goto(videoUrl, {
        waitUntil: 'domcontentloaded',
        timeout: 20000,
      });
      pageTitle = await page.title();
      pageUrl = page.url();
      logStep('Page loaded: ' + pageTitle);
    } catch (navErr) {
      logStep('Nav: ' + navErr.message.substring(0, 100));
      pageError = navErr.message;
    }

    // 6. Check for CF challenge on video page too
    try {
      const body = await page.content();
      if (body.includes('challenge-platform') || body.includes('cf-browser-verification')) {
        logStep('CF challenge on video page, waiting...');
        await waitForCF(page, logStep);
        // After CF passes, the page should auto-redirect and load the actual content
        // Wait more for API calls to fire
        for (let i = 0; i < 20 && !playbackData; i++) {
          await new Promise(r => setTimeout(r, 500));
        }
      }
    } catch (e) {}

    // 7. Wait for playback API response
    if (!playbackData) {
      logStep('Waiting for playback API (up to 12s)...');
      for (let i = 0; i < 24 && !playbackData; i++) {
        await new Promise(r => setTimeout(r, 500));
      }
    }

    // 8. If still no playback, check page for clues
    if (!playbackData) {
      logStep('No playback captured. Checking page...');
      try {
        const body = await page.content();
        const checks = [
          ['CF challenge still active', /challenge-platform|cf-browser-verification|Just a moment/],
          ['Cloudflare block (1020)', /Error 1020|Access denied/i],
          ['Geo block', /not available in your country|geo/i],
          ['VPN block', /VPN.*not allowed|vpn/i],
          ['Proxy block', /proxy.*not allowed/i],
          ['Private video', /private|login|sign in/i],
          ['Embed blocked', /embedding.*not allowed|embed/i],
          ['404', /not found|404/i],
          ['Error 5xx', /5\d{2}/],
        ];
        for (const [label, rx] of checks) {
          if (rx.test(body)) logStep('Page shows: ' + label);
        }

        // Get page title and URL for debug
        pageTitle = await page.title();
        pageUrl = page.url();
        logStep('Final URL: ' + pageUrl);
        logStep('Final title: ' + pageTitle);
      } catch (e) {
        logStep('Page check error: ' + e.message);
      }
    }

  } catch (e) {
    logStep('Fatal: ' + e.message);
  } finally {
    if (page) {
      try { await page.close(); } catch (e) {}
    }
  }

  // 9. Check result
  if (!playbackData) {
    const errMsg = 'Playback response not captured.\n\n' +
      'Page URL: ' + (pageUrl || 'N/A') + '\n' +
      'Page title: ' + (pageTitle || 'N/A') + '\n' +
      'API responses captured: ' + allResponses.length + '\n\n' +
      'Hit /debug/' + code + ' for full network log.';
    logStep('FAILED: ' + errMsg);
    throw new Error(errMsg);
  }

  const pb = playbackData.playback || playbackData;
  if (!pb || !pb.key_parts || !pb.iv || !pb.payload) {
    throw new Error('No encrypted payload. Response keys: ' + Object.keys(playbackData).join(', '));
  }

  // 10. Decrypt
  logStep('Decrypting...');
  const decrypted = decryptPayload(pb);
  logStep('OK! ' + (decrypted.sources || []).length + ' source(s), ' + (Date.now() - t0) + 'ms total');

  return {
    data: decrypted,
    debug: debugMode ? {
      code,
      timestamp: new Date().toISOString(),
      totalTimeMs: Date.now() - t0,
      log,
      pageUrl: pageUrl,
      pageTitle: pageTitle,
      pageError: pageError || null,
      challenge: challengeData ? { challenge_id: challengeData.challenge_id, nonce: challengeData.nonce } : null,
      attest: attestData ? { token: (attestData.token || '').substring(0, 50) + '...' } : null,
      rawPlayback: { ...playbackData, payload: (playbackData.playback || playbackData).payload.substring(0, 50) + '...(truncated)' },
      requestCount: allRequests.length,
      responseCount: allResponses.length,
      requests: allRequests.map(r => ({ ts: r.ts, method: r.method, url: r.url, bodyKeys: r.body ? Object.keys(r.body) : undefined })),
      responses: allResponses.map(r => ({ ts: r.ts, status: r.status, url: r.url, bodyKeys: r.body ? Object.keys(r.body) : undefined, error: r.body && r.body.error ? r.body.error : undefined })),
    } : undefined,
  };
}

// ─── Routes ─────────────────────────────────────────────────────────────────

app.get('/e/:code', async (req, res) => {
  const code = req.params.code;
  console.log('\n[GET /e/' + code + ']');
  try {
    const result = await fetchAndDecrypt(code, false);
    res.json(result.data);
  } catch (e) {
    console.error('[GET /e/' + code + '] Error:', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.get('/d/:code', async (req, res) => {
  const code = req.params.code;
  console.log('\n[GET /d/' + code + ']');
  try {
    const result = await fetchAndDecrypt(code, false);
    res.json(result.data);
  } catch (e) {
    console.error('[GET /d/' + code + '] Error:', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.get('/debug/:code', async (req, res) => {
  const code = req.params.code;
  console.log('\n[GET /debug/' + code + ']');
  try {
    const result = await fetchAndDecrypt(code, true);
    res.json({ success: true, ...result.debug, decrypted: result.data });
  } catch (e) {
    console.error('[GET /debug/' + code + '] Error:', e.message);
    res.status(502).json({
      success: false,
      error: e.message,
      stack: e.stack,
      code,
      timestamp: new Date().toISOString(),
      note: 'Share this full response for analysis',
    });
  }
});

app.post('/decrypt', (req, res) => {
  try {
    const pb = req.body.playback || req.body;
    if (!pb.key_parts || !pb.iv || !pb.payload) {
      return res.status(400).json({ error: 'Missing key_parts, iv, or payload' });
    }
    res.json(decryptPayload(pb));
  } catch (e) {
    res.status(400).json({ error: 'Decrypt failed: ' + e.message });
  }
});

app.get('/proxy', (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).json({ error: 'Missing ?url=' });
  let parsed;
  try { parsed = new URL(targetUrl); } catch (e) { return res.status(400).json({ error: 'Invalid URL' }); }

  const client = parsed.protocol === 'https:' ? https : http;
  const proxyReq = client.request(targetUrl, {
    method: 'GET',
    headers: {
      'User-Agent': UA,
      'Accept': '*/*, video/mp4, application/vnd.apple.mpegurl',
      'Referer': 'https://f75s.com/',
      'Origin': 'https://f75s.com',
    },
  }, (proxyRes) => {
    if (proxyRes.headers['content-type']) res.set('Content-Type', proxyRes.headers['content-type']);
    if (proxyRes.headers['content-range']) res.set('Content-Range', proxyRes.headers['content-range']);
    res.set('Access-Control-Allow-Origin', '*');
    proxyRes.pipe(res);
  });
  proxyReq.on('error', (e) => {
    if (!res.headersSent) res.status(502).json({ error: 'Proxy failed: ' + e.message });
  });
  proxyReq.end();
});

app.get('/rewrite', async (req, res) => {
  const m3u8Url = req.query.url;
  if (!m3u8Url) return res.status(400).json({ error: 'Missing ?url=' });
  const base = req.protocol + '://' + req.get('host');
  try {
    const client = new URL(m3u8Url).protocol === 'https:' ? https : http;
    const body = await new Promise((resolve, reject) => {
      client.get(m3u8Url, { headers: { 'User-Agent': UA, 'Referer': 'https://f75s.com/' } }, (r) => {
        let d = '';
        r.on('data', c => d += c);
        r.on('end', () => resolve(d));
        r.on('error', reject);
      }).on('error', reject);
    });
    const baseUrl = m3u8Url.substring(0, m3u8Url.lastIndexOf('/') + 1);
    const rewritten = body.split('\n').map(line => {
      const t = line.trim();
      if (!t || t.startsWith('#')) return line;
      const full = t.startsWith('http') ? t : baseUrl + t;
      return base + '/proxy?url=' + encodeURIComponent(full);
    }).join('\n');
    res.set('Content-Type', 'application/vnd.apple.mpegurl');
    res.set('Access-Control-Allow-Origin', '*');
    res.send(rewritten);
  } catch (e) {
    res.status(502).json({ error: 'Rewrite failed: ' + e.message });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime(), browser: browser ? 'connected' : 'not running', cfPassed });
});

app.listen(PORT, () => {
  console.log('═════════════════════════════════════════════');
  console.log('  Video Decryptor v2 on port ' + PORT);
  console.log('═════════════════════════════════════════════');
  console.log('  /e/{code}     → decrypt');
  console.log('  /d/{code}     → decrypt');
  console.log('  /debug/{code} → debug info');
  console.log('  /decrypt      → POST raw payload');
  console.log('  /proxy?url=   → proxy segments');
  console.log('  /rewrite?url= → rewrite m3u8');
  console.log('  /health       → status');
  console.log('');
});

process.on('SIGINT', async () => {
  console.log('\nShutting down...');
  if (browser) { try { await browser.close(); } catch (e) {} }
  process.exit(0);
});
