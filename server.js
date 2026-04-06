// ═══════════════════════════════════════════════════════════════════════════════
// server.js — VPS Video Decryptor
// ═══════════════════════════════════════════════════════════════════════════════
//
// Deploy on any VPS (Ubuntu/Debian):
//   sudo apt update && sudo apt install -y chromium-browser
//   npm install
//   node server.js
//
// Routes:
//   GET  /e/{code}          → Fetch + Decrypt → Return JSON
//   GET  /d/{code}          → Same
//   GET  /debug/{code}      → Full debug info (share this when errors happen)
//   POST /decrypt           → Decrypt raw AES-GCM payload
//   GET  /proxy?url=<URL>   → Proxy .ts/.m3u8 segments through VPS
//
// How it works:
//   Puppeteer opens f75s.com → real browser handles fingerprint/auth
//   → intercepts /playback API response → AES-256-GCM decrypt → return JSON
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
        '--window-size=1920,1080',
      ],
    });
    console.log('[browser] Launched Puppeteer');
    browser.on('disconnected', () => {
      console.log('[browser] Disconnected');
      browser = null;
    });
  } catch (e) {
    console.error('[browser] Launch failed:', e.message);
    throw new Error('Puppeteer launch failed: ' + e.message +
      '\n\nInstall Chromium:\n  sudo apt update && sudo apt install -y chromium-browser\n' +
      'Or on Ubuntu 24.04:\n  sudo apt install -y chromium\n');
  }
  browserLaunching = false;
  return browser;
}

// ─── Main: Fetch + Decrypt via Puppeteer ───────────────────────────────────

async function fetchAndDecrypt(code, debugMode) {
  const log = [];
  const t0 = Date.now();

  function logStep(msg) {
    const elapsed = Date.now() - t0;
    const line = `[${elapsed}ms] ${msg}`;
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

  try {
    // 1. Launch browser
    logStep('Launching browser...');
    const br = await getBrowser();

    // 2. New page
    logStep('Opening page...');
    page = await br.newPage();
    await page.setViewport({ width: 1920, height: 1080, deviceScaleFactor: 1 });
    await page.setUserAgent(UA);

    // 3. Capture all API network activity
    page.on('request', req => {
      const url = req.url();
      if (url.includes('f75s.com/api/') || url.includes('/access/')) {
        const entry = {
          ts: Date.now() - t0,
          method: req.method(),
          url: url,
          resourceType: req.resourceType(),
        };
        // Capture POST body for API calls
        if (req.method() === 'POST' && req.postData()) {
          try { entry.body = JSON.parse(req.postData()); } catch (e) { entry.bodyRaw = req.postData().substring(0, 500); }
        }
        allRequests.push(entry);
        if (debugMode) logStep('→ ' + req.method() + ' ' + url.replace('https://f75s.com', ''));
      }
    });

    page.on('response', async resp => {
      const url = resp.url();
      if (!url.includes('f75s.com/api/') && !url.includes('/access/')) return;

      const entry = {
        ts: Date.now() - t0,
        status: resp.status(),
        url: url,
      };

      // Try to parse response body
      try {
        const contentType = resp.headers()['content-type'] || '';
        if (contentType.includes('json')) {
          entry.body = await resp.json();
        } else {
          const text = await resp.text();
          entry.bodyRaw = text.substring(0, 1000);
        }
      } catch (e) {
        entry.parseError = e.message;
      }

      allResponses.push(entry);
      if (debugMode) logStep('← ' + resp.status() + ' ' + url.replace('https://f75s.com', ''));

      // Capture specific responses
      if (url.includes('access/challenge') && resp.status() === 200) {
        challengeData = entry.body;
      }
      if (url.includes('access/attest') && resp.status() === 200) {
        attestData = entry.body;
      }
      if (url.includes('/api/videos/' + code) && url.includes('playback') && resp.status() === 200) {
        playbackData = entry.body;
        logStep('✓ Captured playback response!');
      }
    });

    // 4. Navigate to video page
    const videoUrl = 'https://f75s.com/ei4/' + code;
    logStep('Navigating to ' + videoUrl);

    try {
      await page.goto(videoUrl, {
        waitUntil: 'networkidle2',
        timeout: 25000,
      });
      logStep('Page loaded');
    } catch (navErr) {
      // Timeout is OK — page might still have loaded enough
      logStep('Navigation: ' + navErr.message.substring(0, 100));
      pageError = navErr.message;
    }

    // 5. Wait for playback if not captured yet
    if (!playbackData) {
      logStep('Waiting for playback response (up to 10s)...');
      for (let i = 0; i < 20 && !playbackData; i++) {
        await new Promise(r => setTimeout(r, 500));
      }
    }

    // 6. Check for error messages in page
    if (!playbackData) {
      try {
        const pageContent = await page.content();
        // Check for common error messages
        const errors = [
          /geo/i, /vpn/i, /proxy/i, /not available/i,
          /blocked/i, /restricted/i, /private/i, /login/i,
          /403|401|404/i
        ];
        for (const rx of errors) {
          const match = pageContent.match(rx);
          if (match) {
            logStep('Page might show: "' + match[0] + '"');
          }
        }

        // Try alternative page
        logStep('Trying alternative URL: /pbf/' + code);
        await page.goto('https://f75s.com/pbf/' + code, {
          waitUntil: 'networkidle2',
          timeout: 15000,
        }).catch(() => {});
        for (let i = 0; i < 10 && !playbackData; i++) {
          await new Promise(r => setTimeout(r, 500));
        }
      } catch (e) {
        logStep('Page content check: ' + e.message);
      }
    }

  } catch (e) {
    logStep('Fatal error: ' + e.message);
    logStep('Stack: ' + e.stack);
  } finally {
    // Always close the page
    if (page) {
      try { await page.close(); } catch (e) {}
    }
  }

  // 7. Check result
  if (!playbackData) {
    const errMsg = 'Playback response not captured after page load.\n\n' +
      'Possible reasons:\n' +
      '- Video requires login\n' +
      '- Video is private/deleted\n' +
      '- Geo-blocked or VPN-blocked\n' +
      '- Cloudflare blocked the request\n\n' +
      'Use /debug/' + code + ' for full details.';
    logStep('FAILED: ' + errMsg);
    throw new Error(errMsg);
  }

  const pb = playbackData.playback || playbackData;
  if (!pb || !pb.key_parts || !pb.iv || !pb.payload) {
    throw new Error('No encrypted payload in response. Keys found: ' + Object.keys(playbackData).join(', '));
  }

  // 8. Decrypt
  logStep('Decrypting (' + pb.key_parts.length + ' key_parts, IV ' + pb.iv.length + ' chars)...');
  const decrypted = decryptPayload(pb);
  logStep('✓ Decrypted! ' + (decrypted.sources || []).length + ' source(s) found');
  logStep('Total time: ' + (Date.now() - t0) + 'ms');

  return {
    data: decrypted,
    debug: debugMode ? {
      code,
      timestamp: new Date().toISOString(),
      totalTimeMs: Date.now() - t0,
      log,
      pageUrl: 'https://f75s.com/ei4/' + code,
      pageError: pageError || null,
      challenge: challengeData || null,
      attest: attestData || null,
      rawPlayback: playbackData || null,
      requestCount: allRequests.length,
      responseCount: allResponses.length,
      requests: allRequests,
      responses: allResponses,
    } : undefined,
  };
}

// ─── Routes ─────────────────────────────────────────────────────────────────

// GET /e/{code} — Main route: fetch + decrypt → return JSON
app.get('/e/:code', async (req, res) => {
  const code = req.params.code;
  console.log('\n[GET /e/' + code + '] Request from ' + req.ip);
  try {
    const result = await fetchAndDecrypt(code, false);
    res.json(result.data);
  } catch (e) {
    console.error('[GET /e/' + code + '] Error:', e.message);
    res.status(502).json({ error: e.message });
  }
});

// GET /d/{code} — Same
app.get('/d/:code', async (req, res) => {
  const code = req.params.code;
  console.log('\n[GET /d/' + code + '] Request from ' + req.ip);
  try {
    const result = await fetchAndDecrypt(code, false);
    res.json(result.data);
  } catch (e) {
    console.error('[GET /d/' + code + '] Error:', e.message);
    res.status(502).json({ error: e.message });
  }
});

// GET /debug/{code} — Full debug info with every network request/response
app.get('/debug/:code', async (req, res) => {
  const code = req.params.code;
  console.log('\n[GET /debug/' + code + '] Request from ' + req.ip);
  try {
    const result = await fetchAndDecrypt(code, true);
    res.json({
      success: true,
      ...result.debug,
      decrypted: result.data,
    });
  } catch (e) {
    console.error('[GET /debug/' + code + '] Error:', e.message);
    res.status(502).json({
      success: false,
      error: e.message,
      stack: e.stack,
      code,
      timestamp: new Date().toISOString(),
      note: 'Share this full JSON response for analysis',
    });
  }
});

// POST /decrypt — Decrypt raw AES-GCM payload (manual)
app.post('/decrypt', (req, res) => {
  try {
    const pb = req.body.playback || req.body;
    if (!pb.key_parts || !pb.iv || !pb.payload) {
      return res.status(400).json({ error: 'Missing key_parts, iv, or payload' });
    }
    const key = concatKeyParts(pb.key_parts);
    const decrypted = decryptPayload(pb);
    res.json(decrypted);
  } catch (e) {
    res.status(400).json({ error: 'Decrypt failed: ' + e.message });
  }
});

// GET /proxy?url=<URL> — Proxy .ts/.m3u8 segments through VPS
// This solves the ASN/Referer issue — segments are fetched from VPS
app.get('/proxy', (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) {
    return res.status(400).json({ error: 'Missing ?url= parameter' });
  }

  // Validate URL
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  if (!['https:', 'http:'].includes(parsed.protocol)) {
    return res.status(400).json({ error: 'Only http/https URLs allowed' });
  }

  const client = parsed.protocol === 'https:' ? https : http;

  const proxyReq = client.request(targetUrl, {
    method: 'GET',
    headers: {
      'User-Agent': UA,
      'Accept': '*/*, video/mp4, application/vnd.apple.mpegurl',
      'Accept-Language': 'en-US,en;q=0.9',
      'Referer': 'https://f75s.com/',
      'Origin': 'https://f75s.com',
    },
  }, (proxyRes) => {
    // Forward headers
    const contentType = proxyRes.headers['content-type'];
    if (contentType) res.set('Content-Type', contentType);
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Access-Control-Expose-Headers', 'Content-Length');

    // Handle range requests
    const range = proxyRes.headers['content-range'];
    if (range) res.set('Content-Range', range);

    // Stream response
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (e) => {
    console.error('[proxy] Error fetching ' + targetUrl + ':', e.message);
    if (!res.headersSent) {
      res.status(502).json({ error: 'Proxy fetch failed: ' + e.message, url: targetUrl });
    }
  });

  proxyReq.end();
});

// GET /rewrite?url=<m3u8-url> — Rewrite m3u8 to use /proxy for all segments
app.get('/rewrite', async (req, res) => {
  const m3u8Url = req.query.url;
  if (!m3u8Url) return res.status(400).json({ error: 'Missing ?url= parameter' });

  const proxyBase = req.protocol + '://' + req.get('host');

  try {
    const client = new URL(m3u8Url).protocol === 'https:' ? https : http;
    const m3u8Body = await new Promise((resolve, reject) => {
      client.get(m3u8Url, { headers: { 'User-Agent': UA, 'Referer': 'https://f75s.com/' } }, (resp) => {
        let data = '';
        resp.on('data', chunk => data += chunk);
        resp.on('end', () => resolve(data));
        resp.on('error', reject);
      }).on('error', reject);
    });

    // Rewrite relative URLs to use proxy
    const baseUrl = m3u8Url.substring(0, m3u8Url.lastIndexOf('/') + 1);
    const rewritten = m3u8Body.split('\n').map(line => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) return line;
      if (trimmed.startsWith('http')) {
        return proxyBase + '/proxy?url=' + encodeURIComponent(trimmed);
      }
      // Relative URL
      return proxyBase + '/proxy?url=' + encodeURIComponent(baseUrl + trimmed);
    }).join('\n');

    res.set('Content-Type', 'application/vnd.apple.mpegurl');
    res.set('Access-Control-Allow-Origin', '*');
    res.send(rewritten);
  } catch (e) {
    res.status(502).json({ error: 'Rewrite failed: ' + e.message });
  }
});

// GET /health — Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    browser: browser ? 'connected' : 'not running',
    timestamp: new Date().toISOString(),
  });
});

// ─── Start Server ───────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log('═══════════════════════════════════════════════════');
  console.log('  Video Decryptor running on port ' + PORT);
  console.log('═══════════════════════════════════════════════════');
  console.log('');
  console.log('  Routes:');
  console.log('    GET  /e/{code}          → Decrypt + return JSON');
  console.log('    GET  /d/{code}          → Same');
  console.log('    GET  /debug/{code}      → Full debug info');
  console.log('    POST /decrypt           → Decrypt raw payload');
  console.log('    GET  /proxy?url=<URL>   → Proxy segments');
  console.log('    GET  /rewrite?url=<URL> → Rewrite m3u8 via proxy');
  console.log('    GET  /health            → Health check');
  console.log('');
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\nShutting down...');
  if (browser) {
    try { await browser.close(); } catch (e) {}
  }
  process.exit(0);
});

process.on('uncaughtException', (e) => {
  console.error('[uncaughtException]', e.message);
});
