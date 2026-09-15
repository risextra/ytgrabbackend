require('dotenv').config();

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { Readable } = require('stream');
const { pipeline } = require('stream/promises');

const app = express();

// ========== CORS FIX ==========
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));
app.options('*', cors());
// ==============================

app.use(express.json({ limit: '1mb' }));

const COOKIES_PATH = path.join(__dirname, 'cookies.txt');
const FALLBACK_CLIENTS = ['ANDROID', 'IOS', 'MWEB', 'TV_EMBEDDED', 'WEB'];
const AUTH_COOKIE_NAMES = ['SID', 'HSID', 'SSID', 'SAPISID', 'APISID', '__Secure-1PSID', '__Secure-3PSID', 'LOGIN_INFO'];

// ------------------------------------------------------------------
// Cookie loading — only youtube.com/google.com, warns if no real
// sign-in cookies are present
// ------------------------------------------------------------------
function loadCookieHeader() {
  if (!fs.existsSync(COOKIES_PATH)) return null;

  const raw = fs.readFileSync(COOKIES_PATH, 'utf8');
  const pairs = [];

  for (let line of raw.split('\n')) {
    line = line.trim();
    if (!line) continue;
    if (line.startsWith('#') && !line.startsWith('#HttpOnly_')) continue;

    const cleaned = line.startsWith('#HttpOnly_') ? line.slice('#HttpOnly_'.length) : line;
    const fields = cleaned.split('\t');
    if (fields.length < 7) continue;

    const domain = fields[0];
    if (!domain.endsWith('youtube.com') && !domain.endsWith('.google.com')) continue;

    const name = fields[5];
    const value = fields[6];
    if (name) pairs.push(`${name}=${value}`);
  }

  if (!pairs.length) return null;

  const hasAuth = pairs.some(p => AUTH_COOKIE_NAMES.some(n => p.startsWith(n + '=')));
  if (!hasAuth) {
    console.log('⚠️  cookies.txt has YouTube cookies but none are sign-in cookies. Anonymous session.');
  }

  return pairs.join('; ');
}

// ------------------------------------------------------------------
// youtubei.js singleton
// ------------------------------------------------------------------
let yt = null;
let ytInitPromise = null;

async function getYt() {
  if (yt) return yt;
  if (ytInitPromise) return ytInitPromise;

  ytInitPromise = (async () => {
    const { Innertube, UniversalCache, Platform } = await import('youtubei.js');

    Platform.shim.eval = async (data, env) => {
      const properties = [];
      if (env?.n) {
        properties.push(`n: exportedVars.nFunction("${env.n}")`);
      }
      if (env?.sig) {
        properties.push(`sig: exportedVars.sigFunction("${env.sig}")`);
      }
      const code = `${data.output}\nreturn { ${properties.join(', ')} }`;
      return new Function(code)();
    };

    const cookie = loadCookieHeader();
    if (cookie) {
      console.log('🍪 cookies.txt loaded — using authenticated session');
    } else {
      console.log('⚠️  No usable YouTube cookies found — running unauthenticated');
    }

    yt = await Innertube.create({
      cache: new UniversalCache(false),
      generate_session_locally: true,
      cookie: cookie || undefined,
    });

    console.log('✅ youtubei.js ready');
    return yt;
  })();

  try {
    return await ytInitPromise;
  } catch (err) {
    ytInitPromise = null;
    throw err;
  }
}

// ------------------------------------------------------------------
// PO Token minter — generates per-video BotGuard-attested tokens.
// This is a reverse-engineered reimplementation of a Google
// anti-abuse mechanism (via the bgutils-js library) — best-effort,
// not guaranteed, and may need re-tuning if YouTube changes things.
// If setup fails for any reason, we log it and the app keeps running,
// falling back to the plain client-cascade approach.
// ------------------------------------------------------------------
let poTokenMinter = null;
let poTokenSetupAttempted = false;

async function setupPoTokenMinter(innertube) {
  if (poTokenMinter) return poTokenMinter;
  if (poTokenSetupAttempted) return null;
  poTokenSetupAttempted = true;

  try {
    const { BG, buildURL, GOOG_API_KEY, USER_AGENT } = await import('bgutils-js');
    const { JSDOM } = await import('jsdom');

    // NOTE: this mutates Node's global scope (globalThis.window/document/
    // navigator) once, for the lifetime of the process, so BotGuard's
    // reverse-engineered VM code sees a browser-like environment. Done
    // only once, guarded above, since this process only does this one job.
    const dom = new JSDOM(
      '<!DOCTYPE html><html lang="en"><head><title></title></head><body></body></html>',
      { url: 'https://www.youtube.com/', referrer: 'https://www.youtube.com/', userAgent: USER_AGENT }
    );

    Object.assign(globalThis, {
      window: dom.window,
      document: dom.window.document,
      location: dom.window.location,
      origin: dom.window.origin,
    });
    if (!Reflect.has(globalThis, 'navigator')) {
      Object.defineProperty(globalThis, 'navigator', { value: dom.window.navigator });
    }

    const challengeResponse = await innertube.getAttestationChallenge('ENGAGEMENT_TYPE_UNBOUND');
    if (!challengeResponse.bg_challenge) throw new Error('No bg_challenge in response');

    const interpreterUrl = challengeResponse.bg_challenge.interpreter_url.private_do_not_access_or_else_trusted_resource_url_wrapped_value;
    const bgScriptResponse = await fetch(`https:${interpreterUrl}`);
    const interpreterJavascript = await bgScriptResponse.text();
    if (!interpreterJavascript) throw new Error('Could not load BotGuard VM script');
    new Function(interpreterJavascript)();

    const botguard = await BG.BotGuardClient.create({
      program: challengeResponse.bg_challenge.program,
      globalName: challengeResponse.bg_challenge.global_name,
      globalObj: globalThis,
    });

    const webPoSignalOutput = [];
    const botguardResponse = await botguard.snapshot({ webPoSignalOutput });
    const requestKey = 'O43z0dpjhgX20SCx4KAo'; // public constant used by all bgutils-js consumers

    const integrityTokenResponse = await fetch(buildURL('GenerateIT', true), {
      method: 'POST',
      headers: {
        'content-type': 'application/json+protobuf',
        'x-goog-api-key': GOOG_API_KEY,
        'x-user-agent': 'grpc-web-javascript/0.1',
        'user-agent': USER_AGENT,
      },
      body: JSON.stringify([requestKey, botguardResponse]),
    });

    const response = await integrityTokenResponse.json();
    if (typeof response[0] !== 'string') throw new Error('Could not get integrity token');

    poTokenMinter = await BG.WebPoMinter.create({ integrityToken: response[0] }, webPoSignalOutput);
    console.log('✅ PO token minter ready');
    return poTokenMinter;
  } catch (err) {
    console.log('⚠️  PO token setup failed, continuing without it:', err.message);
    return null;
  }
}

async function mintPoToken(innertube, videoId) {
  const minter = await setupPoTokenMinter(innertube);
  if (!minter) return null;
  try {
    return await minter.mintAsWebsafeString(videoId);
  } catch (err) {
    console.log(`⚠️  Failed to mint PO token for ${videoId}:`, err.message);
    return null;
  }
}

// ------------------------------------------------------------------
// URL parsing
// ------------------------------------------------------------------
function extractVideoId(url) {
  if (!url) return null;
  const trimmed = String(url).trim();

  if (/^[a-zA-Z0-9_-]{11}$/.test(trimmed)) return trimmed;

  try {
    const u = new URL(trimmed);
    if (u.hostname.includes('youtu.be')) {
      return u.pathname.slice(1).split(/[?/]/)[0] || null;
    }
    if (u.searchParams.has('v')) return u.searchParams.get('v');
    const parts = u.pathname.split('/').filter(Boolean);
    if (['shorts', 'embed', 'v', 'live'].includes(parts[0])) {
      return parts[1]?.split('?')[0] || null;
    }
  } catch (_) {}

  return null;
}

// ------------------------------------------------------------------
// Timeout wrapper
// ------------------------------------------------------------------
function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`${label} timed out after ${ms / 1000}s`)), ms)
    )
  ]);
}

async function fetchInfo(innertube, videoId) {
  try {
    return await withTimeout(innertube.getBasicInfo(videoId), 15000, 'getBasicInfo');
  } catch (e) {
    console.log('getBasicInfo failed/timed out, trying getInfo...', e.message);
    return await withTimeout(innertube.getInfo(videoId), 15000, 'getInfo');
  }
}

// ------------------------------------------------------------------
// Download — tries WEB+PO-token first, then falls back to the
// plain client cascade without a token.
// ------------------------------------------------------------------
async function downloadProgressive(innertube, videoId, quality) {
  const qualitiesToTry = quality === 'best' ? ['best'] : [quality, 'best'];
  let lastErr;

  const poToken = await mintPoToken(innertube, videoId);
  if (poToken) {
    for (const q of qualitiesToTry) {
      try {
        const stream = await withTimeout(
          innertube.download(videoId, { type: 'video+audio', quality: q, format: 'any', client: 'WEB', po_token: poToken }),
          20000,
          `download(WEB+PO, ${q})`
        );
        console.log(`✅ Got stream via client=WEB+PO quality=${q}`);
        return { stream, client: 'WEB+PO', actualQuality: q };
      } catch (err) {
        lastErr = err;
        console.log(`❌ client=WEB+PO quality=${q} failed: ${err.message}`);
      }
    }
  }

  for (const q of qualitiesToTry) {
    for (const client of FALLBACK_CLIENTS) {
      try {
        const stream = await withTimeout(
          innertube.download(videoId, { type: 'video+audio', quality: q, format: 'any', client }),
          20000,
          `download(${client}, ${q})`
        );
        console.log(`✅ Got stream via client=${client} quality=${q}`);
        return { stream, client, actualQuality: q };
      } catch (err) {
        lastErr = err;
        console.log(`❌ client=${client} quality=${q} failed: ${err.message}`);
      }
    }
  }

  throw lastErr || new Error('No matching formats found on any client');
}

async function downloadAudio(innertube, videoId) {
  let lastErr;

  const poToken = await mintPoToken(innertube, videoId);
  if (poToken) {
    try {
      const stream = await withTimeout(
        innertube.download(videoId, { type: 'audio', quality: 'best', format: 'any', client: 'WEB', po_token: poToken }),
        20000,
        `download-audio(WEB+PO)`
      );
      console.log(`✅ Got audio stream via client=WEB+PO`);
      return { stream, client: 'WEB+PO' };
    } catch (err) {
      lastErr = err;
      console.log(`❌ audio client=WEB+PO failed: ${err.message}`);
    }
  }

  for (const client of FALLBACK_CLIENTS) {
    try {
      const stream = await withTimeout(
        innertube.download(videoId, { type: 'audio', quality: 'best', format: 'any', client }),
        20000,
        `download-audio(${client})`
      );
      console.log(`✅ Got audio stream via client=${client}`);
      return { stream, client };
    } catch (err) {
      lastErr = err;
      console.log(`❌ audio client=${client} failed: ${err.message}`);
    }
  }
  throw lastErr || new Error('No matching audio formats found on any client');
}

// ------------------------------------------------------------------
// POST /api/info
// ------------------------------------------------------------------
app.post('/api/info', async (req, res) => {
  const { url } = req.body || {};
  console.log('📡 Fetching info for:', url);

  if (!url) return res.status(400).json({ error: 'No URL provided' });

  try {
    const videoId = extractVideoId(url);
    if (!videoId) return res.status(400).json({ error: 'Invalid YouTube URL' });

    const innertube = await getYt();
    const info = await fetchInfo(innertube, videoId);

    const basic = info.basic_info || info;
    const title = basic.title || 'Unknown Title';
    const channel = basic.author || basic.channel?.name || 'Unknown';
    const duration = basic.duration || 0;
    const thumbnail =
      basic.thumbnail?.[0]?.url ||
      (Array.isArray(basic.thumbnail) ? basic.thumbnail.at(-1)?.url : '') ||
      '';

    const formats = [
      { format_id: 'best', resolution: 'Best Quality (recommended)', ext: 'mp4' },
      { format_id: '720', resolution: '720p (if available)', ext: 'mp4' },
      { format_id: '360', resolution: '360p', ext: 'mp4' },
      { format_id: 'audio', resolution: 'Audio Only', ext: 'm4a' },
    ];

    res.json({ title, thumbnail, duration, formats, channel, videoId });
  } catch (err) {
    console.error('Info error:', err.message);
    res.status(500).json({
      error: 'Failed to fetch video info',
      details: (err.message || String(err)).slice(0, 600),
    });
  }
});

// ------------------------------------------------------------------
// POST /api/download
// ------------------------------------------------------------------
app.post('/api/download', async (req, res) => {
  const { url, formatId } = req.body || {};
  console.log('📥 Downloading:', url, 'Format:', formatId);

  if (!url || !formatId) {
    return res.status(400).json({ error: 'URL and format ID required' });
  }

  const videoId = extractVideoId(url);
  if (!videoId) return res.status(400).json({ error: 'Invalid YouTube URL' });

  try {
    const innertube = await getYt();

    let webStream, ext, contentType;

    if (formatId === 'audio') {
      const result = await downloadAudio(innertube, videoId);
      webStream = result.stream;
      ext = 'm4a';
      contentType = 'audio/mp4';
    } else {
      const requestedQuality = formatId === 'best' ? 'best' : formatId + 'p';
      const result = await downloadProgressive(innertube, videoId, requestedQuality);
      webStream = result.stream;
      ext = 'mp4';
      contentType = 'video/mp4';
      if (result.actualQuality !== requestedQuality) {
        console.log(`Served ${result.actualQuality} instead of requested ${requestedQuality}`);
      }
    }

    const nodeStream = Readable.fromWeb(webStream);
    const safeName = `ytgrab_${videoId}_${Date.now()}.${ext}`;

    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);

    await pipeline(nodeStream, res);
  } catch (err) {
    console.error('Download error:', err.message);
    if (!res.headersSent) {
      res.status(500).json({
        error: 'Download failed',
        details: (err.message || String(err)).slice(0, 600),
      });
    } else {
      res.destroy();
    }
  }
});

// ------------------------------------------------------------------
// Health check
// ------------------------------------------------------------------
app.get('/api/health', async (req, res) => {
  let ytReady = false;
  let ytError = null;
  try {
    await getYt();
    ytReady = true;
  } catch (e) {
    ytError = e.message;
  }

  res.json({
    ok: true,
    platform: process.platform,
    nodeVersion: process.version,
    engine: 'youtubei.js',
    ytReady,
    ytError,
    cookiesLoaded: !!loadCookieHeader(),
    poTokenReady: !!poTokenMinter,
  });
});

app.get('/', (req, res) => {
  res.json({ service: 'ytgrab4k', engine: 'youtubei.js', status: 'running' });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (!res.headersSent) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || '0.0.0.0';

app.listen(PORT, HOST, () => {
  console.log(`🚀 Backend running on ${HOST}:${PORT}`);
  console.log(`📦 Engine: youtubei.js`);
  console.log(`🌍 Node: ${process.version}`);
});

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled promise rejection:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
});  look now it's fine