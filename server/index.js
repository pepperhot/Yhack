'use strict';

require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const session   = require('express-session');
const path      = require('path');
const os        = require('os');
const { nanoid } = require('nanoid');
const rateLimit  = require('express-rate-limit');
const { runScan }    = require('./scanManager');
const { createUser, loginUser } = require('./auth');

const app      = express();
const PORT     = process.env.PORT || 5050;
const NODE_ENV = process.env.NODE_ENV || 'development';

// ─── In-memory scan store (no native SQLite dependency) ───────────────────────
const scans = new Map(); // scanId → scan object

function createScan(id, target, email) {
  const scan = {
    id,
    target,
    email:        email || null,
    status:       'queued',
    results:      null,
    lines:        [],
    created_at:   new Date().toISOString(),
    completed_at: null,
    duration_ms:  null,
  };
  scans.set(id, scan);
  return scan;
}

function getScan(id) {
  return scans.get(id) || null;
}

function updateScan(id, fields) {
  const scan = scans.get(id);
  if (scan) Object.assign(scan, fields);
}

// Cleanup: remove scans older than TTL
function cleanupOldScans() {
  const maxScans = parseInt(process.env.MAX_SCANS_MEMORY || '500');
  const ttlHours = Number.isFinite(parseInt(process.env.SCAN_TTL_HOURS))
    ? parseInt(process.env.SCAN_TTL_HOURS) : 24;
  const cutoff = Date.now() - ttlHours * 3600 * 1000;

  for (const [id, scan] of scans.entries()) {
    if (new Date(scan.created_at).getTime() < cutoff) scans.delete(id);
  }
  // Hard cap
  if (scans.size > maxScans) {
    const sorted = [...scans.entries()].sort((a, b) =>
      new Date(a[1].created_at) - new Date(b[1].created_at));
    sorted.slice(0, scans.size - maxScans).forEach(([id]) => scans.delete(id));
  }
}

// ─── Session ─────────────────────────────────────────────────────────────────
app.use(session({
  secret: process.env.SESSION_SECRET || 'yhack-dev-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  },
}));

function requireAuth(req, res, next) {
  if (!req.session?.user) return res.status(401).json({ error: 'Non authentifié' });
  next();
}

// ─── Middleware ───────────────────────────────────────────────────────────────
const corsOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map(s => s.trim())
  : null;

app.use(cors({
  origin: corsOrigins
    ? (origin, cb) => {
        if (!origin || corsOrigins.includes(origin)) cb(null, true);
        else cb(new Error('CORS not allowed'));
      }
    : true, // reflect origin — works behind nginx, Docker, or direct access
  credentials: true,
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, '../')));

// ─── Auth routes ─────────────────────────────────────────────────────────────
app.post('/api/auth/register', (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'Email invalide' });
    const user = createUser(email, password);
    req.session.user = user;
    res.json({ user });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });
    const user = loginUser(email, password);
    req.session.user = user;
    res.json({ user });
  } catch (e) {
    res.status(401).json({ error: e.message });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session?.user) return res.status(401).json({ error: 'Non authentifié' });
  res.json({ user: req.session.user });
});

// ─── Rate limiting ────────────────────────────────────────────────────────────
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max:      parseInt(process.env.MAX_REQUESTS_PER_MINUTE || '5'),
  message:  'Trop de scans lancés. Attendez une minute.',
  standardHeaders: true,
  legacyHeaders:   false,
});

// ─── URL validation + SSRF protection ────────────────────────────────────────
function validateURL(targetUrl) {
  if (!targetUrl || typeof targetUrl !== 'string') throw new Error('URL manquante');

  let normalized = targetUrl.trim();
  if (!normalized.startsWith('http://') && !normalized.startsWith('https://'))
    normalized = 'https://' + normalized;

  let url;
  try { url = new URL(normalized); }
  catch (e) { throw new Error(`URL invalide: ${e.message}`); }

  const h = url.hostname;
  const blocked = [
    /^localhost$/i,
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^192\.168\./,
    /^169\.254\./,
    /^0\.0\.0\.0$/,
    /^::1$/,
    /^fc00:/i,
    /^fe80:/i,
  ];

  if (blocked.some(r => r.test(h)))
    throw new Error('SSRF protection: les IPs/hôtes privés ne sont pas autorisés');

  return url;
}

// ─── POST /api/scan ───────────────────────────────────────────────────────────
app.post('/api/scan', requireAuth, scanLimiter, async (req, res) => {
  try {
    const { targetUrl, email } = req.body || {};

    let url;
    try { url = validateURL(targetUrl); }
    catch (e) {
      console.error('[API] URL validation failed:', e.message);
      return res.status(400).json({ error: e.message });
    }

    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'Email invalide' });

    const scanId    = nanoid(12);
    const startTime = Date.now();
    createScan(scanId, url.href, email);

    console.log('[API] Scan started', { scanId, target: url.href });

    // Fire-and-forget: scanManager writes lines directly via the db-like shim
    runScan(url, email, scanId, {
      prepare: () => ({
        get: (id) => {
          const s = getScan(id);
          return s ? { lines: JSON.stringify(s.lines) } : null;
        },
        run: (linesJson, id) => {
          const s = getScan(id);
          if (s) {
            try { s.lines = JSON.parse(linesJson); } catch (_) {}
          }
        },
      }),
    })
      .then(results => {
        updateScan(scanId, {
          status:       'done',
          results,
          duration_ms:  Date.now() - startTime,
          completed_at: new Date().toISOString(),
        });
        console.log('[API] Scan done', { scanId, duration: Date.now() - startTime + 'ms' });
      })
      .catch(err => {
        updateScan(scanId, {
          status:       'error',
          results:      { error: err.message || String(err) },
          duration_ms:  Date.now() - startTime,
          completed_at: new Date().toISOString(),
        });
        console.error('[API] Scan error', { scanId, error: err.message });
      });

    res.json({ scanId });
  } catch (e) {
    console.error('[API] Server error:', e.message);
    res.status(500).json({ error: 'Erreur serveur interne' });
  }
});

// ─── GET /api/scan/:id ────────────────────────────────────────────────────────
app.get('/api/scan/:id', (req, res) => {
  const scanId = req.params.id;
  if (!/^[A-Za-z0-9_-]{12}$/.test(scanId))
    return res.status(400).json({ error: 'ID de scan invalide' });

  const scan = getScan(scanId);
  if (!scan) return res.status(404).json({ error: 'Scan introuvable' });

  res.json({
    id:           scan.id,
    status:       scan.status,
    target:       scan.target,
    lines:        scan.lines,
    results:      scan.results,
    duration_ms:  scan.duration_ms,
    created_at:   scan.created_at,
    completed_at: scan.completed_at,
  });
});

// ─── Graceful shutdown ────────────────────────────────────────────────────────
process.on('SIGINT', () => {
  console.log('\n[API] Shutting down...');
  process.exit(0);
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  cleanupOldScans();

  let myIp = 'localhost';
  for (const ifaces of Object.values(os.networkInterfaces())) {
    const ipv4 = (ifaces || []).find(i => i.family === 'IPv4' && !i.internal);
    if (ipv4) { myIp = ipv4.address; break; }
  }

  console.log(`\n[yhack] Serveur de sécurité démarré`);
  console.log(`- Mode:   ${NODE_ENV}`);
  console.log(`- Local:  http://localhost:${PORT}`);
  console.log(`- Réseau: http://${myIp}:${PORT}\n`);
});
