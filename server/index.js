'use strict';

require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const session   = require('express-session');
const path      = require('path');
const os        = require('os');
const { nanoid } = require('nanoid');
const rateLimit  = require('express-rate-limit');
const { pool, rawDb, init, isAvailable } = require('./db');
const { runScan }    = require('./scanManager');
const { createUser, loginUser } = require('./auth');

const app      = express();
const PORT     = process.env.PORT || 5050;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Derrière un reverse proxy (Caddy/Nginx), on fait confiance au 1er proxy
// pour récupérer la vraie IP client (rate-limit) et le bon protocole (cookies secure).
app.set('trust proxy', 1);

// ─── Scan store ───────────────────────────────────────────────────────────────
// Active scans stay in memory for real-time line streaming.
// On completion they are flushed to PostgreSQL and evicted after 60 s.
const activeScans = new Map();

async function createScan(id, target, email, userId) {
  const scan = {
    id,
    user_id:      userId || null,
    target,
    email:        email || null,
    status:       'queued',
    results:      null,
    lines:        [],
    created_at:   new Date().toISOString(),
    completed_at: null,
    duration_ms:  null,
  };
  activeScans.set(id, scan);
  if (isAvailable()) {
    await pool.query(
      'INSERT INTO scans (id, user_id, target, email, status) VALUES ($1, $2, $3, $4, $5)',
      [id, userId || null, target, email || null, 'queued'],
    );
  }
  return scan;
}

async function getScan(id) {
  if (activeScans.has(id)) return activeScans.get(id);

  if (!isAvailable()) return null;

  const { rows } = await pool.query('SELECT * FROM scans WHERE id = $1', [id]);
  if (!rows[0]) return null;
  const r = rows[0];
  const parse = (v, d) => { try { return v ? JSON.parse(v) : d; } catch { return d; } };
  return {
    id:           r.id,
    user_id:      r.user_id,
    target:       r.target,
    email:        r.email,
    status:       r.status,
    results:      parse(r.results, null),
    lines:        parse(r.lines, []),
    created_at:   r.created_at,
    completed_at: r.completed_at,
    duration_ms:  r.duration_ms,
  };
}

async function updateScan(id, fields) {
  const scan = activeScans.get(id);
  if (scan) Object.assign(scan, fields);

  if (fields.status === 'done' || fields.status === 'error') {
    if (isAvailable()) {
      const s = scan || {};
      await pool.query(
        `UPDATE scans
            SET status=$1, results=$2, lines=$3, completed_at=$4, duration_ms=$5
          WHERE id=$6`,
        [s.status ?? null, JSON.stringify(s.results ?? null), JSON.stringify(s.lines || []),
         s.completed_at ?? null, s.duration_ms ?? null, id],
      );
    }
    setTimeout(() => activeScans.delete(id), 60_000);
  }
}

// ─── Session ─────────────────────────────────────────────────────────────────
// Sessions persistées dans SQLite (survivent aux redémarrages).
const SqliteStore = require('better-sqlite3-session-store')(session);

app.use(session({
  secret: process.env.SESSION_SECRET || 'netguard-dev-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  store: new SqliteStore({
    client: rawDb(),
    expired: { clear: true, intervalMs: 15 * 60 * 1000 },
  }),
  cookie: {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === 'true',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
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
    : true,
  credentials: true,
}));
app.use(express.json({ limit: '1mb' }));

// SÉCURITÉ : ne jamais servir la base de données ni des fichiers sensibles via HTTP.
// (le fichier SQLite vit sous la racine servie en statique).
app.use((req, res, next) => {
  if (/\.(db|db-wal|db-shm|sqlite)$/i.test(req.path) ||
      req.path.startsWith('/data/') ||
      /\.(env|log)$/i.test(req.path)) {
    return res.status(404).end();
  }
  next();
});

app.use(express.static(path.join(__dirname, '../'), { dotfiles: 'deny' }));

// ─── Health check ──────────────────────────────────────────────────────────────
// Utilisé par Docker / le reverse proxy / le monitoring. Ne nécessite pas d'auth.
app.get('/healthz', (req, res) => {
  res.json({
    status: 'ok',
    db:     'sqlite',
    uptime: Math.round(process.uptime()),
  });
});

// ─── Auth routes ─────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'Email invalide' });
    const user = await createUser(email, password);
    req.session.user = user;
    res.json({ user });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });
    const user = await loginUser(email, password);
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
// Limite par utilisateur connecté (fallback IP) — robuste derrière un proxy.
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max:      parseInt(process.env.MAX_REQUESTS_PER_MINUTE || '5'),
  message:  { error: 'Trop de scans lancés. Attendez une minute.' },
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator: (req) => req.session?.user?.id || req.ip,
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
    const userId    = req.session.user.id;
    const startTime = Date.now();
    await createScan(scanId, url.href, email, userId);
    await updateScan(scanId, { status: 'running' });

    console.log('[API] Scan started', { scanId, target: url.href, userId });

    // Callback de streaming : chaque ligne est poussée dans le store en mémoire.
    const emit = (line) => {
      const s = activeScans.get(scanId);
      if (s) s.lines.push(line);
    };

    runScan(url, email, scanId, emit)
      .then(async results => {
        await updateScan(scanId, {
          status:       'done',
          results,
          duration_ms:  Date.now() - startTime,
          completed_at: new Date().toISOString(),
        });
        console.log('[API] Scan done', { scanId, duration: Date.now() - startTime + 'ms' });
      })
      .catch(async err => {
        await updateScan(scanId, {
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

// ─── GET /api/scans — historique de l'utilisateur ──────────────────────────────
app.get('/api/scans', requireAuth, async (req, res) => {
  if (!isAvailable()) return res.json({ scans: [] });
  const { rows } = await pool.query(
    `SELECT id, target, status, duration_ms, created_at, completed_at
       FROM scans
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 50`,
    [req.session.user.id],
  );
  res.json({ scans: rows });
});

// ─── GET /api/scan/:id ────────────────────────────────────────────────────────
app.get('/api/scan/:id', requireAuth, async (req, res) => {
  const scanId = req.params.id;
  if (!/^[A-Za-z0-9_-]{12}$/.test(scanId))
    return res.status(400).json({ error: 'ID de scan invalide' });

  const scan = await getScan(scanId);
  if (!scan) return res.status(404).json({ error: 'Scan introuvable' });

  // Un utilisateur ne peut consulter que ses propres scans.
  if (scan.user_id && scan.user_id !== req.session.user.id)
    return res.status(403).json({ error: 'Accès refusé' });

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
process.on('SIGINT',  shutdown);
process.on('SIGTERM', shutdown);
async function shutdown() {
  console.log('\n[API] Shutting down...');
  await pool.end();
  process.exit(0);
}

// ─── Start ────────────────────────────────────────────────────────────────────
init()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      let myIp = 'localhost';
      for (const ifaces of Object.values(os.networkInterfaces())) {
        const ipv4 = (ifaces || []).find(i => i.family === 'IPv4' && !i.internal);
        if (ipv4) { myIp = ipv4.address; break; }
      }

      const dbMode = 'SQLite';
      console.log(`\n[netguard] Serveur de sécurité démarré`);
      console.log(`- Mode:   ${NODE_ENV}`);
      console.log(`- DB:     ${dbMode}`);
      console.log(`- Local:  http://localhost:${PORT}`);
      console.log(`- Réseau: http://${myIp}:${PORT}\n`);
    });
  })
  .catch(err => {
    console.error('[init] Erreur inattendue:', err.message);
  });
