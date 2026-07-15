'use strict';

require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const session   = require('express-session');
const path      = require('path');
const os        = require('os');
const { nanoid } = require('nanoid');
const rateLimit  = require('express-rate-limit');
const dns        = require('dns').promises;
const https      = require('https');
const fetch      = require('node-fetch');
const { pool, rawDb, init, isAvailable } = require('./db');
const { runScan }    = require('./scanManager');
const { createUser, loginUser } = require('./auth');
const admin = require('./admin');

// Agent tolérant aux certificats invalides pour la vérification de domaine par fichier.
const insecureAgent = new https.Agent({ rejectUnauthorized: false });

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

async function createScan(id, target, email, userId, mode) {
  const scan = {
    id,
    user_id:      userId || null,
    target,
    email:        email || null,
    mode:         mode || 'passive',
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
      'INSERT INTO scans (id, user_id, target, email, mode, status) VALUES ($1, $2, $3, $4, $5, $6)',
      [id, userId || null, target, email || null, mode || 'passive', 'queued'],
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

// SÉCURITÉ ADMIN : masque la page /admin et l'API admin hors IP autorisées (404).
app.use(admin.adminIpGuard);

// La page d'admin n'est servie qu'aux IP autorisées (grâce au garde ci-dessus).
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, '..', 'admin.html')));

app.use(express.static(path.join(__dirname, '../'), { dotfiles: 'deny' }));

// API d'administration (routes durcies : voir server/admin.js).
app.use('/api/admin', admin.router);

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

// ─── Vérification de propriété de domaine ────────────────────────────────────
// Nettoie une saisie (URL, sous-domaine, majuscules…) en un domaine simple.
function normalizeDomain(input) {
  if (!input || typeof input !== 'string') return null;
  let d = input.trim().toLowerCase();
  d = d.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
  d = d.replace(/^www\./, '');
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(d)) return null;
  return d;
}

// Un domaine vérifié couvre lui-même et tous ses sous-domaines.
function domainCovers(verified, hostname) {
  hostname = (hostname || '').toLowerCase().replace(/^www\./, '');
  return hostname === verified || hostname.endsWith('.' + verified);
}

// Vérifie la propriété via TXT DNS (netguard-verify=<token>) ou fichier
// /.well-known/netguard-verify.txt. Retourne 'dns' | 'file' | null.
async function checkDomainOwnership(domain, token) {
  try {
    const txt = (await dns.resolveTxt(domain)).flat().join(' ');
    if (txt.includes(token)) return 'dns';
  } catch (_) {}
  for (const proto of ['https', 'http']) {
    try {
      const ctrl  = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 6000);
      const r = await fetch(`${proto}://${domain}/.well-known/netguard-verify.txt`, {
        signal: ctrl.signal,
        agent: u => (u.protocol === 'https:' ? insecureAgent : undefined),
      }).finally(() => clearTimeout(timer));
      if (r.ok) { const t = await r.text(); if (t.includes(token)) return 'file'; }
    } catch (_) {}
  }
  return null;
}

// Ajouter un domaine à vérifier → renvoie le token + les instructions.
app.post('/api/domains', requireAuth, async (req, res) => {
  const domain = normalizeDomain((req.body || {}).domain);
  if (!domain) return res.status(400).json({ error: 'Domaine invalide' });
  const userId = req.session.user.id;

  const existing = (await pool.query(
    'SELECT * FROM verified_domains WHERE user_id = $1 AND domain = $2', [userId, domain])).rows[0];
  let row = existing;
  if (!row) {
    const id    = nanoid(12);
    const token = 'netguard-verify-' + nanoid(24);
    await pool.query(
      'INSERT INTO verified_domains (id, user_id, domain, token) VALUES ($1, $2, $3, $4)',
      [id, userId, domain, token]);
    row = { id, domain, token, verified: 0 };
  }
  res.json({
    domain: { id: row.id, domain: row.domain, token: row.token, verified: !!row.verified },
    instructions: {
      dns:  `Ajoutez un enregistrement TXT sur ${row.domain} avec la valeur : ${row.token}`,
      file: `Déposez le fichier https://${row.domain}/.well-known/netguard-verify.txt contenant : ${row.token}`,
    },
  });
});

app.get('/api/domains', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, domain, token, verified, method, verified_at FROM verified_domains WHERE user_id = $1 ORDER BY created_at DESC',
    [req.session.user.id]);
  res.json({ domains: rows.map(r => ({ ...r, verified: !!r.verified })) });
});

app.post('/api/domains/:id/verify', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM verified_domains WHERE id = $1 AND user_id = $2', [req.params.id, req.session.user.id]);
  const row = rows[0];
  if (!row) return res.status(404).json({ error: 'Domaine introuvable' });
  if (row.verified) return res.json({ verified: true, method: row.method });

  const method = await checkDomainOwnership(row.domain, row.token);
  if (!method) return res.status(400).json({
    error: 'Preuve introuvable. Vérifiez le TXT DNS ou le fichier, puis réessayez (la propagation DNS peut prendre quelques minutes).',
  });

  await pool.query(
    "UPDATE verified_domains SET verified = 1, method = $1, verified_at = datetime('now') WHERE id = $2",
    [method, row.id]);
  console.log('[DOMAIN] Verified', { domain: row.domain, userId: req.session.user.id, method });
  res.json({ verified: true, method });
});

app.delete('/api/domains/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM verified_domains WHERE id = $1 AND user_id = $2',
    [req.params.id, req.session.user.id]);
  res.json({ ok: true });
});

// Le domaine (parmi ceux de l'utilisateur) qui couvre ce hostname ET est vérifié.
async function verifiedDomainFor(userId, hostname) {
  const { rows } = await pool.query(
    'SELECT domain FROM verified_domains WHERE user_id = $1 AND verified = 1', [userId]);
  return rows.find(r => domainCovers(r.domain, hostname)) || null;
}

// ─── POST /api/scan ───────────────────────────────────────────────────────────
app.post('/api/scan', requireAuth, scanLimiter, async (req, res) => {
  try {
    const { targetUrl, email } = req.body || {};
    const mode = (req.body || {}).mode === 'active' ? 'active' : 'passive';

    let url;
    try { url = validateURL(targetUrl); }
    catch (e) {
      console.error('[API] URL validation failed:', e.message);
      return res.status(400).json({ error: e.message });
    }

    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'Email invalide' });

    const userId = req.session.user.id;

    // ── Bridage : un scan ACTIF exige un domaine dont la propriété est prouvée ─
    if (mode === 'active') {
      const owned = await verifiedDomainFor(userId, url.hostname);
      if (!owned)
        return res.status(403).json({
          error: 'Scan actif refusé : vous devez d\'abord prouver la propriété de ce domaine.',
          code: 'DOMAIN_NOT_VERIFIED',
        });
      // Trace d'audit : console + base (consultable dans l'interface admin).
      console.log('[AUTH-SCAN] Active scan authorized', {
        userId, ip: req.ip, target: url.href, domain: owned.domain, at: new Date().toISOString(),
      });
      admin.logAudit(req.session.user.email, 'scan.active', `${url.href} (domaine ${owned.domain})`, req.ip);
    }

    const scanId    = nanoid(12);
    const startTime = Date.now();
    await createScan(scanId, url.href, email, userId, mode);
    await updateScan(scanId, { status: 'running' });

    console.log('[API] Scan started', { scanId, target: url.href, userId, mode });

    // Callback de streaming : chaque ligne est poussée dans le store en mémoire.
    const emit = (line) => {
      const s = activeScans.get(scanId);
      if (s) s.lines.push(line);
    };

    runScan(url, email, scanId, emit, mode)
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
    `SELECT id, target, mode, status, duration_ms, created_at, completed_at
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
