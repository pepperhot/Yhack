'use strict';
/**
 * Interface d'administration — isolée et durcie.
 *
 * Modèle de sécurité (défense en profondeur) :
 *   1. L'admin est désigné par ADMIN_EMAIL dans .env — on ne devient JAMAIS
 *      admin via l'application. Modifier la base ne suffit pas.
 *   2. Restriction par IP : si ADMIN_ALLOWED_IPS est défini, toute route admin
 *      (et la page /admin) répond 404 hors de ces IP — l'admin est invisible ailleurs.
 *   3. Élévation à durée limitée : il faut se ré-authentifier (email + mot de passe
 *      du compte admin) ; l'accès expire après ADMIN_ELEVATION_TTL_MIN minutes.
 *   4. Chaque action admin est journalisée dans audit_log.
 */
const express  = require('express');
const path     = require('path');
const fs       = require('fs');
const { nanoid } = require('nanoid');
const rateLimit  = require('express-rate-limit');
const { pool, DB_PATH } = require('./db');
const { loginUser, setPassword } = require('./auth');

const ADMIN_EMAIL   = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const ELEVATION_TTL = parseInt(process.env.ADMIN_ELEVATION_TTL_MIN || '15', 10) * 60 * 1000;

// ── Utilitaires ────────────────────────────────────────────────────────────
// Normalise une IP (retire le préfixe IPv6-mapped ::ffff:).
function normIp(ip) { return (ip || '').replace(/^::ffff:/, ''); }

function allowedIps() {
  return (process.env.ADMIN_ALLOWED_IPS || '')
    .split(',').map(s => s.trim()).filter(Boolean);
}

// Restriction IP : true si autorisé. Liste vide = restriction inactive.
function ipAllowed(req) {
  const list = allowedIps();
  if (!list.length) return true;
  return list.includes(normIp(req.ip));
}

function isAdminAccount(req) {
  const email = req.session?.user?.email;
  return !!ADMIN_EMAIL && !!email && email.toLowerCase() === ADMIN_EMAIL;
}

function isElevated(req) {
  const t = req.session?.adminElevatedAt;
  return !!t && (Date.now() - t) < ELEVATION_TTL;
}

async function logAudit(actor, action, detail, ip) {
  try {
    await pool.query(
      'INSERT INTO audit_log (id, actor, action, detail, ip) VALUES ($1,$2,$3,$4,$5)',
      [nanoid(12), actor || null, action, detail || null, normIp(ip) || null]);
  } catch (e) { console.error('[AUDIT] échec écriture:', e.message); }
}

// ── Middlewares ──────────────────────────────────────────────────────────────
// Garde à poser AVANT le statique et les routes : masque l'admin hors IP autorisées.
function adminIpGuard(req, res, next) {
  const p = req.path;
  if (p === '/admin' || p === '/admin.html' || p.startsWith('/api/admin')) {
    if (!ADMIN_EMAIL || !ipAllowed(req)) return res.status(404).end();
  }
  next();
}

// Exige un accès admin élevé et valide.
function requireAdmin(req, res, next) {
  if (!ADMIN_EMAIL || !ipAllowed(req)) return res.status(404).end();
  if (!req.session?.user)  return res.status(401).json({ error: 'Non authentifié' });
  if (!isAdminAccount(req)) return res.status(403).json({ error: 'Accès refusé' });
  if (!isElevated(req))    return res.status(401).json({ error: 'Ré-authentification requise', code: 'ELEVATION_REQUIRED' });
  next();
}

// ── Routeur ────────────────────────────────────────────────────────────────
const router = express.Router();

// Anti-bruteforce sur le login admin.
const adminLoginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: { error: 'Trop de tentatives. Réessayez dans 10 minutes.' },
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => normIp(req.ip),
});

// État courant (pour que l'UI sache quoi afficher). Ne révèle rien de sensible.
router.get('/session', (req, res) => {
  res.json({
    loggedIn: !!req.session?.user,
    isAdmin:  isAdminAccount(req),
    elevated: isAdminAccount(req) && isElevated(req),
    email:    isAdminAccount(req) ? req.session.user.email : null,
    ttlMin:   Math.round(ELEVATION_TTL / 60000),
  });
});

// Login admin dédié : email + mot de passe du compte ADMIN_EMAIL → élévation.
router.post('/login', adminLoginLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  const em = (email || '').trim().toLowerCase();
  // Message générique volontaire : ne révèle pas si l'email est l'admin.
  const deny = () => res.status(403).json({ error: 'Identifiants invalides' });
  if (!ADMIN_EMAIL || !em || !password || em !== ADMIN_EMAIL) {
    await logAudit(em || '?', 'admin.login.fail', 'email non-admin ou vide', req.ip);
    return deny();
  }
  try {
    const user = await loginUser(email, password);
    req.session.user = user;
    req.session.adminElevatedAt = Date.now();
    await logAudit(user.email, 'admin.login.ok', null, req.ip);
    res.json({ ok: true });
  } catch (_) {
    await logAudit(em, 'admin.login.fail', 'mot de passe invalide', req.ip);
    deny();
  }
});

// Fin de l'accès admin (retire l'élévation, garde la session utilisateur).
router.post('/logout', (req, res) => {
  if (req.session) delete req.session.adminElevatedAt;
  res.json({ ok: true });
});

// ── Tableau de bord (lecture) ────────────────────────────────────────────────
router.get('/stats', requireAdmin, async (req, res) => {
  const one = async (sql) => (await pool.query(sql)).rows[0] || {};
  const users   = (await one('SELECT count(*) AS n FROM users')).n;
  const scans   = (await one('SELECT count(*) AS n FROM scans')).n;
  const active  = (await one("SELECT count(*) AS n FROM scans WHERE mode='active'")).n;
  const domains = (await one('SELECT count(*) AS n FROM verified_domains')).n;
  const verified= (await one('SELECT count(*) AS n FROM verified_domains WHERE verified=1')).n;
  let dbSize = 0; try { dbSize = fs.statSync(DB_PATH).size; } catch (_) {}
  res.json({
    users, scans, activeScans: active, domains, verifiedDomains: verified,
    dbSizeKb: Math.round(dbSize / 1024),
    uptimeSec: Math.round(process.uptime()),
  });
});

router.get('/users', requireAdmin, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT u.id, u.email, u.created_at, u.disabled, u.last_login,
      (SELECT count(*) FROM scans s WHERE s.user_id = u.id) AS scan_count,
      (SELECT count(*) FROM scans s WHERE s.user_id = u.id AND s.mode='active') AS active_count,
      (SELECT count(*) FROM verified_domains d WHERE d.user_id = u.id AND d.verified=1) AS domain_count
    FROM users u ORDER BY u.created_at DESC LIMIT 500`);
  res.json({ users: rows.map(r => ({ ...r, disabled: !!r.disabled })), adminId: req.session.user.id });
});

// Fiche détaillée d'un compte : ses scans et ses domaines.
router.get('/users/:id', requireAdmin, async (req, res) => {
  const user = (await pool.query(
    'SELECT id, email, created_at, disabled, last_login FROM users WHERE id=$1', [req.params.id])).rows[0];
  if (!user) return res.status(404).json({ error: 'Compte introuvable' });
  user.disabled = !!user.disabled;
  const scans = (await pool.query(
    `SELECT id, target, mode, status, created_at, duration_ms
       FROM scans WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`, [req.params.id])).rows;
  const domains = (await pool.query(
    `SELECT id, domain, verified, method, created_at, verified_at
       FROM verified_domains WHERE user_id=$1 ORDER BY created_at DESC`, [req.params.id])).rows
    .map(d => ({ ...d, verified: !!d.verified }));
  res.json({ user, scans, domains });
});

// Suspendre / réactiver un compte (bloque la connexion sans supprimer).
router.post('/users/:id/status', requireAdmin, async (req, res) => {
  const id = req.params.id;
  if (id === req.session.user.id)
    return res.status(400).json({ error: 'Vous ne pouvez pas suspendre votre propre compte admin.' });
  const target = (await pool.query('SELECT email FROM users WHERE id=$1', [id])).rows[0];
  if (!target) return res.status(404).json({ error: 'Compte introuvable' });
  const disabled = (req.body || {}).disabled ? 1 : 0;
  await pool.query('UPDATE users SET disabled=$1 WHERE id=$2', [disabled, id]);
  await logAudit(req.session.user.email, disabled ? 'user.suspend' : 'user.reactivate', target.email, req.ip);
  res.json({ ok: true, disabled: !!disabled });
});

// Réinitialiser le mot de passe d'un compte.
router.post('/users/:id/password', requireAdmin, async (req, res) => {
  const id = req.params.id;
  const target = (await pool.query('SELECT email FROM users WHERE id=$1', [id])).rows[0];
  if (!target) return res.status(404).json({ error: 'Compte introuvable' });
  try {
    await setPassword(id, (req.body || {}).password);
    await logAudit(req.session.user.email, 'user.password_reset', target.email, req.ip);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

router.get('/scans', requireAdmin, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT s.id, s.target, s.mode, s.status, s.created_at, s.duration_ms, u.email
    FROM scans s LEFT JOIN users u ON u.id = s.user_id
    ORDER BY s.created_at DESC LIMIT 100`);
  res.json({ scans: rows });
});

router.get('/domains', requireAdmin, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT d.id, d.domain, d.verified, d.method, d.created_at, d.verified_at, u.email
    FROM verified_domains d LEFT JOIN users u ON u.id = d.user_id
    ORDER BY d.created_at DESC LIMIT 500`);
  res.json({ domains: rows.map(r => ({ ...r, verified: !!r.verified })) });
});

router.get('/audit', requireAdmin, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT at, actor, action, detail, ip FROM audit_log ORDER BY at DESC LIMIT 100');
  res.json({ audit: rows });
});

// ── Modération (écriture) ──────────────────────────────────────────────────
router.delete('/users/:id', requireAdmin, async (req, res) => {
  const id = req.params.id;
  if (id === req.session.user.id)
    return res.status(400).json({ error: 'Vous ne pouvez pas supprimer votre propre compte admin.' });
  const target = (await pool.query('SELECT email FROM users WHERE id=$1', [id])).rows[0];
  if (!target) return res.status(404).json({ error: 'Compte introuvable' });
  // ON DELETE CASCADE supprime aussi ses scans et domaines.
  await pool.query('DELETE FROM users WHERE id=$1', [id]);
  await logAudit(req.session.user.email, 'user.delete', `${target.email} (${id})`, req.ip);
  res.json({ ok: true });
});

router.delete('/scans/:id', requireAdmin, async (req, res) => {
  const id = req.params.id;
  const target = (await pool.query('SELECT target FROM scans WHERE id=$1', [id])).rows[0];
  if (!target) return res.status(404).json({ error: 'Scan introuvable' });
  await pool.query('DELETE FROM scans WHERE id=$1', [id]);
  await logAudit(req.session.user.email, 'scan.delete', `${target.target} (${id})`, req.ip);
  res.json({ ok: true });
});

module.exports = { router, adminIpGuard, logAudit, ADMIN_EMAIL };
