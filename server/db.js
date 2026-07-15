'use strict';

const path     = require('path');
const fs       = require('fs');
const Database = require('better-sqlite3');

// La base est un simple fichier local — aucun port réseau, aucun mot de passe.
// Emplacement hors du dossier servi en statique (voir le garde dans index.js).
const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'netguard.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const _db = new Database(DB_PATH);
_db.pragma('journal_mode = WAL');   // durabilité + lectures concurrentes
_db.pragma('foreign_keys = ON');

async function init() {
  _db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            TEXT PRIMARY KEY,
      email         TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at    TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS scans (
      id           TEXT PRIMARY KEY,
      user_id      TEXT REFERENCES users(id) ON DELETE CASCADE,
      target       TEXT NOT NULL,
      email        TEXT,
      mode         TEXT NOT NULL DEFAULT 'passive',
      status       TEXT NOT NULL DEFAULT 'queued',
      results      TEXT,
      lines        TEXT DEFAULT '[]',
      created_at   TEXT DEFAULT (datetime('now')),
      completed_at TEXT,
      duration_ms  INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);

    CREATE TABLE IF NOT EXISTS verified_domains (
      id          TEXT PRIMARY KEY,
      user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      domain      TEXT NOT NULL,
      token       TEXT NOT NULL,
      verified    INTEGER NOT NULL DEFAULT 0,
      method      TEXT,
      created_at  TEXT DEFAULT (datetime('now')),
      verified_at TEXT,
      UNIQUE(user_id, domain)
    );
    CREATE INDEX IF NOT EXISTS idx_domains_user_id ON verified_domains(user_id);

    -- Journal d'audit : actions admin + autorisations de scans actifs.
    CREATE TABLE IF NOT EXISTS audit_log (
      id      TEXT PRIMARY KEY,
      at      TEXT DEFAULT (datetime('now')),
      actor   TEXT,
      action  TEXT NOT NULL,
      detail  TEXT,
      ip      TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);
  `);
  console.log('[DB] SQLite prêt →', DB_PATH);
}

// SQLite (better-sqlite3) est toujours disponible : plus de mode mémoire.
function isAvailable() { return true; }

// Instance brute — utilisée par le store de sessions.
function rawDb() { return _db; }

// Shim compatible pg : pool.query(sql, params) → { rows }.
// Traduit les placeholders $1,$2… (style Postgres) en ? (style SQLite),
// pour ne pas avoir à réécrire toutes les requêtes des autres modules.
const pool = {
  async query(sql, params = []) {
    const sqlite = sql.replace(/\$(\d+)/g, '?');
    const stmt   = _db.prepare(sqlite);
    if (/^\s*select/i.test(sqlite) || /\breturning\b/i.test(sqlite)) {
      return { rows: stmt.all(...params) };
    }
    const info = stmt.run(...params);
    return { rows: [], rowCount: info.changes };
  },
  async end() { _db.close(); },
};

module.exports = { pool, rawDb, init, isAvailable, DB_PATH };
