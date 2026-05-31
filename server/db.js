'use strict';

const { Pool } = require('pg');

let _pool = null;
let _available = false;

const DB_URL = process.env.DATABASE_URL;

if (DB_URL) {
  _pool = new Pool({ connectionString: DB_URL, max: 10 });
  _pool.on('error', err => {
    console.error('[DB] Pool error:', err.message);
    _available = false;
  });
}

async function init() {
  if (!_pool) {
    console.log('[DB] No DATABASE_URL — running in memory-only mode');
    return;
  }
  try {
    await _pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id            TEXT PRIMARY KEY,
        email         TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at    TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS scans (
        id           TEXT PRIMARY KEY,
        target       TEXT NOT NULL,
        email        TEXT,
        status       TEXT NOT NULL DEFAULT 'queued',
        results      JSONB,
        lines        JSONB DEFAULT '[]'::jsonb,
        created_at   TIMESTAMPTZ DEFAULT NOW(),
        completed_at TIMESTAMPTZ,
        duration_ms  INTEGER
      );
    `);
    _available = true;
    console.log('[DB] Tables ready');
  } catch (e) {
    console.warn('[DB] PostgreSQL unavailable — running in memory-only mode:', e.message);
    _available = false;
  }
}

function isAvailable() {
  return _available;
}

const pool = {
  query: async (sql, params) => {
    if (!_available || !_pool) return { rows: [] };
    return _pool.query(sql, params);
  },
  end: async () => {
    if (_pool) return _pool.end();
  },
};

module.exports = { pool, init, isAvailable };
