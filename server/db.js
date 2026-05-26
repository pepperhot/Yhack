'use strict';

const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://netguard:netguard@localhost:5432/netguard',
  max: 10,
});

pool.on('error', (err) => {
  console.error('[DB] Unexpected pool error:', err.message);
});

async function init() {
  await pool.query(`
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
  console.log('[DB] Tables ready');
}

module.exports = { pool, init };
