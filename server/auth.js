'use strict';

const bcrypt = require('bcryptjs');
const { pool, isAvailable } = require('./db');

// In-memory fallback when PostgreSQL is unavailable
const memUsers = new Map();

async function createUser(email, password) {
  const key = email.toLowerCase().trim();
  if (password.length < 8) throw new Error('Le mot de passe doit faire au moins 8 caractères');

  const id           = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  const passwordHash = bcrypt.hashSync(password, 12);

  if (!isAvailable()) {
    if (memUsers.has(key)) throw new Error('Email déjà utilisé');
    memUsers.set(key, { id, email: key, password_hash: passwordHash });
    return { id, email: key };
  }

  try {
    const { rows } = await pool.query(
      'INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3) RETURNING id, email',
      [id, key, passwordHash],
    );
    return rows[0];
  } catch (e) {
    if (e.code === '23505') throw new Error('Email déjà utilisé');
    throw e;
  }
}

async function loginUser(email, password) {
  const key = email.toLowerCase().trim();

  if (!isAvailable()) {
    const user = memUsers.get(key);
    if (!user || !bcrypt.compareSync(password, user.password_hash))
      throw new Error('Email ou mot de passe incorrect');
    return { id: user.id, email: user.email };
  }

  const { rows } = await pool.query(
    'SELECT * FROM users WHERE email = $1',
    [key],
  );
  const user = rows[0];
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    throw new Error('Email ou mot de passe incorrect');
  return { id: user.id, email: user.email };
}

module.exports = { createUser, loginUser };
