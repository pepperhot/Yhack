'use strict';

const bcrypt = require('bcryptjs');

// In-memory user store — swap this Map for DB calls when ready
const users = new Map(); // email → { id, email, passwordHash, created_at }

function createUser(email, password) {
  const key = email.toLowerCase().trim();
  if (users.has(key)) throw new Error('Email déjà utilisé');
  if (password.length < 8) throw new Error('Le mot de passe doit faire au moins 8 caractères');

  const user = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    email: key,
    passwordHash: bcrypt.hashSync(password, 12),
    created_at: new Date().toISOString(),
  };
  users.set(key, user);
  return { id: user.id, email: user.email };
}

function loginUser(email, password) {
  const user = users.get(email.toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password, user.passwordHash))
    throw new Error('Email ou mot de passe incorrect');
  return { id: user.id, email: user.email };
}

module.exports = { createUser, loginUser };
