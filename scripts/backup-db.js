'use strict';
/**
 * Sauvegarde « à chaud » de la base SQLite, sûre même pendant que l'app tourne
 * (utilise l'API backup de better-sqlite3, compatible WAL).
 *
 *   node scripts/backup-db.js
 *
 * Réglages par variables d'env :
 *   DB_PATH      chemin de la base        (défaut : data/netguard.db)
 *   BACKUP_DIR   dossier des sauvegardes  (défaut : data/backups — non servi en HTTP)
 *   BACKUP_KEEP  nombre à conserver       (défaut : 14)
 */
const path     = require('path');
const fs       = require('fs');
const Database = require('better-sqlite3');

const DB_PATH    = process.env.DB_PATH    || path.join(__dirname, '..', 'data', 'netguard.db');
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(__dirname, '..', 'data', 'backups');
const KEEP       = parseInt(process.env.BACKUP_KEEP || '14', 10);

if (!fs.existsSync(DB_PATH)) {
  console.error('[BACKUP] base introuvable :', DB_PATH);
  process.exit(1);
}
fs.mkdirSync(BACKUP_DIR, { recursive: true });

const stamp = new Date().toISOString().replace(/[:.]/g, '-'); // 2026-07-15T14-30-00-123Z (unique à la ms)
const dest  = path.join(BACKUP_DIR, `netguard-${stamp}.db`);

const db = new Database(DB_PATH, { readonly: true });
db.backup(dest)
  .then(() => {
    db.close();
    const ko = (fs.statSync(dest).size / 1024).toFixed(0);
    console.log(`[BACKUP] OK → ${dest} (${ko} Ko)`);

    // Rotation : ne garder que les KEEP sauvegardes les plus récentes.
    const files = fs.readdirSync(BACKUP_DIR)
      .filter(f => /^netguard-.*\.db$/.test(f))
      .sort();                              // tri lexical = tri chronologique (horodatage ISO)
    const excess = files.slice(0, Math.max(0, files.length - KEEP));
    excess.forEach(f => fs.unlinkSync(path.join(BACKUP_DIR, f)));
    if (excess.length) console.log(`[BACKUP] ${excess.length} ancienne(s) supprimée(s), ${KEEP} conservée(s)`);
  })
  .catch(err => {
    console.error('[BACKUP] échec :', err.message);
    process.exit(1);
  });
