## 🔧 INSTRUCTIONS DE SETUP - YHACK REFACTORED

Vous avez reçu les fichiers refactorisés suivants. Suivez ces étapes pour les intégrer:

### FICHIERS CRÉÉS OU MODIFIÉS

✅ **Créés (nouveaux)**:
- `.env.example` - Template de configuration
- `.gitignore` - Protège .env et node_modules
- `server/payloads.js` - Configuration centralisée des payloads
- `server/scanManager_new.js` - Nouveau scanManager optimisé
- `script_new.js` - Nouveau frontend sans mock confus
- `styles_new.css` - CSS corrigé (pas de caractères espacés)
- `setup.bat` - Script de remplacement automatique
- `SETUP_INSTRUCTIONS.md` - Ce fichier

✅ **Modifiés** (overwritten):
- `package.json` - Ajout dotenv, better-sqlite3, express-rate-limit
- `server/index.js` - Refactoristation complète avec SQLite et validation
- `README.md` - Documentation professionnelle

### ÉTAPE 1: Exécuter le Setup (Windows)

```cmd
cd Yhack
setup.bat
```

Ce script remplacera automatiquement:
- `script.js` ← `script_new.js`
- `styles.css` ← `styles_new.css`
- `server/scanManager.js` ← `server/scanManager_new.js`

### ÉTAPE 2: Configurer l'Environnement

```cmd
copy .env.example .env
```

Éditez `.env` si vous voulez activer les alertes email (optionnel):
```env
ENABLE_EMAIL_ALERTS=true
SMTP_USER=votre-email@gmail.com
SMTP_PASS=your-app-password
```

### ÉTAPE 3: Installer les Dépendances

```cmd
npm install
```

Cela installera:
- `better-sqlite3` - Persistence des scans
- `dotenv` - Chargement des variables d'environnement
- `express-rate-limit` - Protection contre les abus
- Les autres dépendances existantes

### ÉTAPE 4: Démarrer le Serveur

```cmd
npm start
```

Vous devriez voir:
```
[yhack] 🔒 Serveur de sécurité démarré!
- Mode: development
- Local:  http://localhost:5050
- Réseau: http://192.168.x.x:5050
- DB:     C:\...\scan-results.db
```

---

## ✅ CHANGEMENTS APPORTÉS

### 🔒 SÉCURITÉ (CRITIQUE)

**❌ AVANT**:
```javascript
const transporter = nodemailer.createTransport({
    auth: { user: 'lucas.gemo77@gmail.com', pass: 'Super!killer!9' }
});
```

**✅ APRÈS**:
```javascript
const transporter = nodemailer.createTransport({
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});
```
Credentials sécurisés dans `.env`, jamais en clair!

---

### 📊 PERSISTENCE (IMPORTANT)

**❌ AVANT**:
```javascript
const scans = new Map();  // Perdu si serveur redémarre!
```

**✅ APRÈS**:
```javascript
const db = new Database('scan-results.db');
db.exec(`CREATE TABLE scans (...)`);
```
Les scans sont maintenant persistés en SQLite avec:
- Auto-cleanup après 24h
- Max 500 scans en mémoire
- Timestamps et durée

---

### ⚡ PERFORMANCE (PARALLÉLISATION)

**❌ AVANT** (Séquentiel - LENT):
```javascript
// DNS attend 100ms
// TLS attend 100ms
// Headers attend 100ms
// ... Total: 2+ minutes!
```

**✅ APRÈS** (Parallèle - RAPIDE):
```javascript
const [dns, tls, headers, cors, ports, files] = await Promise.all([
  testDNS(url, onLine),
  testTLS(url, onLine),
  testHeaders(url, onLine),
  testCORS(url, onLine),
  testPorts(url, onLine),
  testSensitiveFiles(url, onLine)
]);
// Tous exécutés en même temps!
```

---

### 🎯 TESTS AMÉLIORÉS

**❌ AVANT** (Payloads partout, redondants):
```javascript
const payloads = ["' OR '1'='1", "' OR 1=1 --"];  // Dans scanManager.js
// Difficile à maintenir et modifier
```

**✅ APRÈS** (Centralisé):
```javascript
// server/payloads.js
const PAYLOADS = {
  sqli: {
    params: ['id', 'user', 'q', ...],
    payloads: ["' OR '1'='1", "' OR 1=1 --", ...],
    errorPatterns: [/SQL syntax/, /mysql_fetch/, ...]
  }
}
```
Facile à modifier, maintenir, et réutiliser!

---

### 🛡️ VALIDATION & PROTECTION

**Ajouté**:
- ✅ Validation stricte des URLs (reject invalid formats)
- ✅ SSRF Protection (reject 127.x, 10.x, 192.168.x, etc.)
- ✅ Rate limiting (5 scans/minute par IP)
- ✅ Timeouts configurables
- ✅ Email validation

---

### 🎨 CSS CORRIGÉ

**❌ AVANT**:
```css
/ *   F l a g   A l e r t   * /   /* Espacé! */
@ k e y f r a m e s   f l a s h - f l a g   { /* Cassé! */
```

**✅ APRÈS**:
```css
/* Flag Detection Alert */
@keyframes flash-flag {
  0% { border-color: #ff003c; ... }
  50% { ... }
  100% { ... }
}
.flag-found { display: block; ... animation: flash-flag 1s; }
```

---

### 🧹 CODE CLEANUP

**Supprimé**:
- ❌ `hashString()` - Résultats faux et déterministes
- ❌ `runMockScan()` - Plus besoin, API réel seulement
- ❌ `convertResultsToStatuses()` - Jamais appelée
- ❌ Credentials en clair
- ❌ Code mort et redondances

**Ajouté**:
- ✅ Payload configuration centralisée
- ✅ Proper error handling
- ✅ Logging structuré
- ✅ JSDoc comments sur les fonctions
- ✅ Rate limiting middleware

---

## 🔍 VÉRIFICATION

Après le setup, testez que tout fonctionne:

```bash
# 1. Vérifier que le serveur démarre
npm start

# 2. Dans un autre terminal, tester l'API
curl -X POST http://localhost:5050/api/scan ^
  -H "Content-Type: application/json" ^
  -d "{\"targetUrl\": \"https://httpbin.org/status/200\"}"

# Vous devriez voir: {"scanId": "abc123..."}

# 3. Ouvrir le navigateur
# http://localhost:5050
```

---

## 📚 STRUCTURE DE FICHIERS FINALE

```
Yhack/
├── .env                        # Configuration (ignorée par git)
├── .env.example               # Template de configuration
├── .gitignore                 # Protège .env, node_modules
├── README.md                  # Documentation complète
├── package.json               # Dépendances modifiées
├── setup.bat                  # Script de setup
│
├── index.html                 # Interface UI (inchangé)
├── script.js                  # Frontend refactorisé ✨
├── styles.css                 # CSS corrigé ✨
│
├── server/
│   ├── index.js               # API Express refactorisée ✨
│   ├── scanManager.js         # Scan orchestrator refactorisé ✨
│   └── payloads.js            # Configuration centralisée ✨ (NOUVEAU)
│
├── scan-results.db            # SQLite persistence (créé au démarrage)
└── node_modules/              # Dépendances (ignoré par git)
```

---

## 🚀 DÉMARRAGE RAPIDE

Pour des utilisateurs pressés:

```bash
cd Yhack
setup.bat
npm install
npm start
```

Puis ouvrez http://localhost:5050

---

## ⚠️ NOTES IMPORTANTES

1. **Fichiers _new.js / _new.css**: Gardez-les jusqu'à confirmation que setup.bat a fonctionné
2. **.env**: N'oubliez pas de copier `.env.example` à `.env`
3. **Database**: `scan-results.db` sera créé automatiquement au premier démarrage
4. **Ports**: Si le port 5050 est occupé, modifiez `.env` avec `PORT=5051`
5. **Emails**: Les alertes email sont **désactivées par défaut** (ENABLE_EMAIL_ALERTS=false)

---

## 🐛 TROUBLESHOOTING

### Erreur: "EADDRINUSE: address already in use :::5050"
```bash
PORT=5051 npm start
```

### Erreur: "Cannot find module 'better-sqlite3'"
```bash
npm install
```

### Erreur: "dotenv not defined"
```bash
# Vérifiez que require('dotenv').config() est en haut de server/index.js
```

### Setup.bat ne marche pas (Mac/Linux)

Remplacez manuellement:
```bash
rm script.js && mv script_new.js script.js
rm styles.css && mv styles_new.css styles.css
rm server/scanManager.js && mv server/scanManager_new.js server/scanManager.js
```

---

## ✅ CHECKLIST POST-SETUP

- [ ] setup.bat exécuté avec succès
- [ ] `npm install` terminé
- [ ] `.env` configuré (optionnel)
- [ ] `npm start` affiche "Serveur de sécurité démarré!"
- [ ] http://localhost:5050 fonctionne dans le navigateur
- [ ] Un test de scan complète avec succès
- [ ] `scan-results.db` a été créé

---

**Version**: 1.0.0 Refactored  
**Date**: April 2026  
**Status**: ✅ Production-Ready
