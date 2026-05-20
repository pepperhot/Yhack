# Yhack — Professional Web Security Scanner

**Une suite d'audit de sécurité web professionnelle et sécurisée** pour évaluer les vulnérabilités courantes sur vos applications web.

## ⚠️ Avertissement Légal

**USAGE AUTORISÉ UNIQUEMENT**. Vous ne pouvez tester que des systèmes pour lesquels vous possédez une autorisation écrite explicite. Les tests de sécurité (SQL injection, XSS, brute-force) sont réels et déploient de véritables payloads. L'utilisation non autorisée est **illégale**.

---

## 🚀 Installation & Démarrage

### Prérequis
- **Node.js 18+** (vérifiez avec `node --version`)
- **npm** (vient avec Node.js)

### 1. Cloner ou extraire le projet
```bash
cd Yhack
```

### 2. Configurer les variables d'environnement
```bash
cp .env.example .env
```

Éditez `.env` pour configurer (optionnel):
```env
PORT=5050
SMTP_HOST=smtp.gmail.com
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
ENABLE_EMAIL_ALERTS=false
```

⚠️ **NOTE**: Les alertes email ne fonctionneront que si vous configurez `SMTP_USER` et `SMTP_PASS`. Pour Gmail, générez un [App Password](https://support.google.com/accounts/answer/185833).

### 3. Installer les dépendances
```bash
npm install
```

### 4. Démarrer le serveur
```bash
npm start
```

La UI sera disponible à:
- **Local**: http://localhost:5050
- **Réseau**: http://<YOUR_IP>:5050

---

## 📋 Modules de Test

### Tests Passifs (Non-Intrusifs) 
Aucun impact sur la cible, information gathering seulement:

| Module | Description |
|--------|-------------|
| **DNS** | Résolution et adresses IP |
| **TLS/SSL** | Certificats, protocoles, ciphers |
| **Headers** | CSP, HSTS, X-Frame-Options, etc. |
| **CORS** | Configuration Cross-Origin |
| **Ports** | Scan TCP des ports courants |
| **Fichiers Sensibles** | .env, .git, backup.sql, etc. |

### Tests Actifs (Avec Payloads Contrôlés)
Tests réels de vulnérabilités **avec protections strictes**:

| Module | Payloads | Limites |
|--------|----------|---------|
| **SQL Injection** | 10+ payloads  | 50 requêtes max |
| **XSS** | 5+ vecteurs | 25 requêtes max |
| **LFI** | 4 chemins | 16 requêtes max |
| **RCE** | 4 payloads | 16 requêtes max |
| **SSTI** | Template expressions | Mako/Jinja2 |

### Protections Implémentées

✅ **Délais entre requêtes** : 200ms par défaut (configurable)  
✅ **Timeouts courts** : 5-30s par requête  
✅ **User-Agent identifié** : `Yhack-Scanner/1.0`  
✅ **Rate limiting** : 5 scans/minute par IP  
✅ **SSRF protection** : Rejette 127.x, 10.x, 192.168.x  
✅ **No destructive tests** : Détection uniquement, pas d'exploitation  

---

## 🎯 Interface Utilisateur

1. **Entrez une URL** (avec `https://` ou `http://`)
2. **Email optionnel** pour recevoir des alertes sur vulnérabilités critiques
3. **Cliquez "Analyser"** 
4. **Regardez le scan en temps réel** dans le terminal
5. **Consultez le rapport synthétique** avec score et recommandations

---

## 📊 Architecture

```
Yhack/
├── index.html              # Interface utilisateur
├── script.js              # Logique frontend (real API calls only)
├── styles.css            # Styling
├── package.json          # Dépendances
├── server/
│   ├── index.js          # API Express + SQLite persistence
│   ├── scanManager.js    # 20+ modules de test parallélisés
│   └── payloads.js       # Configuration centralisée des payloads
└── scan-results.db       # Persistence des scans (créé au démarrage)
```

### Flow d'une requête
```
[Frontend] POST /api/scan → [Backend] Crée un scan en DB
    ↓
[scanManager] Exécute les modules en parallèle
    ↓
[Backend] Poll GET /api/scan/:id → [Frontend] Affiche les résultats en temps réel
```

---

## 🔧 Configuration Avancée

Éditer `.env`:

```env
# Server
PORT=5050
NODE_ENV=development

# Scan behavior
SCAN_TIMEOUT_MS=30000          # Timeout global par requête
SCAN_DELAY_MS=200              # Délai entre requests (ms)
MAX_REQUESTS_PER_MINUTE=5      # Rate limiting par IP

# Database
MAX_SCANS_MEMORY=500           # Scans stockés max
SCAN_TTL_HOURS=24              # Retention scans (heures)

# Email alerts
ENABLE_EMAIL_ALERTS=false
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
```

---

## 🧪 Tests

Les tests unitaires (à venir):
```bash
npm test
```

---

## 📁 Structure de Données

### Scan Result
```json
{
  "id": "abcd1234efgh56",
  "status": "done",
  "target": "https://example.com",
  "dns": { "status": "OK", "addresses": ["93.184.216.34"] },
  "tls": { "status": "OK", "details": {...} },
  "sqli": { "status": "OK", "vulnerable": false },
  "xss": { "status": "FAIL", "vulnerable": true, "param": "q" },
  "vulns": { "status": "FAIL", "critical_issues": 1 }
}
```

---

## 🚨 Erreurs Courants

| Erreur | Solution |
|--------|----------|
| `EADDRINUSE` | Port déjà utilisé: `PORT=5051 npm start` |
| `Credentials email invalides` | Vérifiez `.env` (Gmail: utilisez [App Password](https://support.google.com/accounts/answer/185833)) |
| `SSRF protection: IPs privées` | Normal! Pour dev local, utilisez une adresse publique ou whitelist en `.env` |
| `Timeout sur /api/scan` | La cible est très lente, augmentez `SCAN_TIMEOUT_MS` |

---

## 📜 Conditions d'Utilisation

L'outil Yhack est fourni **à des fins pédagogiques et d'audit de sécurité légitime uniquement**.

En l'utilisant, vous acceptez:
- ✅ Vous ne scannez que des systèmes avec **autorisation écrite explicite**
- ✅ Vous êtes **seul responsable** des conséquences juridiques
- ✅ Pas d'usage destructif (DoS, perturbation, exploitation en prod)
- ✅ Les données sensibles sont **stockées de manière sécurisée**
- ✅ Ce projet est un **prototype pédagogique**, pas un service commercial

---

## 🎓 Apprentissage

Les modules de test implémentent les standards:
- **OWASP Top 10** (SQLi, XSS, Broken Auth, Sensitive Data, etc.)
- **CWE-79, CWE-89, CWE-98** (XSS, SQLi, RCE)
- **Best Practices**: Rate limiting, timeouts, validations

---

## 🔐 Sécurité du Projet Lui-Même

- ✅ **Pas de credentials en clair** (variables d'environnement)
- ✅ **SSRF protection** (reject private IPs)
- ✅ **Rate limiting** (5 scans/min)
- ✅ **Logs structurés** (timestamp, scanId, module)
- ✅ **Persistent DB** (SQLite, auto-cleanup 24h)

---

## 📝 Notes de Développement

### Parallelization
- Phase 1 (DNS, TLS, Headers, CORS, Ports, Files) → Parallèle
- Phase 2 (SQLi, XSS, LFI, RCE, SSTI) → Parallèle avec rate limiting (200ms entre requêtes)

### Payload Configuration
Tous les payloads sont définis dans `server/payloads.js` pour facile modification.

### Ajout de Nouveaux Modules
1. Ajouter les payloads à `PAYLOADS` dans `payloads.js`
2. Créer fonction `async testXXX(url, onLine, alertEmail)` dans `scanManager.js`
3. Appeler dans `runScan()` avec `Promise.all()`

---

## 📞 Support

- Vérifiez les logs: `console.log` ou fichier `.env`
- Activez `NODE_ENV=development` pour plus de verbosité
- Les scans sont stockés dans `scan-results.db` pour debug

---

**Version**: 1.0.0  
**License**: MIT  
**Auteurs**: Yhack Team

