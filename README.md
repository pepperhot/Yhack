# NetGuard — Scanner de sécurité web

Suite d'audit de sécurité web : DNS, TLS, en-têtes, CORS, cookies, ports, et
tests actifs (SQLi, XSS, LFI, RCE, SSTI, open redirect, méthodes HTTP). Chaque
vulnérabilité détectée est accompagnée d'un guide d'exploitation et de
remédiation. Interface web avec scan en temps réel + rapport noté (A→F).

## ⚠️ Avertissement légal

**Usage autorisé uniquement.** Vous ne pouvez scanner que des systèmes pour
lesquels vous avez une autorisation écrite explicite. Les tests actifs envoient
de vrais payloads. Toute utilisation non autorisée est illégale.

---

## Stack

- **Backend** : Node.js 18+ / Express
- **Base de données** : SQLite (un fichier `data/netguard.db`, zéro serveur, zéro port réseau)
- **Frontend** : HTML/CSS/JS statique servi par Express (pas de build)
- **Auth** : sessions (cookie `httpOnly`, persistées en base), mots de passe hashés bcrypt
- **Déploiement** : PM2 (recommandé) ou Docker

---

## Démarrage rapide (local)

```bash
cp .env.example .env          # éditer SESSION_SECRET
npm install
npm start
```
App sur http://localhost:5050. La base `data/netguard.db` se crée toute seule au
premier lancement — rien d'autre à installer.

### Avec Docker
```bash
cp .env.example .env
docker compose up --build
```

---

## Architecture

```
NetGuard/
├── index.html            # Interface (auth + formulaire de scan + rapport)
├── script.js             # Frontend : appels API + polling + rendu du rapport
├── styles.css            # Styles
├── server/
│   ├── index.js          # API Express, sessions, routes scan/auth, health
│   ├── db.js             # SQLite (better-sqlite3) + schéma + shim compatible pg
│   ├── auth.js           # register / login (bcrypt)
│   ├── scanManager.js    # Orchestrateur + 16 modules de test
│   └── payloads.js       # Tous les payloads centralisés
├── data/netguard.db      # Base SQLite (créée au 1er lancement, hors Git)
├── Dockerfile            # Image Node non-root
├── docker-compose.yml    # App + volume data
├── ecosystem.config.js   # Config PM2 (déploiement sans Docker)
├── deploy.sh             # Script de redéploiement VPS
├── DEPLOYMENT.md         # Guide de mise en prod sur VPS
└── .env.example          # Modèle de configuration
```

### Flux d'un scan
```
[Front] POST /api/scan ──► [API] crée le scan (DB + mémoire), lance runScan()
                                       │
                  scanManager pousse chaque ligne en mémoire (callback emit)
                                       │
[Front] GET /api/scan/:id (polling 800ms) ──► lignes temps réel + résultats finaux
```
À la fin du scan, les résultats sont écrits en base puis le scan est évincé de
la mémoire après 60 s.

---

## Modules de test

**Reconnaissance (parallèle, non-intrusif)** : DNS, TLS/SSL, en-têtes HTTP,
CORS, cookies, détection de technologies, fichiers sensibles (.env, .git…),
robots.txt, scan de ports TCP.

**Tests actifs (séquentiels)** : SQL injection (error + time-based blind), XSS
réfléchi, LFI, RCE, SSTI, open redirect, méthodes HTTP dangereuses.

Protections : délai configurable entre requêtes, timeouts courts, rate limiting
par utilisateur, **protection SSRF** (rejette localhost, IP privées, link-local).

---

## API

| Route | Auth | Description |
|-------|------|-------------|
| `POST /api/auth/register` | non | Crée un compte, ouvre la session |
| `POST /api/auth/login` | non | Connexion |
| `POST /api/auth/logout` | non | Déconnexion |
| `GET /api/auth/me` | non | Utilisateur courant (ou 401) |
| `POST /api/scan` | **oui** | Lance un scan (rate-limité) |
| `GET /api/scan/:id` | **oui** | État + lignes + résultats (propriétaire only) |
| `GET /api/scans` | **oui** | Historique (50 derniers) |
| `GET /healthz` | non | Santé du service (pour Docker/monitoring) |

---

## Configuration

Toutes les variables sont dans `.env` — voir [.env.example](.env.example) pour
le détail commenté. Les essentielles en production :

| Variable | Rôle |
|----------|------|
| `SESSION_SECRET` | **Obligatoire en prod.** Secret de signature des sessions |
| `COOKIE_SECURE` | `true` derrière HTTPS uniquement |
| `CORS_ORIGINS` | Domaines autorisés (séparés par virgule) |
| `DB_PATH` | Chemin du fichier SQLite (défaut `./data/netguard.db`) |
| `MAX_REQUESTS_PER_MINUTE` | Scans/min par utilisateur (défaut 5) |
| `ENABLE_EMAIL_ALERTS` + `SMTP_*` | Alertes email (optionnel) |

---

## Mise en production

Voir **[DEPLOYMENT.md](DEPLOYMENT.md)** pour le guide VPS complet (Docker, HTTPS
avec Caddy, sauvegardes, logs, mises à jour).

---

**Version** 1.0.0 · **License** MIT
