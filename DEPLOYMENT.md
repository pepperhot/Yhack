# Déploiement VPS — NetGuard

Base de données = **SQLite** : un simple fichier, aucun serveur, aucun port,
aucun mot de passe. C'est ce qui rend le déploiement aussi simple.

Architecture cible :

```
Internet ──HTTPS──► Caddy ou Nginx (TLS Let's Encrypt)
                      │  reverse_proxy
                      ▼
                 NetGuard (127.0.0.1:5050)  ──►  data/netguard.db (fichier local)
```
L'app n'écoute qu'en local ; seul le reverse proxy est exposé (80/443).

Deux façons de lancer : **PM2** (natif, recommandé pour ton VPS) ou **Docker**.

---

## Option A — PM2 (recommandé, c'est ce que tu utilises)

### 1. Prérequis
```bash
ssh pepper@TON_IP
# Node.js 18+ et PM2
node --version
sudo npm install -g pm2
```

### 2. Récupérer le code + configurer
```bash
cd /var/www/html/Yhack
git pull
npm ci --omit=dev

cp .env.example .env
nano .env
```
Renseigner **au minimum** :
```env
NODE_ENV=production
SESSION_SECRET=<colle: openssl rand -hex 32>
COOKIE_SECURE=false        # true seulement une fois le HTTPS en place
CORS_ORIGINS=https://tondomaine.com
```
> Génère le secret : `openssl rand -hex 32`

### 3. Lancer
```bash
pm2 start ecosystem.config.js
pm2 save
pm2 startup      # copie/colle la commande affichée (démarrage auto au boot)
```

### 4. Vérifier
```bash
curl localhost:5050/healthz     # → {"status":"ok","db":"sqlite",...}
pm2 logs netguard
```

### Mises à jour ensuite
```bash
cd /var/www/html/Yhack && git pull && npm ci --omit=dev && pm2 restart netguard --update-env
```

---

## Option B — Docker

```bash
cp .env.example .env      # renseigne SESSION_SECRET + CORS_ORIGINS
docker compose up -d --build
docker compose ps
curl localhost:5050/healthz
```
La base est persistée dans `./data` (volume monté). `docker compose down` n'efface
rien ; le fichier reste dans `./data/netguard.db`.

---

## HTTPS (Caddy — le plus simple)

Pointe d'abord le DNS de `tondomaine.com` vers l'IP du VPS, puis :

```bash
apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt update && apt install -y caddy
```

`/etc/caddy/Caddyfile` :
```
tondomaine.com {
    reverse_proxy localhost:5050
}
```
```bash
systemctl reload caddy
```
HTTPS actif + renouvellement auto. **Ensuite, passe `COOKIE_SECURE=true` dans
`.env`** puis `pm2 restart netguard --update-env`.

> Tu as déjà Nginx ? Un bloc `location / { proxy_pass http://127.0.0.1:5050; ... }`
> + `certbot --nginx -d tondomaine.com` fait le même travail.

---

## Gérer la base de données

C'est **un seul fichier** : `data/netguard.db`. Tables (`users`, `scans`,
`sessions`) créées automatiquement au premier démarrage.

### Voir ce qu'il y a dedans
```bash
# Installer le client (une fois) : apt install -y sqlite3
sqlite3 data/netguard.db
```
```sql
.tables                                         -- lister les tables
SELECT email, created_at FROM users;
SELECT target, status, created_at FROM scans ORDER BY created_at DESC LIMIT 20;
.quit
```
Ou en une ligne :
```bash
sqlite3 data/netguard.db "SELECT count(*) FROM users;"
```

### Sauvegarde (backup) — copier UN fichier
```bash
# Backup cohérent même si l'app tourne (recommandé) :
sqlite3 data/netguard.db ".backup '/home/pepper/backups/netguard_$(date +%F).db'"
```

### Restauration
```bash
pm2 stop netguard
cp /home/pepper/backups/netguard_2026-07-03.db data/netguard.db
pm2 start netguard
```

### Sauvegarde automatique quotidienne (cron)
```bash
mkdir -p ~/backups
crontab -e
# Backup à 3h, conserve 14 jours :
0 3 * * * sqlite3 /var/www/html/Yhack/data/netguard.db ".backup '/home/pepper/backups/netguard_$(date +\%F).db'" && find ~/backups -name 'netguard_*.db' -mtime +14 -delete
```
> Idéalement, copie aussi ces backups **hors du VPS** (rsync/scp vers un autre
> serveur ou un stockage objet) — si le VPS meurt, tu gardes tes données.

---

## Voir les logs

```bash
pm2 logs netguard            # en direct
pm2 logs netguard --lines 100
# Docker : docker compose logs -f netguard
```
Logs structurés : `[API]` (requêtes/erreurs), `[SCAN]` (déroulé d'un scan avec
`scanId` + `userId`), `[DB]` (état base).

---

## Checklist avant ouverture au public

- [ ] `SESSION_SECRET` fort et généré aléatoirement (`openssl rand -hex 32`)
- [ ] `COOKIE_SECURE=true` **une fois le HTTPS actif**
- [ ] `CORS_ORIGINS` = ton domaine exact (pas `*`)
- [ ] Pare-feu : seuls 22/80/443 ouverts ; 5050 fermé au public
- [ ] `/healthz` répond `{"db":"sqlite"}`
- [ ] Le fichier `data/netguard.db` n'est **pas** servi en HTTP (déjà bloqué côté code — `curl https://tondomaine.com/data/netguard.db` doit renvoyer 404)
- [ ] Backup automatisé (cron) **et testé** (restauration vérifiée), copié hors VPS
- [ ] `.env` **absent** de Git (`git status` ne doit pas le lister)
- [ ] SSH par clé, mot de passe root désactivé

---

## Dépannage

| Symptôme | Cause / solution |
|----------|------------------|
| `Cannot find module 'better-sqlite3'` | `npm ci --omit=dev` non lancé, ou binaire non compilé → relancer `npm ci` |
| Déconnexion à chaque restart | Normalement réglé (sessions en base). Vérifier que `data/netguard.db` est bien écrit (droits du dossier `data/`) |
| 401 sur `/api/scan` | Pas connecté, ou cookie bloqué (voir ligne suivante) |
| Cookie non envoyé / login KO | `COOKIE_SECURE=true` mais site en HTTP → repasser à `false` ou activer HTTPS |
| `EADDRINUSE :5050` | Une instance tourne déjà → `pm2 restart netguard` (ne pas relancer `npm start`) |
| `SQLITE_BUSY` sous forte charge | Rare ; le mode WAL est déjà activé. Si ça persiste, c'est le signal qu'il faudra passer à Postgres (beaucoup d'écritures concurrentes) |
