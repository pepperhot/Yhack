# Déploiement VPS — NetGuard

Guide pas-à-pas pour mettre NetGuard en production sur un VPS (Ubuntu/Debian),
avec Docker, HTTPS automatique, sauvegardes et supervision.

Architecture cible :

```
Internet ──HTTPS──► Caddy (TLS Let's Encrypt auto)
                      │  reverse_proxy
                      ▼
                 NetGuard (127.0.0.1:5050)  ── réseau Docker ──►  PostgreSQL
```
La base et l'app n'écoutent **que** en local ; seul Caddy est exposé (80/443).

---

## 1. Préparer le VPS

```bash
# Connexion
ssh root@TON_IP

# Mises à jour + Docker
apt update && apt upgrade -y
curl -fsSL https://get.docker.com | sh

# Pare-feu : n'ouvrir que SSH et le web
apt install -y ufw
ufw allow OpenSSH
ufw allow 80
ufw allow 443
ufw enable
```

> ⚠️ Ne jamais ouvrir le port **5432** (PostgreSQL) ni **5050** (Node) sur le
> pare-feu. Ils restent internes.

---

## 2. Récupérer le code

```bash
# (Recommandé) créer un utilisateur non-root pour le déploiement
adduser deploy && usermod -aG docker deploy && su - deploy

git clone https://github.com/gelucas/<ton-repo>.git netguard
cd netguard
```

---

## 3. Configurer `.env`

```bash
cp .env.example .env
nano .env
```

Renseigner **au minimum** (générer les secrets, ne pas inventer à la main) :

```bash
# Générer un secret de session :
openssl rand -hex 32
# Générer un mot de passe DB :
openssl rand -base64 24
```

```env
NODE_ENV=production
SESSION_SECRET=<colle le openssl rand -hex 32>
POSTGRES_PASSWORD=<colle le openssl rand -base64 24>
CORS_ORIGINS=https://tondomaine.com
COOKIE_SECURE=true
```

`DATABASE_URL` et `COOKIE_SECURE` sont déjà gérés par `docker-compose.yml` — pas
besoin de les définir à la main si tu utilises Docker.

---

## 4. Lancer l'application

```bash
docker compose up -d --build
docker compose ps          # les 2 services doivent être "healthy"
curl localhost:5050/healthz   # → {"status":"ok","db":"postgres",...}
```

---

## 5. HTTPS avec Caddy (recommandé)

Caddy gère le certificat Let's Encrypt **automatiquement**. Pointe d'abord le
DNS de `tondomaine.com` vers l'IP du VPS (enregistrement A).

```bash
# Installer Caddy
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
C'est tout : HTTPS actif, renouvellement automatique du certificat.

> Alternative Nginx : il faut générer le certificat (certbot) et écrire un bloc
> `location / { proxy_pass http://127.0.0.1:5050; ... }`. Caddy fait tout ça seul.

---

## 6. Gérer la base de données

La base vit dans le **volume Docker `pgdata`** (persiste aux redémarrages et aux
rebuilds). Les tables (`users`, `scans`, `session`) sont créées automatiquement
au premier démarrage.

### Se connecter à la base
```bash
docker compose exec postgres psql -U netguard -d netguard
```
Commandes utiles : `\dt` (tables), `SELECT count(*) FROM users;`, `\q` (quitter).

### Sauvegarde (backup)
```bash
docker compose exec -T postgres pg_dump -U netguard netguard > backup_$(date +%F).sql
```

### Restauration
```bash
cat backup_2026-06-29.sql | docker compose exec -T postgres psql -U netguard -d netguard
```

### Sauvegarde automatique quotidienne (cron)
```bash
crontab -e
# Ajouter (backup à 3h, conserve 7 jours) :
0 3 * * * cd ~/netguard && docker compose exec -T postgres pg_dump -U netguard netguard > ~/backups/db_$(date +\%F).sql && find ~/backups -name 'db_*.sql' -mtime +7 -delete
```

### ⚠️ Ne jamais supprimer le volume
`docker compose down -v` **détruit la base**. Utilise `docker compose down`
(sans `-v`) pour arrêter sans perdre les données.

---

## 7. Voir les logs

```bash
docker compose logs -f netguard      # logs de l'app en direct
docker compose logs --tail=100 netguard
docker compose logs postgres         # logs de la base
```

Les logs applicatifs sont structurés : `[API]` (requêtes/erreurs serveur),
`[SCAN]` (déroulé d'un scan), `[DB]` (état base). Chaque scan est tracé avec son
`scanId` et le `userId`.

Pour persister/rotater les logs au-delà des conteneurs, ajoute dans
`docker-compose.yml` sous le service `netguard` :
```yaml
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "5"
```

---

## 8. Mettre à jour (redéploiement)

Après un `git push` depuis ta machine :
```bash
ssh deploy@TON_IP "cd ~/netguard && bash deploy.sh"
```
`deploy.sh` fait : `git pull` → rebuild → restart → affiche l'état + les logs.
Le volume `pgdata` est conservé, aucune donnée perdue.

---

## 9. Alternative sans Docker (PM2)

Si tu préfères tourner en natif :
```bash
# PostgreSQL natif
apt install -y postgresql nodejs npm
sudo -u postgres createuser netguard -P
sudo -u postgres createdb netguard -O netguard

# App
npm ci --omit=dev
npm install -g pm2
# Renseigner DATABASE_URL + SESSION_SECRET dans .env
pm2 start ecosystem.config.js
pm2 save && pm2 startup     # redémarrage auto au boot
pm2 logs netguard           # voir les logs
```
> Adapte `cwd` dans `ecosystem.config.js` au chemin réel du projet sur le VPS.

---

## Checklist avant ouverture au public

- [ ] `SESSION_SECRET` et `POSTGRES_PASSWORD` forts et générés aléatoirement
- [ ] `COOKIE_SECURE=true` + HTTPS actif (Caddy)
- [ ] `CORS_ORIGINS` = ton domaine exact (pas `*`)
- [ ] Pare-feu : seuls 22/80/443 ouverts ; 5050 et 5432 fermés
- [ ] `/healthz` répond `ok`
- [ ] Sauvegarde DB automatisée (cron) et **testée** (restauration vérifiée)
- [ ] `.env` **absent** de Git (`git status` ne doit pas le lister)
- [ ] Connexion SSH par clé, mot de passe root désactivé

---

## Dépannage

| Symptôme | Cause probable / solution |
|----------|---------------------------|
| App `unhealthy` au démarrage | DB pas prête → vérifier `docker compose logs postgres` |
| `db:"memory"` sur `/healthz` | `DATABASE_URL`/`POSTGRES_PASSWORD` mal configuré |
| Déconnexion à chaque restart | Sessions en mémoire → vérifier que la DB est bien active |
| 401 sur `/api/scan` | Pas connecté, ou cookie bloqué (vérifier HTTPS + `COOKIE_SECURE`) |
| Cookie non envoyé | `COOKIE_SECURE=true` mais site en HTTP → passer en HTTPS |
| Certificat TLS échoue | DNS pas encore propagé vers l'IP du VPS |
