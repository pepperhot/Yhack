#!/usr/bin/env bash
# Smoke test post-déploiement — valide une instance NetGuard en production.
#
# Usage :
#   bash scripts/smoke-test.sh https://tondomaine.com
#   bash scripts/smoke-test.sh                 # défaut : http://localhost:5050
#
# Ne fait AUCUN scan actif sur une cible tierce. Il crée un compte de test
# jetable (smoketest+<horodatage>@netguard.local) — supprime-le ensuite si tu veux :
#   sqlite3 data/netguard.db "DELETE FROM users WHERE email LIKE 'smoketest+%';"

set -u
BASE="${1:-http://localhost:5050}"
JAR="$(mktemp)"
EMAIL="smoketest+$(date +%s)@netguard.local"
PASS=0; FAIL=0

ok()   { echo "  ✅ $1"; PASS=$((PASS+1)); }
ko()   { echo "  ❌ $1"; FAIL=$((FAIL+1)); }
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }

echo "── Smoke test NetGuard → $BASE ──"

# 1. Santé
[ "$(code "$BASE/healthz")" = "200" ] && ok "healthz répond 200" || ko "healthz KO"
curl -s "$BASE/healthz" | grep -q '"db":"sqlite"' && ok "base = sqlite" || ko "base non sqlite"

# 2. Sécurité : la base et les secrets ne doivent PAS être servis
[ "$(code "$BASE/data/netguard.db")" = "404" ] && ok "/data/netguard.db bloqué (404)" || ko "⚠ BASE TÉLÉCHARGEABLE"
[ "$(code "$BASE/.env")" = "404" ]             && ok "/.env bloqué (404)"             || ko "⚠ .env exposé"

# 3. Auth : non connecté = 401
[ "$(code "$BASE/api/auth/me")" = "401" ] && ok "/api/auth/me = 401 sans session" || ko "auth non protégée"

# 4. Inscription (compte jetable)
curl -s -c "$JAR" -X POST "$BASE/api/auth/register" -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"motdepasse123\"}" | grep -q '"user"' \
  && ok "inscription OK" || ko "inscription KO"

# 5. Scan PASSIF autorisé
curl -s -b "$JAR" -X POST "$BASE/api/scan" -H "Content-Type: application/json" \
  -d '{"targetUrl":"https://example.com","mode":"passive"}' | grep -q '"scanId"' \
  && ok "scan passif accepté" || ko "scan passif KO"

# 6. Scan ACTIF sur un domaine non vérifié → 403
[ "$(code -b "$JAR" -X POST "$BASE/api/scan" -H "Content-Type: application/json" \
  -d '{"targetUrl":"https://example.com","mode":"active"}')" = "403" ] \
  && ok "scan actif sur domaine non vérifié → refusé (403)" || ko "⚠ BRIDAGE DOMAINE KO"

rm -f "$JAR"
echo "──────────────────────────────────"
echo "  $PASS OK / $FAIL échec(s)   (compte de test : $EMAIL)"
[ "$FAIL" -eq 0 ] && echo "  ✅ Prod saine." || { echo "  ❌ À corriger avant d'ouvrir."; exit 1; }
