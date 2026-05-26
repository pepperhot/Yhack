#!/bin/bash
# deploy.sh — À exécuter sur le VPS après un git pull
# Usage : ssh user@vps "cd ~/yhack && bash deploy.sh"

set -e

echo "📦 Pull des dernières modifications..."
git pull origin main

echo "🐳 Rebuild et redémarrage des conteneurs..."
docker compose up -d --build

echo "🧹 Nettoyage des images inutilisées..."
docker image prune -f

echo "✅ Déployé ! Logs :"
docker compose logs --tail=20 netguard
