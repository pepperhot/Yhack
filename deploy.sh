#!/bin/bash
# deploy.sh — À exécuter sur le VPS après un git pull
# Usage : ssh user@vps "cd ~/netguard && bash deploy.sh"

set -e

if [ ! -f .env ]; then
  echo "❌ Fichier .env manquant. Copie : cp .env.example .env puis édite-le."
  exit 1
fi

echo "📦 Pull des dernières modifications..."
git pull origin main

echo "🐳 Rebuild et redémarrage des conteneurs..."
docker compose up -d --build

echo "🧹 Nettoyage des images inutilisées..."
docker image prune -f

echo "✅ Déployé. État des conteneurs :"
docker compose ps

echo "📋 Derniers logs :"
docker compose logs --tail=20 netguard
