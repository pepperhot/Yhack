# Yhack — Outil de test de sécurité web

Outil de penetration testing pour évaluer la sécurité de sites web. Tests réels de vulnérabilités avec limites strictes.

## ⚠️ Avertissement légal

**Utilisez uniquement sur des sites pour lesquels vous avez une autorisation écrite explicite.** Les tests de sécurité (SQL injection, XSS, brute-force) sont réels mais limités. L'utilisation non autorisée est illégale.

## Installation

```powershell
npm install
npm run start
```

**Note** : Puppeteer sera installé automatiquement avec `npm install`. Il permet l'automatisation du navigateur pour le module Mako (barre de recherche).

L'API écoute sur `http://localhost:5050`.

## Modules de test

### Tests passifs (non-intrusifs)
- **DNS** : Résolution DNS
- **TLS** : Vérification certificat et protocole
- **Headers** : Analyse des en-têtes de sécurité (CSP, HSTS, etc.)
- **CMS** : Détection de technologies (WordPress, Drupal, etc.)
- **Subdomains** : Découverte via crt.sh (source passive)
- **Ports** : Scan TCP de ports communs (80, 443, 22, etc.)

### Tests actifs (avec limites strictes)
- **SQL Injection** : Tests avec payloads SQL classiques (500+ requêtes possibles)
- **XSS** : Tests de Cross-Site Scripting (378+ requêtes possibles)
- **Brute-force** : Tests de rate limiting (max 6 tentatives)
- **Mako Template Injection (SSTI)** : Tests avec navigateur automatisé (Puppeteer) + fetch
  - Automatise la barre de recherche du site
  - Teste 100+ payloads Mako avec `popen().read()`
  - Récupère automatiquement le flag

## Garde-fous implémentés

- Limites strictes sur le nombre de requêtes par module
- Délais entre requêtes (200-500ms)
- Timeouts courts (2-3s)
- User-Agent identifié : `Yhack-Security-Scanner/1.0`
- Pas d'exploitation destructive, uniquement détection

## Structure

- `index.html` — Interface frontend
- `styles.css` — Styles
- `script.js` — Logique frontend (scan backend + fallback mock)
- `server/index.js` — API Express
- `server/scanManager.js` — Modules de scan

## Utilisation

1. Démarrer le backend : `npm run start`
2. Ouvrir `index.html` dans le navigateur
3. Entrer une URL (avec autorisation !)
4. Consulter le rapport synthétique après le scan

## Notes

- Les tests sont limités pour éviter la surcharge
- Les résultats sont affichés en temps réel dans le terminal
- Le rapport inclut un score global et des recommandations

