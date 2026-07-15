'use strict';

// ── Auth ───────────────────────────────────────────────────────────────────────
(function auth() {
  const API      = window.location.origin;
  const overlay  = document.getElementById('authOverlay');
  const navUser  = document.getElementById('navUser');
  const emailEl  = document.getElementById('navUserEmail');
  const logoutBtn = document.getElementById('logoutBtn');

  function showApp(user) {
    if (overlay)  overlay.hidden = true;
    if (navUser)  navUser.hidden = false;
    if (emailEl)  emailEl.textContent = user.email;
    document.dispatchEvent(new CustomEvent('ng:auth', { detail: user }));
  }

  function showAuth() {
    if (overlay)  overlay.hidden = false;
    if (navUser)  navUser.hidden = true;
    document.dispatchEvent(new CustomEvent('ng:logout'));
  }

  // Check existing session on load
  fetch(API + '/api/auth/me', { credentials: 'same-origin' })
    .then(r => r.ok ? r.json() : null)
    .then(data => { if (data?.user) showApp(data.user); else showAuth(); })
    .catch(() => showAuth());

  // Sliding panel switching
  const container = document.getElementById('authContainer');
  function setMode(mode) {
    if (!container) return;
    container.classList.toggle('is-register', mode === 'register');
    const errLogin = document.getElementById('loginError');
    const errReg   = document.getElementById('registerError');
    if (errLogin) errLogin.hidden = true;
    if (errReg)   errReg.hidden   = true;
  }
  document.querySelectorAll('[data-switch]').forEach(btn => {
    btn.addEventListener('click', () => setMode(btn.dataset.switch));
  });

  // Login
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    loginForm.addEventListener('submit', async e => {
      e.preventDefault();
      const email    = document.getElementById('loginEmail').value.trim();
      const password = document.getElementById('loginPassword').value;
      const errEl    = document.getElementById('loginError');
      const btn      = loginForm.querySelector('button[type="submit"]');
      errEl.hidden   = true;
      btn.disabled   = true;
      btn.textContent = 'Connexion…';
      try {
        const res  = await fetch(API + '/api/auth/login', {
          method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Connexion échouée');
        showApp(data.user);
      } catch (err) {
        errEl.textContent = err.message;
        errEl.hidden = false;
      } finally {
        btn.disabled = false;
        btn.textContent = 'Se connecter';
      }
    });
  }

  // Register
  const registerForm = document.getElementById('registerForm');
  if (registerForm) {
    registerForm.addEventListener('submit', async e => {
      e.preventDefault();
      const email    = document.getElementById('regEmail').value.trim();
      const password = document.getElementById('regPassword').value;
      const confirm  = document.getElementById('regConfirm').value;
      const errEl    = document.getElementById('registerError');
      const btn      = registerForm.querySelector('button[type="submit"]');
      errEl.hidden   = true;
      if (password !== confirm) {
        errEl.textContent = 'Les mots de passe ne correspondent pas';
        errEl.hidden = false;
        return;
      }
      btn.disabled = true;
      btn.textContent = 'Création…';
      try {
        const res  = await fetch(API + '/api/auth/register', {
          method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Inscription échouée');
        showApp(data.user);
      } catch (err) {
        errEl.textContent = err.message;
        errEl.hidden = false;
      } finally {
        btn.disabled = false;
        btn.textContent = 'Créer mon compte';
      }
    });
  }

  // Logout
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      await fetch(API + '/api/auth/logout', { method: 'POST', credentials: 'same-origin' }).catch(() => {});
      showAuth();
    });
  }
})();

(function setYear() {
  const yearEl = document.getElementById('year');
  if (yearEl) yearEl.textContent = String(new Date().getFullYear());
})();

(function scanForm() {
  const form  = document.querySelector('.scan-form');
  if (!form) return;

  const input  = form.querySelector('input[type="url"]');
  const termEl = document.getElementById('terminalBody');

  const API_URL      = window.location.origin; // s'adapte automatiquement peu importe le serveur
  const POLL_INTERVAL = 800;

  function escHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function writeLine(line) {
    if (!termEl) return;
    termEl.innerHTML += '\n' + line;
    const pre = termEl.parentElement;
    if (pre) pre.scrollTop = pre.scrollHeight;
  }

  function resetTerminal(command) {
    if (!termEl) return;
    termEl.textContent = '';
    termEl.innerHTML = '<span class="mono-dim">$</span> ' + command;
  }

  function mapResultsToStatus(results) {
    if (!results) return {};
    const keys = [
      'dns', 'tls', 'headers', 'cors', 'cookies', 'tech',
      'sensitive_files', 'robots', 'ports',
      'https_redirect', 'mixed_content', 'dir_listing',
      'sqli', 'xss', 'lfi', 'rce', 'mako',
      'open_redirect', 'http_methods', 'host_injection', 'error_disclosure', 'vulns',
    ];
    const map = {};
    keys.forEach(k => { if (results[k]?.status) map[k] = results[k].status; });
    return map;
  }

  function buildReport(statuses, fullResults, scanMeta) {
    const reportSection = document.getElementById('fullReport');
    if (!reportSection) return;

    // ── Score ─────────────────────────────────────────────────────────────────
    const scored = [
      { key: 'sqli', w: 3 }, { key: 'xss', w: 3 }, { key: 'rce', w: 3 },
      { key: 'lfi',  w: 3 }, { key: 'mako', w: 3 },
      { key: 'tls',  w: 2 }, { key: 'headers', w: 2 }, { key: 'cors', w: 2 },
      { key: 'mixed_content', w: 2 }, { key: 'host_injection', w: 2 },
      { key: 'dns',  w: 1 }, { key: 'cookies', w: 1 }, { key: 'ports', w: 1 },
      { key: 'sensitive_files', w: 1 }, { key: 'robots', w: 1 },
      { key: 'tech', w: 1 }, { key: 'open_redirect', w: 1 }, { key: 'http_methods', w: 1 },
      { key: 'https_redirect', w: 1 }, { key: 'dir_listing', w: 1 }, { key: 'error_disclosure', w: 1 },
    ];
    let pts = 0, total = 0;
    scored.forEach(({ key, w }) => {
      const st = statuses[key];
      if (!st || st === 'ERROR') return;   // module non analysé : exclu du score
      pts += w * (st === 'OK' ? 1 : st === 'WARN' ? 0.5 : 0);
      total += w;
    });
    const pct   = total > 0 ? Math.round((pts / total) * 100) : 0;
    const grade = pct >= 90 ? 'A' : pct >= 75 ? 'B' : pct >= 60 ? 'C' : pct >= 40 ? 'D' : 'F';
    const gc    = { A: '#00ffa3', B: '#7fff7f', C: '#ffd166', D: '#ff9a3c', F: '#ff5c8a' }[grade];

    // ── Animate ring ──────────────────────────────────────────────────────────
    const ringFill  = document.getElementById('gradeRingFill');
    const gLetter   = document.getElementById('gradeLetter');
    const scoreNum  = document.getElementById('scoreNum');
    const circ      = 2 * Math.PI * 34; // ≈213.6

    if (ringFill) {
      ringFill.style.strokeDasharray  = circ;
      ringFill.style.strokeDashoffset = String(circ);
      ringFill.style.stroke = gc;
      requestAnimationFrame(() => requestAnimationFrame(() => {
        ringFill.style.strokeDashoffset = String(circ * (1 - pct / 100));
      }));
    }
    if (gLetter) { gLetter.textContent = grade; gLetter.style.color = gc; }
    if (scoreNum) scoreNum.textContent = String(pct);

    // ── Meta ──────────────────────────────────────────────────────────────────
    const reportMetaEl = document.getElementById('reportMeta');
    if (reportMetaEl) {
      const crits = fullResults?.vulns?.critical_issues || 0;
      const warns = fullResults?.vulns?.warnings        || 0;
      const errs  = fullResults?.vulns?.errors          || 0;
      const dur   = scanMeta?.duration_ms ? Math.round(scanMeta.duration_ms / 1000) + 's' : '';
      reportMetaEl.innerHTML = `
        <div class="meta-target">${escHtml(scanMeta?.target || '')}</div>
        <div class="meta-stats">
          ${crits > 0 ? `<span class="meta-badge meta-badge--red">${crits} critique${crits > 1 ? 's' : ''}</span>` : ''}
          ${warns > 0 ? `<span class="meta-badge meta-badge--yellow">${warns} avertissement${warns > 1 ? 's' : ''}</span>` : ''}
          ${crits === 0 && warns === 0 ? '<span class="meta-badge meta-badge--green">Aucun problème</span>' : ''}
          ${errs > 0 ? `<span class="meta-badge meta-badge--gray">${errs} non analysé${errs > 1 ? 's' : ''}</span>` : ''}
          ${dur ? `<span class="meta-badge">⏱ ${escHtml(dur)}</span>` : ''}
        </div>
      `;
    }

    // ── Module cards ──────────────────────────────────────────────────────────
    const MODULE_META = [
      { key: 'dns',             label: 'DNS',           note: 'Résolution & enregistrements' },
      { key: 'tls',             label: 'TLS/SSL',       note: 'Certificat & chiffrement' },
      { key: 'headers',         label: 'En-têtes',      note: 'Headers de sécurité HTTP' },
      { key: 'cors',            label: 'CORS',          note: 'Cross-Origin Policy' },
      { key: 'cookies',         label: 'Cookies',       note: 'HttpOnly / Secure / SameSite' },
      { key: 'tech',            label: 'Technologies',  note: 'Stack & disclosure' },
      { key: 'sensitive_files', label: 'Fichiers',      note: '.env, .git, backups...' },
      { key: 'robots',          label: 'robots.txt',    note: 'Chemins révélés' },
      { key: 'ports',           label: 'Ports TCP',     note: 'Services exposés' },
      { key: 'https_redirect',  label: 'HTTPS Redirect',note: 'HTTP → HTTPS forcé' },
      { key: 'mixed_content',   label: 'Mixed Content', note: 'Ressources http & SRI' },
      { key: 'dir_listing',     label: 'Dir Listing',   note: 'Répertoires ouverts' },
      { key: 'sqli',            label: 'SQLi',          note: 'Error-based & blind' },
      { key: 'xss',             label: 'XSS',           note: 'Scripting réfléchi' },
      { key: 'lfi',             label: 'LFI',           note: 'File Inclusion locale' },
      { key: 'rce',             label: 'RCE',           note: 'Exécution de code' },
      { key: 'mako',            label: 'SSTI',          note: 'Template Injection' },
      { key: 'open_redirect',   label: 'Redirect',      note: 'Open Redirect' },
      { key: 'http_methods',    label: 'Méthodes HTTP', note: 'PUT, DELETE, TRACE' },
      { key: 'host_injection',  label: 'Host Header',   note: 'Injection / poisoning' },
      { key: 'error_disclosure',label: 'Erreurs',       note: 'Stack traces exposées' },
    ];

    const modulesGrid = document.getElementById('modulesGrid');
    if (modulesGrid) {
      modulesGrid.innerHTML = '';
      MODULE_META.forEach(({ key, label, note }) => {
        const st  = statuses[key];
        if (!st) return;
        const cls   = st === 'OK' ? 'ok' : st === 'WARN' ? 'warn' : st === 'ERROR' ? 'error' : 'fail';
        const badge = st === 'OK' ? '✓ OK' : st === 'WARN' ? '⚠ WARN' : st === 'ERROR' ? '⚠ N/A' : '✗ FAIL';
        const div   = document.createElement('div');
        div.className = `module-card module-card--${cls}`;
        const hasExploit = cls !== 'ok' && cls !== 'error' && fullResults?.[key]?.exploitation;
        // Pour un module non analysé, on affiche la raison (cible injoignable…) au lieu de la note générique.
        const noteText = st === 'ERROR' ? (fullResults?.[key]?.error || 'Cible injoignable') : note;
        div.innerHTML = `
          ${hasExploit ? `<button class="info-btn" data-key="${escHtml(key)}" title="Voir pourquoi &amp; comment exploiter" aria-label="Détails d'exploitation pour ${escHtml(label)}">i</button>` : ''}
          <div class="module-card__name">${escHtml(label)}</div>
          <div class="module-card__status module-card__status--${cls}">${badge}</div>
          <div class="module-card__note">${escHtml(noteText)}</div>
        `;
        modulesGrid.appendChild(div);
      });

      // Delegated click for all info buttons in this grid
      modulesGrid.addEventListener('click', function (e) {
        const btn = e.target.closest('.info-btn');
        if (!btn) return;
        showInfoModal(btn.dataset.key, MODULE_META, fullResults);
      });
    }

    // ── Improvements ─────────────────────────────────────────────────────────
    const NAMES = {
      headers:         'En-têtes de sécurité HTTP',
      tls:             'Chiffrement TLS/SSL',
      cors:            'Configuration CORS',
      cookies:         'Sécurité des cookies',
      sensitive_files: 'Fichiers sensibles exposés',
      robots:          'Disclosure via robots.txt',
      ports:           'Ports TCP exposés',
      sqli:            'SQL Injection',
      xss:             'Cross-Site Scripting',
      lfi:             'Local File Inclusion',
      rce:             'Remote Code Execution',
      mako:            'Server-Side Template Injection',
      open_redirect:   'Open Redirect',
      http_methods:    'Méthodes HTTP dangereuses',
      dns:             'Configuration DNS',
      tech:            'Exposition des technologies',
      https_redirect:  'Redirection HTTPS non forcée',
      mixed_content:   'Contenu mixte / SRI manquant',
      dir_listing:     'Listing de répertoires',
      host_injection:  'Injection Host Header',
      error_disclosure:'Fuite de messages d\'erreur',
    };

    const improvements = [];
    if (fullResults) {
      Object.entries(fullResults).forEach(([key, result]) => {
        if (!result || result.status === 'OK' || key === 'vulns') return;
        const exp = result.exploitation;
        if (!exp) return;
        const cvss   = exp.cvss || (result.status === 'FAIL' ? 7.0 : 4.0);
        const sevKey = cvss >= 9 ? 'critique' : cvss >= 7 ? 'eleve' : cvss >= 4 ? 'moyen' : 'faible';
        const sevLbl = { critique: 'CRITIQUE', eleve: 'ÉLEVÉ', moyen: 'MOYEN', faible: 'FAIBLE' }[sevKey];
        improvements.push({ key, name: NAMES[key] || key, cvss, sevKey, sevLbl, exp });
      });
      improvements.sort((a, b) => b.cvss - a.cvss);
    }

    const improvList    = document.getElementById('improvementsList');
    const improvSection = document.getElementById('improvSection');
    const improvCount   = document.getElementById('improvCount');
    const allClear      = document.getElementById('allClearMsg');

    if (improvList) {
      improvList.innerHTML = '';
      improvements.forEach(({ name, cvss, sevKey, sevLbl, exp }) => {
        const card = document.createElement('div');
        card.className = `improv-card improv-card--${sevKey}`;
        const toolsHtml = (exp.tools || []).map(t => `<span class="tool-tag">${escHtml(t)}</span>`).join('');
        card.innerHTML = `
          <div class="improv-header">
            <span class="improv-severity improv-severity--${sevKey}">${escHtml(sevLbl)}</span>
            <span class="improv-title">${escHtml(name)}</span>
            <span class="improv-cvss">CVSS ${cvss.toFixed(1)}</span>
          </div>
          <p class="improv-desc">${escHtml(exp.description || '')}</p>
          ${exp.impact      ? `<div class="improv-impact">${escHtml(exp.impact)}</div>`      : ''}
          ${exp.remediation ? `<div class="improv-fix">${escHtml(exp.remediation)}</div>`   : ''}
          ${toolsHtml ? `<div class="improv-tools">${toolsHtml}</div>` : ''}
        `;
        improvList.appendChild(card);
      });
    }

    if (improvSection) improvSection.hidden = improvements.length === 0;
    if (improvCount)   improvCount.textContent = String(improvements.length);
    if (allClear)      allClear.hidden = improvements.length > 0;

    reportSection.hidden = false;
    setTimeout(() => reportSection.scrollIntoView({ behavior: 'smooth', block: 'start' }), 120);
  }

  // ── Info Modal ─────────────────────────────────────────────────────────────
  const infoModal        = document.getElementById('infoModal');
  const infoModalClose   = document.getElementById('infoModalClose');
  const infoModalBackdrop = document.getElementById('infoModalBackdrop');

  function closeInfoModal() {
    if (infoModal) infoModal.hidden = true;
  }

  if (infoModalClose)   infoModalClose.addEventListener('click', closeInfoModal);
  if (infoModalBackdrop) infoModalBackdrop.addEventListener('click', closeInfoModal);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeInfoModal();
  });

  function showInfoModal(key, moduleMeta, results) {
    if (!infoModal) return;
    const exp  = results?.[key]?.exploitation;
    if (!exp) return;

    const meta  = moduleMeta.find(function (m) { return m.key === key; });
    const label = meta ? meta.label : key;

    const cvss   = exp.cvss || (results[key].status === 'FAIL' ? 7.0 : 4.0);
    const sevKey = cvss >= 9 ? 'critique' : cvss >= 7 ? 'eleve' : cvss >= 4 ? 'moyen' : 'faible';
    const sevLbl = { critique: 'CRITIQUE', eleve: 'ÉLEVÉ', moyen: 'MOYEN', faible: 'FAIBLE' }[sevKey];

    const desc = exp.description ||
      (exp.missing_headers && exp.missing_headers.length
        ? exp.missing_headers.length + ' en-tête(s) de sécurité critique(s) absents.'
        : '');

    // Code blocks
    const CODE_FIELDS = [
      { field: 'example',      label: 'Exemple' },
      { field: 'manual',       label: 'Manuel' },
      { field: 'reverse_shell',label: 'Reverse shell' },
      { field: 'log_poisoning',label: 'Log poisoning' },
      { field: 'web_shell',    label: 'Web shell' },
      { field: 'beef_hook',    label: 'BeEF hook' },
      { field: 'phishing',     label: 'Phishing URL' },
      { field: 'oauth_abuse',  label: 'Abus OAuth' },
      { field: 'math_proof',   label: 'Preuve d\'évaluation' },
      { field: 'rce_payload',  label: 'Payload RCE' },
    ];

    let codesHtml = '';
    CODE_FIELDS.forEach(function (cf) {
      if (exp[cf.field]) {
        codesHtml += '<div class="info-code-block">' +
          '<div class="info-code-label">' + escHtml(cf.label) + '</div>' +
          '<pre class="info-code">' + escHtml(exp[cf.field]) + '</pre>' +
          '</div>';
      }
    });

    // Missing headers (special case for headers module)
    let headersHtml = '';
    if (exp.missing_headers && exp.missing_headers.length) {
      headersHtml = '<div class="info-missing-headers">';
      exp.missing_headers.forEach(function (h) {
        const sev = h.severity === 'HIGH' ? 'eleve' : h.severity === 'MEDIUM' ? 'moyen' : 'faible';
        headersHtml +=
          '<div class="info-header-row">' +
            '<span class="improv-severity improv-severity--' + sev + '">' + escHtml(h.severity) + '</span>' +
            '<span class="info-header-name">' + escHtml(h.header) + '</span>' +
            '<span class="info-header-scenario">' + escHtml(h.scenario || '') + '</span>' +
          '</div>';
      });
      headersHtml += '</div>';
    }

    // Info leakage (headers module)
    if (exp.info_leakage && exp.info_leakage.length) {
      exp.info_leakage.forEach(function (l) {
        codesHtml += '<div class="info-code-block">' +
          '<div class="info-code-label">Disclosure : ' + escHtml(l.header) + '</div>' +
          '<pre class="info-code">' + escHtml(l.header + ': ' + l.value) + '</pre>' +
          '</div>';
      });
    }

    const toolsHtml = (exp.tools || [])
      .map(function (t) { return '<span class="tool-tag">' + escHtml(t) + '</span>'; })
      .join('');

    document.getElementById('infoModalContent').innerHTML =
      '<div class="info-modal-header">' +
        '<span class="improv-severity improv-severity--' + sevKey + '">' + escHtml(sevLbl) + '</span>' +
        '<span class="info-modal-title">' + escHtml(label) + '</span>' +
        (cvss ? '<span class="improv-cvss">CVSS&nbsp;' + cvss.toFixed(1) + '</span>' : '') +
      '</div>' +
      (desc ? '<p class="improv-desc info-modal-desc">' + escHtml(desc) + '</p>' : '') +
      headersHtml +
      codesHtml +
      (exp.impact      ? '<div class="improv-impact">' + escHtml(exp.impact) + '</div>'      : '') +
      (exp.remediation ? '<div class="improv-fix">'    + escHtml(exp.remediation) + '</div>' : '') +
      (toolsHtml       ? '<div class="improv-tools">'  + toolsHtml + '</div>'                : '');

    infoModal.hidden = false;
    infoModal.focus();
  }

  // ── Backend scan + polling ─────────────────────────────────────────────────
  async function runBackendScan(targetUrl, mode, authorized) {
    try {
      writeLine('<span class="mono-dim"># Initializing backend scan (' + (mode || 'passive') + ')...</span>');

      const createRes = await fetch(API_URL + '/api/scan', {
        method:      'POST',
        credentials: 'same-origin',
        headers:     { 'Content-Type': 'application/json' },
        body:        JSON.stringify({ targetUrl, mode: mode || 'passive', authorized: !!authorized }),
      });

      if (!createRes.ok) {
        let errMsg = `Erreur serveur (HTTP ${createRes.status})`;
        try {
          const ct = createRes.headers.get('content-type') || '';
          if (ct.includes('application/json')) {
            const err = await createRes.json();
            errMsg = err.error || errMsg;
          } else if (createRes.status === 401) {
            errMsg = 'Non authentifié — connectez-vous avant de lancer un scan';
          }
        } catch (_) {}
        throw new Error(errMsg);
      }

      const { scanId } = await createRes.json();
      writeLine(`<span class="mono-dim"># Scan ID: ${escHtml(scanId)}</span>`);

      let lastLen = 0;
      let pollErrors = 0;
      const MAX_POLL_ERRORS = 5;

      return new Promise((resolve, reject) => {
        const poll = setInterval(async () => {
          try {
            const pollRes = await fetch(API_URL + '/api/scan/' + scanId, { credentials: 'same-origin' });
            if (!pollRes.ok) throw new Error('Poll failed (' + pollRes.status + ')');
            const j = await pollRes.json();
            pollErrors = 0; // reset on success

            if (j.lines && j.lines.length > lastLen) {
              for (let i = lastLen; i < j.lines.length; i++) writeLine(j.lines[i]);
              lastLen = j.lines.length;
            }

            if (j.status === 'done') {
              clearInterval(poll);
              writeLine('<span class="mono-dim"># Scan completed ✓</span>');
              try {
                buildReport(mapResultsToStatus(j.results), j.results, j);
                loadHistory();
              } catch (reportErr) {
                console.error('buildReport error:', reportErr);
                writeLine('<span class="mono-intense-red"># Erreur lors de la génération du rapport</span>');
              }
              resolve(true);
            } else if (j.status === 'error') {
              clearInterval(poll);
              writeLine(`<span class="mono-intense-red"># Scan error: ${escHtml(j.results?.error)}</span>`);
              reject(new Error(j.results?.error || 'Unknown error'));
            }
          } catch (e) {
            pollErrors++;
            if (pollErrors >= MAX_POLL_ERRORS) {
              clearInterval(poll);
              writeLine(`<span class="mono-intense-red"># Connection lost after ${MAX_POLL_ERRORS} retries: ${escHtml(e.message)}</span>`);
              reject(e);
            }
            // else: ignore transient error, keep polling
          }
        }, POLL_INTERVAL);

        setTimeout(() => { clearInterval(poll); reject(new Error('Scan timeout (5 minutes)')); }, 300000);
      });
    } catch (e) {
      writeLine(`<span class="mono-intense-red"># Backend error: ${escHtml(e.message)}</span>`);
      throw e;
    }
  }

  // ── Historique / Mes scans ─────────────────────────────────────────────────
  const historyBtn     = document.getElementById('historyBtn');
  const newScanBtn      = document.getElementById('newScanBtn');
  const historyRefresh  = document.getElementById('historyRefresh');
  const historySection  = document.getElementById('historySection');
  const historyList     = document.getElementById('historyList');
  const historyEmpty    = document.getElementById('historyEmpty');
  const reportSectionEl = document.getElementById('fullReport');

  function fmtDate(s) {
    if (!s) return '';
    try {
      const iso = s.includes('T') ? s : s.replace(' ', 'T') + 'Z';
      return new Date(iso).toLocaleString('fr-FR');
    } catch (_) { return s; }
  }

  async function loadHistory() {
    if (!historyList) return;
    try {
      const res = await fetch(API_URL + '/api/scans', { credentials: 'same-origin' });
      if (!res.ok) return;
      const { scans } = await res.json();
      historyList.innerHTML = '';
      if (!scans || !scans.length) { if (historyEmpty) historyEmpty.hidden = false; return; }
      if (historyEmpty) historyEmpty.hidden = true;
      scans.forEach(s => {
        const cls   = s.status === 'done' ? 'ok' : s.status === 'error' ? 'fail' : 'warn';
        const badge = s.status === 'done' ? 'Terminé' : s.status === 'error' ? 'Erreur'
                    : s.status === 'running' ? 'En cours' : s.status;
        const dur   = s.duration_ms ? Math.round(s.duration_ms / 1000) + 's' : '';
        const item  = document.createElement('button');
        item.className = 'history-item';
        item.type = 'button';
        item.dataset.id = s.id;
        item.innerHTML = `
          <span class="history-item__target">${escHtml(s.target)}</span>
          <span class="history-item__meta">
            <span class="history-badge history-badge--${cls}">${escHtml(badge)}</span>
            <span class="history-date">${escHtml(fmtDate(s.created_at))}</span>
            ${dur ? `<span class="history-dur">⏱ ${escHtml(dur)}</span>` : ''}
          </span>`;
        historyList.appendChild(item);
      });
    } catch (_) {}
  }

  if (historyList) {
    historyList.addEventListener('click', async (e) => {
      const item = e.target.closest('.history-item');
      if (!item) return;
      try {
        const res = await fetch(API_URL + '/api/scan/' + item.dataset.id, { credentials: 'same-origin' });
        if (!res.ok) return;
        const scan = await res.json();
        if (scan.status !== 'done' || !scan.results) {
          alert('Rapport indisponible pour ce scan (statut : ' + scan.status + ').');
          return;
        }
        buildReport(mapResultsToStatus(scan.results), scan.results, scan);
      } catch (_) {}
    });
  }

  function showHistory() {
    if (historySection) historySection.hidden = false;
    if (reportSectionEl) reportSectionEl.hidden = true;
    loadHistory();
    if (historySection) historySection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  if (historyBtn)     historyBtn.addEventListener('click', showHistory);
  if (historyRefresh) historyRefresh.addEventListener('click', loadHistory);
  if (newScanBtn)     newScanBtn.addEventListener('click', () => {
    if (historySection)  historySection.hidden = true;
    document.getElementById('scan')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

  document.addEventListener('ng:auth',   () => { loadHistory(); });
  document.addEventListener('ng:logout', () => { if (historySection) historySection.hidden = true; });

  // ── Domaines vérifiés ──────────────────────────────────────────────────────
  const domainsBtn     = document.getElementById('domainsBtn');
  const domainsSection = document.getElementById('domainsSection');
  const domainsList    = document.getElementById('domainsList');
  const domainAddForm  = document.getElementById('domainAddForm');
  const domainInput    = document.getElementById('domainInput');
  const domainAddError = document.getElementById('domainAddError');

  function renderDomain(d) {
    const el = document.createElement('div');
    el.className = 'domain-card ' + (d.verified ? 'domain-card--ok' : 'domain-card--pending');
    el.dataset.id = d.id;
    if (d.verified) {
      el.innerHTML = `
        <div class="domain-card__head">
          <span class="domain-name">${escHtml(d.domain)}</span>
          <span class="history-badge history-badge--ok">✓ Vérifié</span>
          <button class="btn btn--ghost btn--sm domain-del" type="button">Supprimer</button>
        </div>
        <p class="domain-hint">Scans actifs débloqués sur ${escHtml(d.domain)} et ses sous-domaines.</p>`;
    } else {
      el.innerHTML = `
        <div class="domain-card__head">
          <span class="domain-name">${escHtml(d.domain)}</span>
          <span class="history-badge history-badge--warn">En attente</span>
          <button class="btn btn--primary btn--sm domain-verify" type="button">Vérifier</button>
          <button class="btn btn--ghost btn--sm domain-del" type="button">Supprimer</button>
        </div>
        <p class="domain-hint">Prouvez la propriété par <strong>l'une</strong> de ces méthodes, puis cliquez « Vérifier » :</p>
        <div class="domain-proof">
          <div class="domain-proof__label">Option A — Enregistrement TXT DNS sur <code>${escHtml(d.domain)}</code> :</div>
          <pre class="info-code">${escHtml(d.token)}</pre>
          <div class="domain-proof__label">Option B — Fichier <code>https://${escHtml(d.domain)}/.well-known/netguard-verify.txt</code> contenant :</div>
          <pre class="info-code">${escHtml(d.token)}</pre>
        </div>`;
    }
    return el;
  }

  async function loadDomains() {
    if (!domainsList) return;
    try {
      const res = await fetch(API_URL + '/api/domains', { credentials: 'same-origin' });
      if (!res.ok) return;
      const { domains } = await res.json();
      domainsList.innerHTML = '';
      if (!domains.length) {
        domainsList.innerHTML = '<p class="history-empty">Aucun domaine. Ajoutez-en un pour débloquer les scans actifs.</p>';
        return;
      }
      domains.forEach(d => domainsList.appendChild(renderDomain(d)));
    } catch (_) {}
  }

  if (domainAddForm) {
    domainAddForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (domainAddError) domainAddError.hidden = true;
      const domain = (domainInput && domainInput.value || '').trim();
      if (!domain) return;
      try {
        const res  = await fetch(API_URL + '/api/domains', {
          method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Ajout impossible');
        if (domainInput) domainInput.value = '';
        loadDomains();
      } catch (err) {
        if (domainAddError) { domainAddError.textContent = err.message; domainAddError.hidden = false; }
      }
    });
  }

  if (domainsList) {
    domainsList.addEventListener('click', async (e) => {
      const card = e.target.closest('.domain-card');
      if (!card) return;
      const id = card.dataset.id;

      if (e.target.closest('.domain-verify')) {
        const btn = e.target.closest('.domain-verify');
        btn.disabled = true; btn.textContent = 'Vérification…';
        try {
          const res  = await fetch(API_URL + '/api/domains/' + id + '/verify', {
            method: 'POST', credentials: 'same-origin',
          });
          const data = await res.json();
          if (!res.ok) throw new Error(data.error || 'Vérification échouée');
          loadDomains();
        } catch (err) {
          btn.disabled = false; btn.textContent = 'Vérifier';
          alert(err.message);
        }
      } else if (e.target.closest('.domain-del')) {
        if (!confirm('Supprimer ce domaine ? Les scans actifs seront rebloqués dessus.')) return;
        await fetch(API_URL + '/api/domains/' + id, { method: 'DELETE', credentials: 'same-origin' });
        loadDomains();
      }
    });
  }

  function showDomains() {
    if (domainsSection) domainsSection.hidden = false;
    if (historySection) historySection.hidden = true;
    if (reportSectionEl) reportSectionEl.hidden = true;
    loadDomains();
    if (domainsSection) domainsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  if (domainsBtn) domainsBtn.addEventListener('click', showDomains);
  document.addEventListener('ng:logout', () => { if (domainsSection) domainsSection.hidden = true; });

  // ── Form submit ────────────────────────────────────────────────────────────
  let scanning = false;
  const submitBtn = form.querySelector('button[type="submit"]');

  function setScanningState(active) {
    scanning = active;
    if (submitBtn) {
      submitBtn.disabled = active;
      submitBtn.textContent = active ? 'Analyse en cours…' : 'Analyser';
    }
    if (input) input.disabled = active;
  }

  // Mode passif/actif : la case d'attestation n'apparaît qu'en mode actif.
  const authorizeBox = document.getElementById('scanAuthorize');
  const authorizeChk = document.getElementById('authorizeCheck');
  function currentMode() {
    const el = form.querySelector('input[name="scanMode"]:checked');
    return el ? el.value : 'passive';
  }
  form.querySelectorAll('input[name="scanMode"]').forEach(r => {
    r.addEventListener('change', () => {
      if (authorizeBox) authorizeBox.hidden = currentMode() !== 'active';
    });
  });

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    if (scanning) return;
    const url  = (input && input.value || '').trim();
    const mode = currentMode();
    const authorized = !!(authorizeChk && authorizeChk.checked);

    if (mode === 'active' && !authorized) {
      alert('Cochez l\'attestation d\'autorisation pour lancer un scan actif.');
      return;
    }

    try {
      if (!url) throw new Error('empty');
      const normalized = url.startsWith('http') ? url : 'https://' + url;
      new URL(normalized);

      resetTerminal(`probe ${normalized} --mode ${mode}`);
      const reportSection = document.getElementById('fullReport');
      if (reportSection) reportSection.hidden = true;

      setScanningState(true);
      runBackendScan(normalized, mode, authorized)
        .catch(err => {
          console.error('Scan error:', err);
          if (/domaine/i.test(err.message) || /DOMAIN_NOT_VERIFIED/.test(err.message)) {
            writeLine(`<span class="mono-intense-red"># ${escHtml(err.message)}</span>`);
            writeLine('<span class="mono-dim"># → Ouvrez « Domaines » pour prouver la propriété de cette cible.</span>');
          } else {
            writeLine(`<span class="mono-intense-red"># ERROR: ${escHtml(err.message)}</span>`);
          }
        })
        .finally(() => setScanningState(false));
    } catch (_) {
      alert('Veuillez saisir une URL valide (ex: https://example.com)');
      if (input) input.focus();
    }
  });
})();

// ── Reveal on scroll ───────────────────────────────────────────────────────────
(function revealOnScroll() {
  const els = Array.prototype.slice.call(document.querySelectorAll('.reveal'));
  if (!('IntersectionObserver' in window) || els.length === 0) {
    els.forEach(function (el) { el.classList.add('is-visible'); });
    return;
  }
  const io = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) { entry.target.classList.add('is-visible'); io.unobserve(entry.target); }
    });
  }, { threshold: 0.15 });
  els.forEach(function (el) { io.observe(el); });
})();
