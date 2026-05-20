'use strict';

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
    termEl.scrollTop = termEl.scrollHeight;
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
      'sqli', 'xss', 'lfi', 'rce', 'mako',
      'open_redirect', 'http_methods', 'vulns',
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
      { key: 'dns',  w: 1 }, { key: 'cookies', w: 1 }, { key: 'ports', w: 1 },
      { key: 'sensitive_files', w: 1 }, { key: 'robots', w: 1 },
      { key: 'tech', w: 1 }, { key: 'open_redirect', w: 1 }, { key: 'http_methods', w: 1 },
    ];
    let pts = 0, total = 0;
    scored.forEach(({ key, w }) => {
      const st = statuses[key];
      if (st) { pts += w * (st === 'OK' ? 1 : st === 'WARN' ? 0.5 : 0); total += w; }
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
      const dur   = scanMeta?.duration_ms ? Math.round(scanMeta.duration_ms / 1000) + 's' : '';
      reportMetaEl.innerHTML = `
        <div class="meta-target">${escHtml(scanMeta?.target || '')}</div>
        <div class="meta-stats">
          ${crits > 0 ? `<span class="meta-badge meta-badge--red">${crits} critique${crits > 1 ? 's' : ''}</span>` : ''}
          ${warns > 0 ? `<span class="meta-badge meta-badge--yellow">${warns} avertissement${warns > 1 ? 's' : ''}</span>` : ''}
          ${crits === 0 && warns === 0 ? '<span class="meta-badge meta-badge--green">Aucun problème</span>' : ''}
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
      { key: 'sqli',            label: 'SQLi',          note: 'Error-based & blind' },
      { key: 'xss',             label: 'XSS',           note: 'Scripting réfléchi' },
      { key: 'lfi',             label: 'LFI',           note: 'File Inclusion locale' },
      { key: 'rce',             label: 'RCE',           note: 'Exécution de code' },
      { key: 'mako',            label: 'SSTI',          note: 'Template Injection' },
      { key: 'open_redirect',   label: 'Redirect',      note: 'Open Redirect' },
      { key: 'http_methods',    label: 'Méthodes HTTP', note: 'PUT, DELETE, TRACE' },
    ];

    const modulesGrid = document.getElementById('modulesGrid');
    if (modulesGrid) {
      modulesGrid.innerHTML = '';
      MODULE_META.forEach(({ key, label, note }) => {
        const st = statuses[key];
        if (!st) return;
        const cls   = st === 'OK' ? 'ok' : st === 'WARN' ? 'warn' : 'fail';
        const badge = st === 'OK' ? '✓ OK' : st === 'WARN' ? '⚠ WARN' : '✗ FAIL';
        const div   = document.createElement('div');
        div.className = `module-card module-card--${cls}`;
        div.innerHTML = `
          <div class="module-card__name">${escHtml(label)}</div>
          <div class="module-card__status module-card__status--${cls}">${badge}</div>
          <div class="module-card__note">${escHtml(note)}</div>
        `;
        modulesGrid.appendChild(div);
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

  // ── Backend scan + polling ─────────────────────────────────────────────────
  async function runBackendScan(targetUrl) {
    try {
      writeLine('<span class="mono-dim"># Initializing backend scan...</span>');

      const createRes = await fetch(API_URL + '/api/scan', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ targetUrl }),
      });

      if (!createRes.ok) {
        const err = await createRes.json();
        throw new Error(err.error || 'Scan initialization failed');
      }

      const { scanId } = await createRes.json();
      writeLine(`<span class="mono-dim"># Scan ID: ${escHtml(scanId)}</span>`);

      let lastLen = 0;
      return new Promise((resolve, reject) => {
        const poll = setInterval(async () => {
          try {
            const pollRes = await fetch(API_URL + '/api/scan/' + scanId);
            if (!pollRes.ok) throw new Error('Poll failed');
            const j = await pollRes.json();

            if (j.lines && j.lines.length > lastLen) {
              for (let i = lastLen; i < j.lines.length; i++) writeLine(j.lines[i]);
              lastLen = j.lines.length;
            }

            if (j.status === 'done') {
              clearInterval(poll);
              writeLine('<span class="mono-dim"># Scan completed ✓</span>');
              buildReport(mapResultsToStatus(j.results), j.results, j);
              resolve(true);
            } else if (j.status === 'error') {
              clearInterval(poll);
              writeLine(`<span class="mono-intense-red"># Scan error: ${escHtml(j.results?.error)}</span>`);
              reject(new Error(j.results?.error || 'Unknown error'));
            }
          } catch (e) {
            clearInterval(poll);
            writeLine(`<span class="mono-intense-red"># Connection error: ${escHtml(e.message)}</span>`);
            reject(e);
          }
        }, POLL_INTERVAL);

        setTimeout(() => { clearInterval(poll); reject(new Error('Scan timeout (5 minutes)')); }, 300000);
      });
    } catch (e) {
      writeLine(`<span class="mono-intense-red"># Backend error: ${escHtml(e.message)}</span>`);
      throw e;
    }
  }

  // ── Form submit ────────────────────────────────────────────────────────────
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    const url = (input && input.value || '').trim();
    try {
      if (!url) throw new Error('empty');
      const normalized = url.startsWith('http') ? url : 'https://' + url;
      new URL(normalized);

      resetTerminal(`probe ${normalized} --modules all --deep`);
      const reportSection = document.getElementById('fullReport');
      if (reportSection) reportSection.hidden = true;

      runBackendScan(normalized).catch(err => {
        console.error('Scan error:', err);
        writeLine(`<span class="mono-intense-red"># ERROR: ${escHtml(err.message)}</span>`);
      });
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
