'use strict';
// Interface d'administration NetGuard — front minimal, tout est gardé côté serveur.
(function () {
  const $ = (id) => document.getElementById(id);
  const gate = $('adminGate'), dash = $('adminDash'), panel = $('adminPanel');
  const modal = $('adminModal'), modalTitle = $('modalTitle'), modalBody = $('modalBody');
  let currentTab = 'users';
  let adminId = null;
  // État de la vue « comptes » (persiste entre les rafraîchissements).
  let allUsers = [], userSearch = '', userFilter = 'all';

  const esc = (s) => String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  const fmtDate = (s) => s ? new Date(s.replace(' ', 'T') + (s.includes('Z') ? '' : 'Z')).toLocaleString('fr-FR') : '—';

  async function api(path, opts) {
    const res = await fetch('/api/admin' + path, Object.assign({ credentials: 'same-origin' }, opts));
    // 401 = session/élévation expirée → on renvoie l'admin vers l'écran de connexion.
    if (res.status === 401) { showGate(); throw new Error('reauth'); }
    return res;
  }

  function showGate() { gate.hidden = false; dash.hidden = true; }
  function showDash(email) {
    gate.hidden = true; dash.hidden = false;
    $('adminWho').textContent = email || '';
    loadStats(); selectTab(currentTab);
  }

  // ── Démarrage : quel écran afficher ? ──────────────────────────────────────
  async function boot() {
    try {
      const res = await fetch('/api/admin/session', { credentials: 'same-origin' });
      if (!res.ok) return showGate();           // 404 (hors IP) → écran de connexion neutre
      const s = await res.json();
      if (s.elevated) showDash(s.email); else showGate();
    } catch (_) { showGate(); }
  }

  // ── Connexion admin ────────────────────────────────────────────────────────
  $('adminLoginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('adminError'); err.hidden = true;
    const email = $('adminEmail').value.trim();
    const password = $('adminPass').value;
    try {
      const res = await fetch('/api/admin/login', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { err.textContent = data.error || 'Accès refusé'; err.hidden = false; return; }
      $('adminPass').value = '';
      showDash(email);
    } catch (_) { err.textContent = 'Erreur réseau'; err.hidden = false; }
  });

  $('adminExit').addEventListener('click', async () => {
    await fetch('/api/admin/logout', { method: 'POST', credentials: 'same-origin' });
    showGate();
  });
  $('adminRefresh').addEventListener('click', () => { loadStats(); selectTab(currentTab); });

  // ── Stats ────────────────────────────────────────────────────────────────
  async function loadStats() {
    try {
      const res = await api('/stats'); const s = await res.json();
      const tiles = [
        [s.users, 'Comptes'],
        [s.scans, 'Scans total'],
        [s.activeScans, 'Scans actifs'],
        [s.verifiedDomains + ' / ' + s.domains, 'Domaines vérifiés'],
        [(s.dbSizeKb / 1024).toFixed(1) + ' Mo', 'Taille base'],
        [Math.floor(s.uptimeSec / 3600) + 'h', 'Uptime'],
      ];
      $('adminStats').innerHTML = tiles.map(([n, l]) =>
        `<div class="stat-tile"><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`).join('');
    } catch (_) {}
  }

  // ── Onglets ────────────────────────────────────────────────────────────────
  document.querySelectorAll('.admin-tab').forEach(t =>
    t.addEventListener('click', () => selectTab(t.dataset.tab)));

  function selectTab(tab) {
    currentTab = tab;
    document.querySelectorAll('.admin-tab').forEach(t =>
      t.classList.toggle('active', t.dataset.tab === tab));
    ({ users: loadUsers, scans: loadScans, domains: loadDomains, audit: loadAudit }[tab] || loadUsers)();
  }

  function table(cols, rowsHtml) {
    if (!rowsHtml) return '<div class="admin-table-wrap"><div class="admin-empty">Aucune donnée.</div></div>';
    return `<div class="admin-table-wrap"><table class="admin-table"><thead><tr>${cols.map(c => `<th>${c}</th>`).join('')}</tr></thead><tbody>${rowsHtml}</tbody></table></div>`;
  }

  // ── Comptes : recherche + filtre + actions ─────────────────────────────────
  async function loadUsers() {
    const res = await api('/users'); const d = await res.json();
    allUsers = d.users; adminId = d.adminId;
    renderUsers();
  }

  function renderUsers() {
    panel.innerHTML = `
      <div class="admin-toolbar">
        <input id="userSearch" class="admin-search" type="search" placeholder="Rechercher un email…" value="${esc(userSearch)}" />
        <select id="userFilter" class="admin-select">
          <option value="all">Tous les comptes</option>
          <option value="active">Ayant fait des scans actifs</option>
          <option value="verified">Avec domaine vérifié</option>
          <option value="suspended">Suspendus</option>
        </select>
      </div>
      <div id="usersHost"></div>`;
    const sel = $('userFilter'); if (sel) sel.value = userFilter;
    renderUsersTable();
  }

  function renderUsersTable() {
    const host = $('usersHost'); if (!host) return;
    const q = userSearch.trim().toLowerCase();
    let list = allUsers.filter(u => !q || u.email.toLowerCase().includes(q));
    if (userFilter === 'active')    list = list.filter(u => u.active_count > 0);
    if (userFilter === 'verified')  list = list.filter(u => u.domain_count > 0);
    if (userFilter === 'suspended') list = list.filter(u => u.disabled);
    host.innerHTML = table(['Email', 'Créé le', 'Dernière connexion', 'Scans', 'Domaines', ''], list.map(u => `
      <tr>
        <td>${esc(u.email)}${u.id === adminId ? ' <span class="tag tag--ok">admin</span>' : ''}${u.disabled ? ' <span class="tag tag--off">suspendu</span>' : ''}</td>
        <td class="mono">${fmtDate(u.created_at)}</td>
        <td class="mono">${u.last_login ? fmtDate(u.last_login) : '—'}</td>
        <td>${u.scan_count}${u.active_count ? ` <span class="tag tag--active">${u.active_count} actif${u.active_count > 1 ? 's' : ''}</span>` : ''}</td>
        <td>${u.domain_count}</td>
        <td><div class="row-actions">
          <button class="btn-act" data-action="detail" data-id="${esc(u.id)}">Détails</button>
          ${u.id === adminId ? '' : `
          <button class="btn-act" data-action="password" data-id="${esc(u.id)}" data-label="${esc(u.email)}">Mot de passe</button>
          <button class="btn-act warn" data-action="suspend" data-id="${esc(u.id)}" data-label="${esc(u.email)}" data-disabled="${u.disabled ? 1 : 0}">${u.disabled ? 'Réactiver' : 'Suspendre'}</button>
          <button class="btn-del" data-del="user" data-id="${esc(u.id)}" data-label="${esc(u.email)}">Supprimer</button>`}
        </div></td>
      </tr>`).join(''));
  }

  async function openUserDetail(id) {
    let d;
    try { d = await (await api('/users/' + id)).json(); } catch (_) { return; }
    modalTitle.textContent = d.user.email;
    const scansRows = d.scans.map(s => `<tr>
      <td class="mono">${esc(s.target)}</td>
      <td><span class="tag tag--${s.mode === 'active' ? 'active' : 'passive'}">${esc(s.mode)}</span></td>
      <td>${esc(s.status)}</td><td class="mono">${fmtDate(s.created_at)}</td></tr>`).join('');
    const domRows = d.domains.map(x => `<tr>
      <td class="mono">${esc(x.domain)}</td>
      <td><span class="tag ${x.verified ? 'tag--ok' : 'tag--active'}">${x.verified ? 'vérifié' : 'en attente'}</span></td>
      <td>${esc(x.method || '—')}</td></tr>`).join('');
    modalBody.innerHTML = `
      <p style="color:var(--muted);font-size:12px;margin:0;">
        Créé : ${fmtDate(d.user.created_at)} · Dernière connexion : ${d.user.last_login ? fmtDate(d.user.last_login) : 'jamais'} ·
        ${d.user.disabled ? '<span class="tag tag--off">suspendu</span>' : '<span class="tag tag--ok">actif</span>'}</p>
      <div class="modal-sub">Scans (${d.scans.length})</div>
      ${table(['Cible', 'Mode', 'Statut', 'Date'], scansRows)}
      <div class="modal-sub">Domaines (${d.domains.length})</div>
      ${table(['Domaine', 'État', 'Méthode'], domRows)}`;
    modal.hidden = false;
  }

  async function resetPassword(id, label) {
    const pw = prompt(`Nouveau mot de passe pour « ${label} » (8 caractères minimum) :`);
    if (pw == null) return;
    const res = await api('/users/' + id + '/password', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pw }),
    });
    if (res.ok) alert('Mot de passe réinitialisé.');
    else { const d = await res.json().catch(() => ({})); alert(d.error || 'Échec'); }
  }

  async function toggleSuspend(id, label, isDisabled) {
    const next = !isDisabled;
    if (!confirm(`${next ? 'Suspendre' : 'Réactiver'} le compte « ${label} » ?`)) return;
    const res = await api('/users/' + id + '/status', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ disabled: next }),
    });
    if (res.ok) { loadStats(); loadUsers(); }
    else { const d = await res.json().catch(() => ({})); alert(d.error || 'Échec'); }
  }

  // Modale : fermeture.
  $('modalClose').addEventListener('click', () => modal.hidden = true);
  modal.addEventListener('click', (e) => { if (e.target === modal) modal.hidden = true; });
  // Recherche / filtre (délégation : survit aux re-rendus du tableau).
  panel.addEventListener('input',  (e) => { if (e.target.id === 'userSearch') { userSearch = e.target.value; renderUsersTable(); } });
  panel.addEventListener('change', (e) => { if (e.target.id === 'userFilter') { userFilter = e.target.value; renderUsersTable(); } });

  async function loadScans() {
    const res = await api('/scans'); const { scans } = await res.json();
    const st = (s) => s === 'done' ? 'tag--ok' : s === 'error' ? 'tag--err' : 'tag--passive';
    panel.innerHTML = table(['Cible', 'Mode', 'Statut', 'Par', 'Date', ''], scans.map(s => `
      <tr>
        <td class="mono">${esc(s.target)}</td>
        <td><span class="tag tag--${s.mode === 'active' ? 'active' : 'passive'}">${esc(s.mode)}</span></td>
        <td><span class="tag ${st(s.status)}">${esc(s.status)}</span></td>
        <td>${esc(s.email || '—')}</td>
        <td class="mono">${fmtDate(s.created_at)}</td>
        <td><button class="btn-del" data-del="scan" data-id="${esc(s.id)}" data-label="${esc(s.target)}">Supprimer</button></td>
      </tr>`).join(''));
  }

  async function loadDomains() {
    const res = await api('/domains'); const { domains } = await res.json();
    panel.innerHTML = table(['Domaine', 'Propriétaire', 'État', 'Méthode', 'Vérifié le'], domains.map(d => `
      <tr>
        <td class="mono">${esc(d.domain)}</td>
        <td>${esc(d.email || '—')}</td>
        <td><span class="tag ${d.verified ? 'tag--ok' : 'tag--active'}">${d.verified ? 'vérifié' : 'en attente'}</span></td>
        <td>${esc(d.method || '—')}</td>
        <td class="mono">${fmtDate(d.verified_at)}</td>
      </tr>`).join(''));
  }

  async function loadAudit() {
    const res = await api('/audit'); const { audit } = await res.json();
    panel.innerHTML = table(['Date', 'Acteur', 'Action', 'Détail', 'IP'], audit.map(a => `
      <tr>
        <td class="mono">${fmtDate(a.at)}</td>
        <td>${esc(a.actor || '—')}</td>
        <td><span class="tag ${/fail/.test(a.action) ? 'tag--err' : 'tag--passive'}">${esc(a.action)}</span></td>
        <td class="mono">${esc(a.detail || '')}</td>
        <td class="mono">${esc(a.ip || '')}</td>
      </tr>`).join(''));
  }

  // ── Actions (détails, mot de passe, suspension, suppression) ─────────────────
  panel.addEventListener('click', async (e) => {
    const act = e.target.closest('[data-action]');
    if (act) {
      const { action, id, label, disabled } = act.dataset;
      if (action === 'detail')   return openUserDetail(id);
      if (action === 'password') return resetPassword(id, label);
      if (action === 'suspend')  return toggleSuspend(id, label, disabled === '1');
      return;
    }
    const btn = e.target.closest('[data-del]'); if (!btn) return;
    const kind = btn.dataset.del, id = btn.dataset.id, label = btn.dataset.label;
    const what = kind === 'user' ? `le compte « ${label} » et TOUTES ses données (scans, domaines)` : `le scan « ${label} »`;
    if (!confirm(`Supprimer ${what} ?\nCette action est définitive et journalisée.`)) return;
    const res = await api('/' + (kind === 'user' ? 'users' : 'scans') + '/' + id, { method: 'DELETE' });
    if (res.ok) { loadStats(); selectTab(currentTab); }
    else { const d = await res.json().catch(() => ({})); alert(d.error || 'Suppression impossible'); }
  });

  boot();
})();
