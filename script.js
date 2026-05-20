// Set current year in footer
(function setYear() {
	var yearEl = document.getElementById('year');
	if (yearEl) yearEl.textContent = String(new Date().getFullYear());
})();

// Simple URL validation for prototype form
(function scanForm() {
    var form = document.querySelector('.scan-form');
    if (!form) return;
    var input = form.querySelector('input[type="url"]');
    var termEl = document.getElementById('terminalBody');
    var reportToggle = document.getElementById('reportToggle');
    var reportPanel = document.getElementById('reportPanel');
    var reportSummary = document.getElementById('reportSummary');
    var reportRecs = document.getElementById('reportRecs');
    var scoreValue = document.getElementById('scoreValue');

    function writeLine(line) {
        if (!termEl) return;
        termEl.innerHTML += "\n" + line;
    }

    function resetTerminal(command) {
        if (!termEl) return;
        termEl.textContent = '';
        termEl.innerHTML = '<span class="mono-dim">$</span> ' + command;
    }

    function hashString(s) {
        var h = 0, i = 0, len = s.length|0;
        for (; i < len; i++) { h = (h << 5) - h + s.charCodeAt(i); h |= 0; }
        return Math.abs(h);
    }

    function toStatus(okRatio) {
        return okRatio > 0.66 ? 'OK' : (okRatio > 0.33 ? 'WARN' : 'FAIL');
    }

    function runMockScan(targetUrl) {
        var u = new URL(targetUrl.startsWith('http') ? targetUrl : 'https://' + targetUrl);
        var hostHash = hashString(u.hostname);
        var isHttps = u.protocol === 'https:';

        // Deterministic pseudo-results from hostname
        var ratios = {
            dns: (hostHash % 100) / 100,
            tls: isHttps ? ((hostHash >> 3) % 100) / 100 : 0.2,
            headers: ((hostHash >> 5) % 100) / 100,
            cms: ((hostHash >> 7) % 100) / 100,
            vulns: ((hostHash >> 9) % 100) / 100,
            subdomains: ((hostHash >> 11) % 100) / 100,
            ports: ((hostHash >> 13) % 100) / 100,
            sqli: ((hostHash >> 15) % 100) / 100,
            xss: ((hostHash >> 17) % 100) / 100,
            bruteforce: ((hostHash >> 19) % 100) / 100
        };

        var statuses = {
            dns: 'OK',
            tls: toStatus(ratios.tls),
            headers: toStatus(ratios.headers),
            cms: toStatus(ratios.cms),
            vulns: toStatus(ratios.vulns),
            subdomains: toStatus(ratios.subdomains),
            ports: toStatus(ratios.ports),
            sqli: toStatus(1 - ratios.sqli), // higher ratio => worse risk; invert
            xss: toStatus(1 - ratios.xss),
            bruteforce: toStatus(ratios.bruteforce)
        };
        // DNS considered OK unless domain looks invalid; minimal check
        if (!u.hostname || u.hostname.indexOf('.') === -1) statuses.dns = 'FAIL';

        var command = 'probe ' + u.href + ' --modules owasp,tls,headers,subdomains,ports,sqli,xss,bruteforce';
        resetTerminal(command);

        // reset report
        if (reportSummary) reportSummary.innerHTML = '';
        if (reportRecs) reportRecs.innerHTML = '';
        if (scoreValue) scoreValue.textContent = '--';
        if (reportPanel) reportPanel.hidden = true;
        if (reportToggle) { reportToggle.disabled = true; reportToggle.textContent = 'Rapport synthétique'; }

        var steps = [
            { key: 'dns',       label: 'Résolution DNS',       delay: 600 },
            { key: 'tls',       label: 'Vérification TLS',     delay: 700 },
            { key: 'headers',   label: 'En-têtes de sécurité', delay: 700 },
            { key: 'cms',       label: 'CMS et plugins',       delay: 650 },
            { key: 'subdomains',label: 'Sous-domaines',        delay: 600 },
            { key: 'ports',     label: 'Ports exposés',        delay: 650 },
            { key: 'sqli',      label: 'Injection SQL',        delay: 700 },
            { key: 'xss',       label: 'Cross-Site Scripting (XSS)', delay: 700 },
            { key: 'bruteforce',label: 'Résilience brute-force', delay: 700 },
            { key: 'vulns',     label: 'Détection vulnérabilités', delay: 800 }
        ];

        var i = 0;
        function next() {
            if (i >= steps.length) {
                writeLine('<span class="mono-dim"># Rapport synthétique prêt ▸</span>');
                buildReport(statuses);
                return;
            }
            var step = steps[i++];
            var status = statuses[step.key];
            var colorClass = status === 'OK' ? 'mono-green' : (status === 'WARN' ? 'mono-yellow' : 'mono-dim');
            setTimeout(function () {
                writeLine('<span class="mono-green">▸</span> ' + step.label + ' .......... ' + '<span class="' + colorClass + '">' + status + '</span>');
                next();
            }, step.delay);
        }
        next();
    }

    function buildReport(statuses) {
        var keys = [
            ['dns','DNS'], ['tls','TLS'], ['headers','En-têtes'], ['cms','CMS'],
            ['subdomains','Sous-domaines'], ['ports','Ports'], ['sqli','SQLi'], ['xss','XSS'], ['bruteforce','Brute-force'], ['vulns','Vulnérabilités']
        ];
        
        var defs = {
            dns: "Résolution et config de base du domaine",
            tls: "Certificats, protocoles et chiffrement",
            headers: "En-têtes de sécurité (CSP, HSTS...)",
            cms: "Détection du CMS et versions obsolètes",
            subdomains: "Points d'entrée sur le même domaine",
            ports: "Services exposés sur le réseau",
            sqli: "Injection de commandes SQL malveillantes",
            xss: "Injection de scripts dans le navigateur",
            bruteforce: "Tentatives de deviner des mots de passe",
            vulns: "Failles publiques (CVE) connues"
        };

        var weights = { dns: 0.05, tls: 0.15, headers: 0.15, cms: 0.1, subdomains: 0.1, ports: 0.1, sqli: 0.2, xss: 0.15, bruteforce: 0.1, vulns: 0.1 };
        function scoreOf(status) { return status === 'OK' ? 1 : (status === 'WARN' ? 0.5 : 0); }
        var score = 0;
        var totalWeight = 0;
        keys.forEach(function(k){ 
            var w = weights[k[0]] || 0;
            if (statuses[k[0]]) {
                score += w * scoreOf(statuses[k[0]]);
                totalWeight += w;
            }
        });
        var percent = totalWeight > 0 ? Math.round((score / totalWeight) * 100) : 0;
        if (scoreValue) scoreValue.textContent = String(percent);
        if (reportSummary) {
            reportSummary.innerHTML = '';
            keys.forEach(function(k){
                var key = k[0];
                var label = k[1];
                var st = statuses[key];
                var cls = st === 'OK' ? 'mono-green' : (st === 'WARN' ? 'mono-yellow' : 'mono-dim');
                var li = document.createElement('li');
                var tooltip = defs[key] ? ' <span class="info-icon" data-tooltip="' + defs[key] + '">i</span>' : '';
                li.innerHTML = '<strong>' + label + '</strong>' + tooltip + ': <span class="' + cls + '">' + st + '</span>';
                reportSummary.appendChild(li);
            });
        }
        if (reportRecs) {
            reportRecs.innerHTML = '';
            var recs = [];
            if (statuses.headers !== 'OK') recs.push('Configurer CSP, HSTS, X-Frame-Options, X-Content-Type, Referrer-Policy.');
            if (statuses.tls !== 'OK') recs.push('Forcer HTTPS, désactiver TLS obsolète, activer HSTS, ciphers modernes.');
            if (statuses.sqli === 'FAIL') recs.push('CRITIQUE: Injection SQL détectée. Utiliser requêtes préparées, validation stricte, ORM, whitelist des entrées.');
            if (statuses.xss === 'FAIL') recs.push('CRITIQUE: XSS détecté. Encoder toutes les sorties HTML/JS, utiliser CSP strict, éviter innerHTML non sécurisé.');
            if (statuses.bruteforce !== 'OK') recs.push('Activer rate limiting sur les endpoints d\'authentification, CAPTCHA, verrouillage de compte après échecs.');
            if (statuses.ports !== 'OK') recs.push('Fermer les ports inutiles, segmenter le réseau, filtrer via pare-feu.');
            if (statuses.subdomains !== 'OK') recs.push('Auditer les sous-domaines et supprimer DNS orphelins.');
            if (statuses.vulns !== 'OK') recs.push('Mettre à jour dépendances et CMS, appliquer les correctifs de sécurité.');
            if (recs.length === 0) recs.push('Aucune recommandation prioritaire. Continuer la veille et le durcissement.');
            recs.forEach(function (r) { var li = document.createElement('li'); li.textContent = r; reportRecs.appendChild(li); });
        }
        if (reportToggle) {
            reportToggle.disabled = false;
            reportToggle.onclick = function(){ if (!reportPanel) return; reportPanel.hidden = !reportPanel.hidden; };
        }
    }

    async function runBackendScan(targetUrl) {
        // Use relative path if served via HTTP/HTTPS, otherwise fallback to localhost:5050 for file://
        var api = (window.YHACK_API || (location.protocol.startsWith('http') ? '' : 'http://localhost:5050'));
        try {
            var res = await fetch(api + '/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ targetUrl: targetUrl }) });
            if (!res.ok) throw new Error('API init failed');
            var data = await res.json();
            var id = data.scanId;
            resetTerminal('probe ' + targetUrl + ' --modules auto');
            var lastLen = 0;
            var poll = setInterval(async function(){
                try {
                    var r = await fetch(api + '/api/scan/' + id);
                    if (!r.ok) throw new Error('poll failed');
                    var j = await r.json();
                    var lines = Array.isArray(j.lines) ? j.lines : [];
                    for (var i = lastLen; i < lines.length; i++) writeLine(lines[i]);
                    lastLen = lines.length;
                    if (j.status === 'done' || j.status === 'error') {
                        clearInterval(poll);
                        writeLine('<span class="mono-dim"># Rapport synthétique prêt ▸</span>');
                        if (j.results) buildReport(convertResultsToStatuses(j.results));
                    }
                } catch (e) {
                    clearInterval(poll);
                    writeLine('<span class="mono-dim"># API indisponible</span>');
                }
            }, 800);
        } catch (e) {
            throw e;
        }
    }

    function convertResultsToStatuses(results) {
        var map = {};
        Object.keys(results || {}).forEach(function(k){ map[k] = results[k].status || 'WARN'; });
        return map;
    }

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        var url = (input && input.value || '').trim();
        try {
            if (!url) throw new Error('empty');
            var normalized = url.startsWith('http') ? url : 'https://' + url;
            new URL(normalized); // will throw if invalid
            // try backend first, then fallback to mock
            runBackendScan(normalized).catch(function(){ runMockScan(normalized); });
        } catch (err) {
            alert('Veuillez saisir une URL valide (ex: https://exemple.com)');
            input && input.focus();
        }
    });
})();

// Intersection Observer for reveal animations
(function revealOnScroll() {
	var els = Array.prototype.slice.call(document.querySelectorAll('.reveal'));
	if (!('IntersectionObserver' in window) || els.length === 0) {
		els.forEach(function (el) { el.classList.add('is-visible'); });
		return;
	}
	var io = new IntersectionObserver(function (entries) {
		entries.forEach(function (entry) {
			if (entry.isIntersecting) {
				entry.target.classList.add('is-visible');
				io.unobserve(entry.target);
			}
		});
	}, { threshold: 0.15 });
	els.forEach(function (el) { io.observe(el); });
})();
