/**
 * YHACK Security Scan Manager - COMPLETE REWRITE
 * Professional security testing with proper parallelization and configuration
 */

const dns = require('dns').promises;
const net = require('net');
const tls = require('tls');
const fetch = require('node-fetch');
const nodemailer = require('nodemailer');
const { PAYLOADS } = require('./payloads');

let puppeteer = null;
try {
  puppeteer = require('puppeteer');
} catch (e) {
  console.warn('[SCAN] Puppeteer not available');
}

// Email transporter with environment variables
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

const wait = (ms) => new Promise(r => setTimeout(r, ms));

const log = (level, module, message, data = {}) => {
  const timestamp = new Date().toISOString();
  const prefix = `[${timestamp}] [${level}] [${module}]`;
  const dataStr = Object.keys(data).length ? ' ' + JSON.stringify(data).substring(0, 500) : '';
  console.log(prefix, message + dataStr);
};

/**
 * Send vulnerability alert email
 */
async function sendVulnerabilityAlert(email, vulnTitle, target, details) {
  if (!email || !email.includes('@') || process.env.ENABLE_EMAIL_ALERTS !== 'true') return;

  try {
    log('INFO', 'EMAIL', `Sending alert to ${email}`);
    await transporter.sendMail({
      from: process.env.ALERT_EMAIL_FROM || '"Yhack Scanner" <alert@yhack.local>',
      to: email,
      subject: `[CRITICAL] Vulnerability on ${target}: ${vulnTitle}`,
      text: `⚠️ SECURITY ALERT YHACK\n\nTarget: ${target}\nType: ${vulnTitle}\n\n${details}`
    });
    log('SUCCESS', 'EMAIL', `Alert sent to ${email}`);
  } catch(e) {
    log('ERROR', 'EMAIL', 'Send failed', { error: e.message });
  }
}

/**
 * Module: DNS Resolution
 */
async function testDNS(url, onLine) {
  onLine('▸ Résolution DNS ..........');
  try {
    const recs = await dns.lookup(url.hostname, { all: true });
    onLine(`  • IP: ${recs.map(r => r.address).join(', ')}`);
    return { status: 'OK', addresses: recs.map(r => r.address) };
  } catch (e) {
    onLine('  ! DNS non résolu');
    return { status: 'FAIL', error: String(e.message) };
  }
}

/**
 * Module: TLS/SSL Verification
 */
async function testTLS(url, onLine) {
  onLine('▸ Vérification TLS/SSL ....');
  try {
    if (url.protocol === 'http:') {
      onLine('  ! HTTP non chiffré');
      return { status: 'WARN', details: 'Non-encrypted HTTP' };
    }

    const socket = tls.connect({
      host: url.hostname,
      port: 443,
      servername: url.hostname,
      timeout: 3000
    });

    const info = await new Promise((resolve, reject) => {
      socket.on('secureConnect', () => {
        const cert = socket.getPeerCertificate();
        resolve({
          authorized: socket.authorized,
          proto: socket.getProtocol(),
          cipher: socket.getCipher(),
          validTo: cert.valid_to
        });
        socket.end();
      });
      socket.on('error', reject);
      socket.setTimeout(3000, () => socket.destroy(new Error('Timeout')));
    });

    onLine(`  • ${info.proto} (${info.authorized ? 'Valid' : 'Invalid'})`);
    return { status: info.authorized ? 'OK' : 'WARN', details: info };
  } catch (e) {
    onLine('  ! TLS Error');
    return { status: 'FAIL', error: String(e.message) };
  }
}

/**
 * Module: HTTP Security Headers
 */
async function testHeaders(url, onLine) {
  onLine('▸ En-têtes HTTP Sécurité ..');
  try {
    const resp = await fetch(url.href, { method: 'GET', timeout: 5000 });
    const headers = Object.fromEntries(resp.headers.entries());

    const required = ['content-security-policy', 'x-frame-options', 'x-content-type-options', 
                      'strict-transport-security', 'referrer-policy'];
    const missing = required.filter(h => !(h in headers));

    onLine(`  • ${missing.length} headers manquants`);
    return { status: missing.length > 2 ? 'WARN' : 'OK', missing };
  } catch (e) {
    onLine('  ! Erreur headers');
    return { status: 'FAIL', error: String(e.message) };
  }
}

/**
 * Module: CORS Configuration
 */
async function testCORS(url, onLine, alertEmail) {
  onLine('▸ CORS Misconfiguration ...');
  try {
    const resp = await fetch(url.href, {
      headers: { 'Origin': PAYLOADS.cors.testOrigin, 'User-Agent': 'Yhack-Scanner/1.0' },
      timeout: 5000
    });

    const acao = resp.headers.get('access-control-allow-origin');
    if (acao === PAYLOADS.cors.testOrigin) {
      onLine('  ! CORS Wildcard or Arbitrary Origin');
      if (alertEmail) {
        await sendVulnerabilityAlert(alertEmail, 'CORS_MISCONFIGURATION', url.href, 
          `Insecure CORS detected on origin ${acao}`);
      }
      return { status: 'WARN', vulnerable: true };
    }
    onLine('  • CORS OK');
    return { status: 'OK', vulnerable: false };
  } catch (e) {
    onLine('  ! CORS test error');
    return { status: 'FAIL', error: String(e.message) };
  }
}

/**
 * Module: Sensitive Files Discovery
 */
async function testSensitiveFiles(url, onLine) {
  onLine('▸ Fichiers Sensibles ......');
  let found = 0;
  
  for (const file of PAYLOADS.sensitiveFiles.slice(0, 10)) {
    try {
      const u = new URL(file, url.href);
      const resp = await fetch(u.href, { timeout: 2000 });
      if (resp.status === 200) {
        const text = await resp.text();
        if (text.length > 0 && !text.includes('<html')) {
          onLine(`  ! Fichier exposé: ${file}`);
          found++;
        }
      }
    } catch (e) {}
    await wait(50);
  }
  
  if (found === 0) onLine('  • Aucun fichier sensible trouvé');
  return { status: found > 0 ? 'WARN' : 'OK', exposed: found };
}

/**
 * Module: Port Scan
 */
async function testPorts(url, onLine) {
  onLine('▸ Ports exposés ...........');
  const common = [21, 22, 25, 80, 443, 3306, 5432, 8080];
  const open = [];

  for (const port of common) {
    try {
      const socket = net.createConnection({ host: url.hostname, port, timeout: 800 });
      await new Promise((resolve) => {
        socket.on('connect', () => {
          open.push(port);
          socket.destroy();
          resolve();
        });
        socket.on('error', () => resolve());
        socket.setTimeout(800, () => { socket.destroy(); resolve(); });
      });
    } catch (e) {}
  }

  onLine('  • Ports ouverts: ' + (open.join(', ') || 'None'));
  return { status: 'OK', open_ports: open };
}

/**
 * Module: SQL Injection Testing
 */
async function testSQLi(url, onLine, alertEmail) {
  onLine('▸ Injection SQL ...........');
  const delay = parseInt(process.env.SCAN_DELAY_MS || '200');

  for (const payload of PAYLOADS.sqli.payloads.slice(0, 8)) {
    for (const param of PAYLOADS.sqli.params.slice(0, 5)) {
      try {
        const u = new URL(url.href);
        u.searchParams.set(param, payload);
        const r = await fetch(u.href, { timeout: 5000 });
        const text = await r.text();

        if (PAYLOADS.sqli.errorPatterns.some(p => p.test(text))) {
          onLine(`  ! SQLi détectée sur '${param}'`);
          if (alertEmail) {
            await sendVulnerabilityAlert(alertEmail, 'SQL_INJECTION', url.href, 
              `Vulnerable parameter: ${param}`);
          }
          return { status: 'FAIL', vulnerable: true, param };
        }
      } catch (e) {}
      await wait(delay);
    }
  }

  onLine('  • SQLi non détectée');
  return { status: 'OK', vulnerable: false };
}

/**
 * Module: Cross-Site Scripting Testing
 */
async function testXSS(url, onLine, alertEmail) {
  onLine('▸ Cross-Site Scripting ....');
  const delay = parseInt(process.env.SCAN_DELAY_MS || '200');

  for (const payload of PAYLOADS.xss.payloads.slice(0, 5)) {
    for (const param of PAYLOADS.xss.params.slice(0, 5)) {
      try {
        const u = new URL(url.href);
        u.searchParams.set(param, payload);
        const r = await fetch(u.href, { timeout: 5000 });
        const text = await r.text();

        if (text.includes(payload)) {
          onLine(`  ! XSS réfléchi détectée sur '${param}'`);
          if (alertEmail) {
            await sendVulnerabilityAlert(alertEmail, 'CROSS_SITE_SCRIPTING', url.href, 
              `Parameter ${param} vulnerable to XSS`);
          }
          return { status: 'FAIL', vulnerable: true, param };
        }
      } catch (e) {}
      await wait(delay);
    }
  }

  onLine('  • XSS non détectée');
  return { status: 'OK', vulnerable: false };
}

/**
 * Module: Local File Inclusion Testing
 */
async function testLFI(url, onLine, alertEmail) {
  onLine('▸ Local File Inclusion ....');
  const delay = parseInt(process.env.SCAN_DELAY_MS || '200');

  for (const payload of PAYLOADS.lfi.paths.slice(0, 4)) {
    for (const param of PAYLOADS.lfi.params.slice(0, 4)) {
      try {
        const u = new URL(url.href);
        u.searchParams.set(param, payload);
        const r = await fetch(u.href, { timeout: 5000 });
        const text = await r.text();

        if (PAYLOADS.lfi.indicators.some(ind => text.includes(ind))) {
          onLine(`  ! LFI détectée sur '${param}'`);
          if (alertEmail) {
            await sendVulnerabilityAlert(alertEmail, 'LOCAL_FILE_INCLUSION', url.href, 
              `Parameter ${param} vulnerable to LFI`);
          }
          return { status: 'FAIL', vulnerable: true, param };
        }
      } catch (e) {}
      await wait(delay);
    }
  }

  onLine('  • LFI non détectée');
  return { status: 'OK', vulnerable: false };
}

/**
 * Module: Remote Code Execution Testing
 */
async function testRCE(url, onLine, alertEmail) {
  onLine('▸ Remote Code Execution ...');
  const delay = parseInt(process.env.SCAN_DELAY_MS || '200');

  for (const payload of PAYLOADS.rce.payloads.slice(0, 4)) {
    for (const param of PAYLOADS.rce.params.slice(0, 4)) {
      try {
        const u = new URL(url.href);
        u.searchParams.set(param, payload);
        const r = await fetch(u.href, { timeout: 5000 });
        const text = await r.text();

        if (PAYLOADS.rce.indicators.some(ind => text.includes(ind))) {
          onLine(`  ! RCE détectée sur '${param}'`);
          if (alertEmail) {
            await sendVulnerabilityAlert(alertEmail, 'REMOTE_CODE_EXECUTION', url.href, 
              `Parameter ${param} vulnerable to RCE`);
          }
          return { status: 'FAIL', vulnerable: true, param };
        }
      } catch (e) {}
      await wait(delay);
    }
  }

  onLine('  • RCE non détectée');
  return { status: 'OK', vulnerable: false };
}

/**
 * Module: Server-Side Template Injection Testing
 */
async function testSSTI(url, onLine, alertEmail) {
  onLine('▸ Template Injection ......');

  for (const payload of PAYLOADS.mako.simplePayloads) {
    for (const param of PAYLOADS.mako.params.slice(0, 3)) {
      try {
        const u = new URL(url.href);
        u.searchParams.set(param, payload);
        const r = await fetch(u.href, { timeout: 5000 });
        const text = await r.text();

        if ((payload === '${7*7}' && text.includes('49')) || 
            (payload === "${'yhack'.upper()}" && text.includes('YHACK'))) {
          onLine(`  ! SSTI détectée sur '${param}'`);
          if (alertEmail) {
            await sendVulnerabilityAlert(alertEmail, 'TEMPLATE_INJECTION', url.href, 
              `Parameter ${param} vulnerable to SSTI`);
          }
          return { status: 'FAIL', vulnerable: true, param };
        }
      } catch (e) {}
      await wait(100);
    }
  }

  onLine('  • SSTI non détectée');
  return { status: 'OK', vulnerable: false };
}

/**
 * Main scan orchestrator with parallelization
 */
async function runScan(url, alertEmail, scanId, db) {
  log('INFO', 'SCAN', `Starting scan for ${url.href}`);

  const results = {};
  const onLine = (line) => {
    if (db && scanId) {
      try {
        const stmt = db.prepare('SELECT lines FROM scans WHERE id = ?');
        const scan = stmt.get(scanId);
        if (scan) {
          const lines = JSON.parse(scan.lines || '[]');
          lines.push(line);
          const updateStmt = db.prepare('UPDATE scans SET lines = ? WHERE id = ?');
          updateStmt.run(JSON.stringify(lines), scanId);
        }
      } catch (e) {
        console.error('Error updating lines:', e.message);
      }
    }
    console.log(`[SCAN] ${line}`);
  };

  try {
    // Phase 1: Passive & Network tests (parallel)
    onLine('▸ Phase 1: Passive scans...');
    const phase1Results = await Promise.all([
      testDNS(url, onLine),
      testTLS(url, onLine),
      testHeaders(url, onLine),
      testCORS(url, onLine, alertEmail),
      testPorts(url, onLine),
      testSensitiveFiles(url, onLine)
    ]);

    results.dns = phase1Results[0];
    results.tls = phase1Results[1];
    results.headers = phase1Results[2];
    results.cors = phase1Results[3];
    results.ports = phase1Results[4];
    results.sensitive_files = phase1Results[5];

    await wait(500);

    // Phase 2: Active vulnerability tests (parallel but with rate limiting)
    onLine('▸ Phase 2: Active tests...');
    const phase2Results = await Promise.all([
      testSQLi(url, onLine, alertEmail),
      testXSS(url, onLine, alertEmail),
      testLFI(url, onLine, alertEmail),
      testRCE(url, onLine, alertEmail),
      testSSTI(url, onLine, alertEmail)
    ]);

    results.sqli = phase2Results[0];
    results.xss = phase2Results[1];
    results.lfi = phase2Results[2];
    results.rce = phase2Results[3];
    results.mako = phase2Results[4];

    // Calculate overall score
    const criticalVulns = Object.values(results).filter(r => r && r.status === 'FAIL').length;
    results.vulns = {
      status: criticalVulns > 0 ? 'FAIL' : 'OK',
      critical_issues: criticalVulns
    };

    onLine('▸ Scan completed successfully');
    log('INFO', 'SCAN', 'Scan finished', { criticalVulns });
    return results;

  } catch (e) {
    log('ERROR', 'SCAN', 'Scan failed', { error: e.message });
    onLine(`▸ Erreur: ${e.message}`);
    throw e;
  }
}

module.exports = { runScan };
