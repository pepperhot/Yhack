#!/usr/bin/env node

/**
 * YHACK Validation Script
 * Run with: node validate.js
 * 
 * Checks that all refactoring changes are in place
 */

const fs = require('fs');
const path = require('path');

const checks = [
  // Configuration files
  {
    name: '.env.example exists',
    test: () => fs.existsSync('.env.example'),
    critical: true
  },
  {
    name: '.gitignore exists and contains .env',
    test: () => {
      const content = fs.readFileSync('.gitignore', 'utf8');
      return content.includes('.env');
    },
    critical: true
  },

  // New files
  {
    name: 'server/payloads.js exists',
    test: () => fs.existsSync('server/payloads.js'),
    critical: true
  },
  {
    name: 'payloads.js exports PAYLOADS',
    test: () => {
      try {
        const { PAYLOADS } = require('./server/payloads');
        return PAYLOADS && PAYLOADS.sqli && PAYLOADS.xss;
      } catch (e) {
        return false;
      }
    },
    critical: true
  },

  // Modified files (check key changes)
  {
    name: 'package.json has better-sqlite3',
    test: () => {
      const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
      return pkg.dependencies['better-sqlite3'] !== undefined;
    },
    critical: true
  },
  {
    name: 'package.json has dotenv',
    test: () => {
      const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
      return pkg.dependencies['dotenv'] !== undefined;
    },
    critical: true
  },
  {
    name: 'package.json has express-rate-limit',
    test: () => {
      const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
      return pkg.dependencies['express-rate-limit'] !== undefined;
    },
    critical: true
  },

  // server/index.js checks
  {
    name: 'server/index.js uses dotenv',
    test: () => {
      const content = fs.readFileSync('server/index.js', 'utf8');
      return content.includes("require('dotenv').config()");
    },
    critical: true
  },
  {
    name: 'server/index.js uses better-sqlite3',
    test: () => {
      const content = fs.readFileSync('server/index.js', 'utf8');
      return content.includes("require('better-sqlite3')") || 
             content.includes('new Database(');
    },
    critical: true
  },
  {
    name: 'server/index.js has rate limiting',
    test: () => {
      const content = fs.readFileSync('server/index.js', 'utf8');
      return content.includes('rate-limit') || content.includes('rateLimit');
    },
    critical: true
  },
  {
    name: 'server/index.js has SSRF protection',
    test: () => {
      const content = fs.readFileSync('server/index.js', 'utf8');
      return content.includes('privateRanges') || content.includes('SSRF');
    },
    critical: true
  },
  {
    name: 'server/index.js does not have hardcoded credentials',
    test: () => {
      const content = fs.readFileSync('server/index.js', 'utf8');
      return !content.includes('lucas.gemo77@gmail.com') && 
             !content.includes("'Super!killer!9'");
    },
    critical: true
  },

  // scanManager.js checks
  {
    name: 'server/scanManager.js imports payloads',
    test: () => {
      const content = fs.readFileSync('server/scanManager.js', 'utf8');
      return content.includes("require('./payloads')");
    },
    critical: true
  },
  {
    name: 'server/scanManager.js uses Promise.all for parallelization',
    test: () => {
      const content = fs.readFileSync('server/scanManager.js', 'utf8');
      return content.includes('Promise.all');
    },
    critical: true
  },
  {
    name: 'server/scanManager.js uses dotenv for email config',
    test: () => {
      const content = fs.readFileSync('server/scanManager.js', 'utf8');
      return content.includes('process.env.SMTP_HOST') && 
             content.includes('process.env.SMTP_USER') &&
             content.includes('process.env.SMTP_PASS');
    },
    critical: true
  },
  {
    name: 'server/scanManager.js does not have hardcoded credentials',
    test: () => {
      const content = fs.readFileSync('server/scanManager.js', 'utf8');
      return !content.includes('lucas.gemo77@gmail.com') && 
             !content.includes("'Super!killer!9'");
    },
    critical: true
  },

  // script.js checks
  {
    name: 'script.js has API-only logic (no mock)',
    test: () => {
      const content = fs.readFileSync('script.js', 'utf8');
      return content.includes('runBackendScan') && 
             !content.includes('runMockScan');
    },
    critical: true
  },
  {
    name: 'script.js does not have hashString',
    test: () => {
      const content = fs.readFileSync('script.js', 'utf8');
      return !content.includes('hashString');
    },
    critical: true
  },

  // styles.css checks
  {
    name: 'styles.css does not have spaced-out characters',
    test: () => {
      const content = fs.readFileSync('styles.css', 'utf8');
      return !content.includes('/ *   F l a g') && 
             !content.includes('@ k e y f r a m e s');
    },
    critical: true
  },
  {
    name: 'styles.css has proper @keyframes flash-flag',
    test: () => {
      const content = fs.readFileSync('styles.css', 'utf8');
      return content.includes('@keyframes flash-flag') && 
             content.includes('.flag-found');
    },
    critical: true
  },

  // Documentation
  {
    name: 'README.md exists and is comprehensive',
    test: () => {
      const content = fs.readFileSync('README.md', 'utf8');
      return content.includes('Installation') && 
             content.includes('Modules de Test') &&
             content.includes('Architecture');
    },
    critical: false
  },
  {
    name: 'SETUP_INSTRUCTIONS.md exists',
    test: () => fs.existsSync('SETUP_INSTRUCTIONS.md'),
    critical: false
  }
];

// Run checks
console.log('\n═══════════════════════════════════════════════════════════════');
console.log('  YHACK REFACTORING VALIDATION');
console.log('═══════════════════════════════════════════════════════════════\n');

let passed = 0;
let failed = 0;
let criticalFailed = 0;

for (const check of checks) {
  try {
    const result = check.test();
    const icon = result ? '✅' : '❌';
    const severity = check.critical ? '[CRITICAL]' : '[INFO]';
    
    console.log(`${icon} ${check.name} ${check.critical ? severity : ''}`);
    
    if (result) {
      passed++;
    } else {
      failed++;
      if (check.critical) criticalFailed++;
    }
  } catch (e) {
    console.log(`❌ ${check.name} [ERROR: ${e.message.substring(0, 50)}...]`);
    failed++;
    if (check.critical) criticalFailed++;
  }
}

// Summary
console.log('\n═══════════════════════════════════════════════════════════════');
console.log(`Passed: ${passed}/${checks.length}`);
console.log(`Failed: ${failed}/${checks.length}`);
if (criticalFailed > 0) {
  console.log(`\n⚠️  CRITICAL FAILURES: ${criticalFailed}\n`);
  process.exit(1);
} else {
  console.log('\n✅ ALL CRITICAL CHECKS PASSED!\n');
  process.exit(0);
}
