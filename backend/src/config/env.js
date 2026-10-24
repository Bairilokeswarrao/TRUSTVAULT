'use strict';
const fs = require('node:fs');
const path = require('node:path');

const BACKEND_ROOT = path.resolve(__dirname, '..', '..');

function parseDotenv(text) {
  const out = {};
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (m && !line.trim().startsWith('#')) out[m[1]] = m[2].replace(/^"(.*)"$/, '$1');
  }
  return out;
}

function hexKey(name, value) {
  if (!/^[0-9a-f]{64}$/i.test(value || '')) {
    throw new Error(`${name} must be 64 hex characters (32 bytes). Run "npm run init" to generate one.`);
  }
  return Buffer.from(value, 'hex');
}

/**
 * Build configuration. `overrides` wins (used by tests). Secrets are never defaulted:
 * a missing key stops startup rather than silently running with a guessable one.
 */
function loadConfig(overrides = {}) {
  const envFile = path.join(BACKEND_ROOT, '.env');
  const fileVars = fs.existsSync(envFile) ? parseDotenv(fs.readFileSync(envFile, 'utf8')) : {};
  const get = (k, d) => process.env[k] ?? fileVars[k] ?? d;

  const dataDir = overrides.dataDir ?? path.resolve(BACKEND_ROOT, get('DATA_DIR', 'data'));
  const cfg = {
    port: Number(get('PORT', '3000')),
    host: get('HOST', '127.0.0.1'),
    dataDir,
    dbFile: overrides.dbFile ?? path.join(dataDir, 'trustvault.db'),
    anchorFile: overrides.anchorFile ?? path.join(dataDir, 'audit-anchor.log'),
    uploadDir: overrides.uploadDir ?? path.resolve(BACKEND_ROOT, get('UPLOAD_DIR', 'private_uploads')),
    frontendDir: overrides.frontendDir ?? path.resolve(BACKEND_ROOT, '..', 'frontend'),
    auditKey: overrides.auditKey ?? hexKey('AUDIT_HMAC_KEY', get('AUDIT_HMAC_KEY')),
    fileKey: overrides.fileKey ?? hexKey('FILE_ENC_KEY', get('FILE_ENC_KEY')),
    cookieSecure: overrides.cookieSecure ?? get('COOKIE_SECURE', '0') === '1',
    trustProxy: overrides.trustProxy ?? get('TRUST_PROXY', '0') === '1',
    sessionIdleMinutes: overrides.sessionIdleMinutes ?? Number(get('SESSION_IDLE_MINUTES', '30')),
    sessionMaxHours: overrides.sessionMaxHours ?? Number(get('SESSION_MAX_HOURS', '12')),
    maxUploadBytes: overrides.maxUploadBytes ?? Number(get('MAX_UPLOAD_MB', '10')) * 1024 * 1024,
    retentionDays: overrides.retentionDays ?? Number(get('RETENTION_DAYS', '30')),
    loginRatePerMinute: overrides.loginRatePerMinute ?? Number(get('LOGIN_RATE_PER_MINUTE', '10')),
    apiRatePerMinute: overrides.apiRatePerMinute ?? Number(get('API_RATE_PER_MINUTE', '600')),
    // Registration code required to self-register as an administrator. Empty/unset = admin sign-up disabled.
    adminRegistrationCode: overrides.adminRegistrationCode ?? get('ADMIN_REGISTRATION_CODE', ''),
    scryptN: overrides.scryptN,
    lockoutThreshold: overrides.lockoutThreshold ?? 5,
    lockoutMinutes: overrides.lockoutMinutes ?? 15,
  };
  if (cfg.auditKey.equals(cfg.fileKey)) {
    throw new Error('AUDIT_HMAC_KEY and FILE_ENC_KEY must be different keys.');
  }
  return cfg;
}

module.exports = { loadConfig, parseDotenv, BACKEND_ROOT };
