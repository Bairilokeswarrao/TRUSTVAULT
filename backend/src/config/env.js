'use strict';
const fs = require('node:fs');
const path = require('node:path');

const BACKEND_ROOT = path.resolve(__dirname, '..', '..');

function parseDotenv(text) {
  const out = {};
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (m && !line.trim().startsWith('#')) {
      let val = m[2].trim();
      val = val.replace(/^["']+|["']+$/g, '').trim();
      out[m[1]] = val;
    }
  }
  return out;
}

function cleanHexKey(name, rawValue) {
  let val = typeof rawValue === 'string' ? rawValue : (typeof name === 'string' && arguments.length === 1 ? name : '');
  const varName = arguments.length > 1 ? name : null;
  if (!val || typeof val !== 'string') return val;

  // Strip zero-width characters and BOM often copied from browser/clipboard
  val = val.replace(/[\u200B-\u200D\uFEFF]/g, '').trim();

  // Strip leading 'export ' if copied from shell script
  if (/^export\s+/i.test(val)) {
    val = val.replace(/^export\s+/i, '').trim();
  }

  // Strip leading 'VARIABLE_NAME=' if the variable name was pasted into the value box
  if (varName) {
    const namePrefix = new RegExp(`^${varName}\\s*=\\s*`, 'i');
    if (namePrefix.test(val)) {
      val = val.replace(namePrefix, '').trim();
    }
  }

  // Strip inline comments if pasted from .env (e.g. "key # comment")
  const commentIdx = val.indexOf('#');
  if (commentIdx > 0) {
    val = val.slice(0, commentIdx).trim();
  }

  // Strip enclosing quotes (e.g. "abc..." or 'abc...')
  val = val.replace(/^["']+|["']+$/g, '').trim();

  // Strip trailing semicolon or comma if pasted from code
  val = val.replace(/[;,]+$/, '').trim();

  // Strip 0x or 0X prefix if present with 64 hex digits
  if (/^0x[0-9a-f]{64}$/i.test(val)) {
    val = val.slice(2);
  }

  return val;
}

function hexKey(name, rawValue) {
  const value = cleanHexKey(name, rawValue);

  if (!value) {
    throw new Error(
      `Missing required environment variable "${name}". In production (Render), go to your Web Service > Environment tab, and add ${name} with a 64-hex-character value (32 bytes). For local development, run "npm run init" to generate a backend/.env file.`
    );
  }

  if (typeof value !== 'string') {
    throw new Error(`Environment variable "${name}" must be a string.`);
  }

  if (value.length !== 64) {
    let explanation = '';
    if (value.length === 32 || value.length === 33) {
      explanation = ' NOTE: You provided approximately 32 characters. In hexadecimal, 32 bytes requires 64 characters (2 hex digits per byte). A 32-character string is only 16 bytes.';
    } else if (value.startsWith('<') && value.endsWith('>')) {
      explanation = ' NOTE: You entered template placeholder text (like <...>) instead of a real key.';
    }
    throw new Error(
      `Environment variable "${name}" must be exactly 64 hexadecimal characters (32 bytes), but received length ${value.length}.${explanation} Run 'node -e "console.log(require(\\'crypto\\').randomBytes(32).toString(\\'hex\\'))"' to generate a valid 64-hex key.`
    );
  }

  if (!/^[0-9a-f]{64}$/i.test(value)) {
    throw new Error(
      `Environment variable "${name}" contains non-hexadecimal characters. It must contain only hex digits (0-9, a-f).`
    );
  }

  return Buffer.from(value, 'hex');
}

/**
 * Case-insensitive environment variable resolver that also checks trimmed names.
 * Protects against common dashboard mistakes like 'audit_hmac_key' or 'AUDIT_HMAC_KEY '.
 */
function resolveEnv(name) {
  if (process.env[name] !== undefined) return process.env[name];
  const target = name.toLowerCase();
  for (const k of Object.keys(process.env)) {
    if (k.trim().toLowerCase() === target) {
      return process.env[k];
    }
  }
  return undefined;
}

/**
 * Build configuration. `overrides` wins (used by tests). Secrets are never defaulted:
 * a missing key stops startup rather than silently running with a guessable one.
 */
function loadConfig(overrides = {}) {
  const envFile = path.join(BACKEND_ROOT, '.env');
  const fileVars = fs.existsSync(envFile) ? parseDotenv(fs.readFileSync(envFile, 'utf8')) : {};
  const get = (k, d) => {
    const val = overrides[k] ?? resolveEnv(k) ?? fileVars[k] ?? d;
    return typeof val === 'string' ? val.trim() : val;
  };

  const dataDir = overrides.dataDir ?? path.resolve(BACKEND_ROOT, get('DATA_DIR', 'data'));
  const defaultHost = (resolveEnv('RENDER') || resolveEnv('NODE_ENV') === 'production') ? '0.0.0.0' : '127.0.0.1';

  const cfg = {
    port: Number(get('PORT', '3000')),
    host: get('HOST', defaultHost),
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

module.exports = { loadConfig, parseDotenv, hexKey, cleanHexKey, resolveEnv, BACKEND_ROOT };
