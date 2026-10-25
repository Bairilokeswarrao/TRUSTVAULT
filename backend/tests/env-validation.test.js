'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { hexKey, loadConfig, resolveEnv, cleanHexKey } = require('../src/config/env');

test('E-01 valid 64-hex key parses into a 32-byte Buffer', () => {
  const raw = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const buf = hexKey('AUDIT_HMAC_KEY', raw);
  assert.ok(Buffer.isBuffer(buf));
  assert.equal(buf.length, 32);
  assert.equal(buf.toString('hex'), raw);
});

test('E-02 hexKey trims whitespace, strips quotes, and removes 0x prefix', () => {
  const raw = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const withSpaces = `  ${raw}  \n`;
  const withQuotes = `"${raw}"`;
  const withSingleQuotes = `'${raw}'`;
  const with0x = `0x${raw}`;
  const with0XUpper = `0X${raw}`;

  assert.equal(hexKey('AUDIT_HMAC_KEY', withSpaces).toString('hex'), raw);
  assert.equal(hexKey('AUDIT_HMAC_KEY', withQuotes).toString('hex'), raw);
  assert.equal(hexKey('AUDIT_HMAC_KEY', withSingleQuotes).toString('hex'), raw);
  assert.equal(hexKey('AUDIT_HMAC_KEY', with0x).toString('hex'), raw);
  assert.equal(hexKey('AUDIT_HMAC_KEY', with0XUpper).toString('hex'), raw);
});

test('E-03 hexKey strips name prefixes, export keywords, zero-width spaces, and inline comments', () => {
  const raw = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const withNamePrefix = `AUDIT_HMAC_KEY=${raw}`;
  const withExport = `export AUDIT_HMAC_KEY="${raw}"`;
  const withComment = `${raw} # production audit key`;
  const withZeroWidth = `\u200B${raw}\uFEFF`;

  assert.equal(hexKey('AUDIT_HMAC_KEY', withNamePrefix).toString('hex'), raw);
  assert.equal(hexKey('AUDIT_HMAC_KEY', withExport).toString('hex'), raw);
  assert.equal(hexKey('AUDIT_HMAC_KEY', withComment).toString('hex'), raw);
  assert.equal(hexKey('AUDIT_HMAC_KEY', withZeroWidth).toString('hex'), raw);
});

test('E-04 33-character or passphrase input safely derives a deterministic 32-byte key via SHA-256', () => {
  const key33 = 'a'.repeat(33);
  const buf = hexKey('AUDIT_HMAC_KEY', key33);
  assert.ok(Buffer.isBuffer(buf));
  assert.equal(buf.length, 32);
  const expected = crypto.createHash('sha256').update(key33).digest();
  assert.equal(buf.toString('hex'), expected.toString('hex'));
});

test('E-05 resolveEnv finds lowercase and trailing-space environment variables', () => {
  process.env['test_crypto_key_lowercase'] = '1234';
  process.env['TEST_CRYPTO_KEY_TRAILING '] = '5678';

  assert.equal(resolveEnv('TEST_CRYPTO_KEY_LOWERCASE'), '1234');
  assert.equal(resolveEnv('TEST_CRYPTO_KEY_TRAILING'), '5678');

  delete process.env['test_crypto_key_lowercase'];
  delete process.env['TEST_CRYPTO_KEY_TRAILING '];
});

test('E-06 missing key throws clear error with guidance', () => {
  assert.throws(
    () => hexKey('AUDIT_HMAC_KEY', undefined),
    /Missing required environment variable "AUDIT_HMAC_KEY"/
  );
  assert.throws(
    () => hexKey('FILE_ENC_KEY', ''),
    /Missing required environment variable "FILE_ENC_KEY"/
  );
});

test('E-07 key that is too short (< 16 chars) fails fast without leaking secret', () => {
  const shortAttempt = 'short-secret';
  assert.throws(
    () => hexKey('AUDIT_HMAC_KEY', shortAttempt),
    (err) => {
      assert.ok(err.message.includes('too short'));
      assert.ok(!err.message.includes(shortAttempt));
      return true;
    }
  );
});

test('E-08 AUDIT_HMAC_KEY and FILE_ENC_KEY cannot be identical', () => {
  const sameKey = crypto.randomBytes(32);
  assert.throws(
    () => loadConfig({ auditKey: sameKey, fileKey: sameKey }),
    /AUDIT_HMAC_KEY and FILE_ENC_KEY must be different keys/
  );
});
