'use strict';
const crypto = require('node:crypto');

class HttpError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}

const ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const isId = (s) => typeof s === 'string' && ID_RE.test(s);
const newId = () => crypto.randomUUID();
const nowIso = () => new Date().toISOString();

// Control chars, and the bidirectional overrides used for "evil[RTL]fdp.exe" filename spoofing.
// eslint-disable-next-line no-control-regex
const BAD_CHARS = /[\u0000-\u001F\u007F-\u009F​-‏‪-‮⁦-⁩﻿]/g;

function cleanText(value, { field, min = 1, max = 200, pattern } = {}) {
  if (typeof value !== 'string') throw new HttpError(422, 'invalid_field', `${field} must be text`);
  const v = value.normalize('NFC').replace(BAD_CHARS, '').trim();
  if (v.length < min || v.length > max) {
    throw new HttpError(422, 'invalid_field', `${field} must be ${min}-${max} characters`);
  }
  if (pattern && !pattern.test(v)) throw new HttpError(422, 'invalid_field', `${field} has invalid characters`);
  return v;
}

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}$/;
function cleanEmail(value) {
  const v = cleanText(value, { field: 'email', min: 3, max: 254 }).toLowerCase();
  if (!EMAIL_RE.test(v)) throw new HttpError(422, 'invalid_field', 'email is not valid');
  return v;
}

const escapeLike = (s) => s.replace(/[\\%_]/g, '\\$&');

function parseDateOnly(value, field) {
  if (value == null || value === '') return null;
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value) || Number.isNaN(Date.parse(value))) {
    throw new HttpError(422, 'invalid_field', `${field} must be YYYY-MM-DD`);
  }
  return value;
}

function clampInt(value, def, min, max) {
  const n = Number.parseInt(value, 10);
  if (Number.isNaN(n)) return def;
  return Math.min(max, Math.max(min, n));
}

module.exports = { HttpError, isId, newId, nowIso, cleanText, cleanEmail, escapeLike, parseDateOnly, clampInt };
