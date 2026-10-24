'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { HttpError } = require('../util');

const KEY_RE = /^[0-9a-f]{48}$/;

/** What we accept. Everything is decided by content (magic bytes), then the extension must agree. */
const TYPES = {
  pdf: { mime: 'application/pdf' },
  png: { mime: 'image/png' },
  jpg: { mime: 'image/jpeg' },
  jpeg: { mime: 'image/jpeg' },
  docx: { mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', part: 'word/' },
  xlsx: { mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', part: 'xl/' },
  pptx: { mime: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', part: 'ppt/' },
  txt: { mime: 'text/plain; charset=utf-8' },
  csv: { mime: 'text/csv; charset=utf-8' },
};

function inspect(buf, originalName) {
  if (!buf || buf.length === 0) throw new HttpError(422, 'empty_file', 'The file is empty');
  const ext = path.extname(originalName).slice(1).toLowerCase();
  const type = TYPES[ext];
  if (!type) throw new HttpError(415, 'type_not_allowed', `File type ".${ext}" is not allowed`);
  const head = buf.subarray(0, 8);
  const bad = (why) => new HttpError(415, 'content_mismatch', `The file content does not look like a .${ext} (${why})`);
  if (ext === 'pdf') {
    if (buf.subarray(0, 5).toString('latin1') !== '%PDF-') throw bad('no PDF header');
    const text = buf.toString('latin1');
    if (/\/(JavaScript|JS|Launch|EmbeddedFile)\b/.test(text)) throw new HttpError(422, 'active_content', 'PDFs with scripts, launch actions or embedded files are refused');
  } else if (ext === 'png') {
    if (!head.equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) throw bad('no PNG signature');
  } else if (ext === 'jpg' || ext === 'jpeg') {
    if (!(head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff)) throw bad('no JPEG signature');
  } else if (type.part) {
    if (!(head[0] === 0x50 && head[1] === 0x4b && head[2] === 0x03 && head[3] === 0x04)) throw bad('not a zip container');
    const text = buf.toString('latin1');
    if (!text.includes('[Content_Types].xml') || !text.includes(type.part)) throw bad('missing Office parts');
    if (text.includes('vbaProject.bin')) throw new HttpError(422, 'active_content', 'Documents containing macros are refused');
  } else {
    // txt / csv: must be UTF-8 text with no NUL bytes (rules out executables renamed .txt).
    if (buf.includes(0)) throw bad('binary data');
    try { new TextDecoder('utf-8', { fatal: true }).decode(buf); } catch { throw bad('not valid UTF-8'); }
  }
  return { ext, mime: type.mime };
}

module.exports = ({ cfg }) => {
  fs.mkdirSync(cfg.uploadDir, { recursive: true, mode: 0o700 });
  const pathFor = (key) => {
    if (!KEY_RE.test(key)) throw new Error('invalid storage key');
    return path.join(cfg.uploadDir, key);
  };
  // Per-file key derived from the master key + the file's own random name, so one leaked file key opens one file.
  const fileKey = (key) => Buffer.from(crypto.hkdfSync('sha256', cfg.fileKey, Buffer.alloc(0), Buffer.from(`trustvault-file:${key}`), 32));

  /** Encrypt (AES-256-GCM, key name bound as AAD so ciphertexts cannot be swapped between records) and store. */
  function save(buf) {
    const storageKey = crypto.randomBytes(24).toString('hex');
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', fileKey(storageKey), iv);
    c.setAAD(Buffer.from(storageKey));
    const ct = Buffer.concat([c.update(buf), c.final()]);
    const blob = Buffer.concat([iv, c.getAuthTag(), ct]);
    fs.writeFileSync(pathFor(storageKey), blob, { mode: 0o600, flag: 'wx' });
    return { storageKey, size: buf.length, sha256: crypto.createHash('sha256').update(buf).digest('hex') };
  }

  /** Returns plaintext, or throws {integrity:true} if the blob was modified, swapped or truncated. */
  function read(storageKey, expectedSha256) {
    const blob = fs.readFileSync(pathFor(storageKey));
    const fail = () => Object.assign(new Error('stored file failed its integrity check'), { integrity: true });
    if (blob.length < 28) throw fail();
    const d = crypto.createDecipheriv('aes-256-gcm', fileKey(storageKey), blob.subarray(0, 12));
    d.setAAD(Buffer.from(storageKey));
    d.setAuthTag(blob.subarray(12, 28));
    let pt;
    try { pt = Buffer.concat([d.update(blob.subarray(28)), d.final()]); } catch { throw fail(); }
    if (expectedSha256 && crypto.createHash('sha256').update(pt).digest('hex') !== expectedSha256) throw fail();
    return pt;
  }

  const remove = (storageKey) => { try { fs.unlinkSync(pathFor(storageKey)); } catch { /* already gone */ } };
  return { save, read, remove, inspect };
};
module.exports.inspect = inspect;
