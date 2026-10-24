'use strict';
const crypto = require('node:crypto');
const { HttpError } = require('../util');

const COMMON = new Set(['password1234', 'passwordpassword', '123456789012', 'qwertyuiop12', 'letmein12345', 'trustvault123', 'administrator1']);

function scrypt(pw, salt, N, r, p, len) {
  return new Promise((resolve, reject) =>
    crypto.scrypt(pw.normalize('NFKC'), salt, len, { N, r, p, maxmem: 256 * 1024 * N / 1024 + 64 * 1024 * 1024 }, (e, k) => (e ? reject(e) : resolve(k))));
}

module.exports = (cfg) => {
  const N = cfg.scryptN ?? 32768;
  const r = 8;
  const p = 1;
  // Verified against this when the account does not exist, so "unknown user" costs the same as "wrong password".
  let dummy;

  async function hash(pw) {
    const salt = crypto.randomBytes(16);
    const key = await scrypt(pw, salt, N, r, p, 32);
    return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${key.toString('base64')}`;
  }

  async function verify(pw, stored) {
    if (!stored) { dummy ??= await hash('dummy-password-for-timing'); stored = dummy; pw = `x${pw}`; }
    const [alg, n, rr, pp, salt, key] = stored.split('$');
    if (alg !== 'scrypt') return false;
    const expect = Buffer.from(key, 'base64');
    const got = await scrypt(pw, Buffer.from(salt, 'base64'), Number(n), Number(rr), Number(pp), expect.length);
    return crypto.timingSafeEqual(got, expect) && stored !== dummy;
  }

  function checkPolicy(pw, email) {
    if (typeof pw !== 'string') throw new HttpError(422, 'weak_password', 'Password must be text');
    if (pw.length < 12) throw new HttpError(422, 'weak_password', 'Password must be at least 12 characters');
    if (pw.length > 128) throw new HttpError(422, 'weak_password', 'Password must be at most 128 characters');
    if (COMMON.has(pw.toLowerCase()) || (email && pw.toLowerCase().includes(email.split('@')[0].toLowerCase()) && email.split('@')[0].length >= 4)) {
      throw new HttpError(422, 'weak_password', 'Password is too easy to guess');
    }
  }

  return { hash, verify, checkPolicy };
};
