'use strict';
const fs = require('node:fs');
const crypto = require('node:crypto');
const { nowIso } = require('../util');

const GENESIS = '0'.repeat(64);

/**
 * Append-only, tamper-evident audit trail.
 *
 *  1. Each row's hash = HMAC-SHA256(AUDIT_HMAC_KEY, prev_hash + every field). Editing, inserting or removing
 *     a row in the middle breaks the chain, and without the key an attacker cannot recompute it.
 *  2. SQL triggers refuse UPDATE/DELETE from the application's connection.
 *  3. After every commit the (seq, hash) pair is appended to a separate anchor file. Cutting rows off the END of
 *     the chain (which a chain alone cannot notice) leaves the anchor ahead of the database. Ship that file to
 *     storage the application cannot rewrite (WORM bucket, remote syslog) to cover an attacker who owns this host.
 *  4. Success events are written inside the same transaction as the action they describe: no change without a record.
 *     Refusals are written on their own (outside any rolled-back transaction) so attempts are never lost.
 */
module.exports = ({ db, cfg, models }) => {
  const canonical = (e) => JSON.stringify([
    e.seq, e.ts, e.actor_id, e.actor_email, e.action, e.outcome, e.document_id, e.target_user_id, e.ip, e.detail, e.prev_hash,
  ]);
  const mac = (e) => crypto.createHmac('sha256', cfg.auditKey).update(canonical(e)).digest('hex');

  function append({ actor = null, action, outcome = 'success', documentId = null, targetUserId = null, ip = null, detail = {} }) {
    return db.tx(() => {
      const head = db.prepare('SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1').get();
      const row = {
        seq: head ? head.seq + 1 : 1,
        ts: nowIso(),
        actor_id: actor?.id ?? null,
        actor_email: actor?.email ?? null,
        action,
        outcome,
        document_id: documentId,
        target_user_id: targetUserId,
        ip,
        detail: JSON.stringify(detail ?? {}),
        prev_hash: head ? head.hash : GENESIS,
      };
      row.hash = mac(row);
      db.prepare(
        `INSERT INTO audit_events (seq, ts, actor_id, actor_email, action, outcome, document_id, target_user_id, ip, detail, prev_hash, hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(row.seq, row.ts, row.actor_id, row.actor_email, row.action, row.outcome, row.document_id,
        row.target_user_id, row.ip, row.detail, row.prev_hash, row.hash);
      db.onCommit(() => {
        try { fs.appendFileSync(cfg.anchorFile, `${row.seq} ${row.hash} ${row.ts}\n`, { mode: 0o600 }); }
        catch (e) { console.error('audit anchor write failed:', e.message); }
      });
      return row.seq;
    });
  }

  function readAnchors() {
    if (!fs.existsSync(cfg.anchorFile)) return [];
    return fs.readFileSync(cfg.anchorFile, 'utf8').split('\n').filter(Boolean).map((l) => {
      const [seq, hash] = l.split(' ');
      return { seq: Number(seq), hash };
    });
  }

  /** Re-derive the whole chain and compare with the anchor file. Never throws on tampering: it reports it. */
  function verify() {
    const problems = [];
    let prevHash = GENESIS;
    let expectedSeq = 1;
    let checked = 0;
    const hashes = new Map();
    let after = 0;
    for (;;) {
      const rows = db.prepare('SELECT * FROM audit_events WHERE seq > ? ORDER BY seq LIMIT 1000').all(after);
      if (rows.length === 0) break;
      for (const r of rows) {
        if (r.seq !== expectedSeq) {
          problems.push({ seq: r.seq, reason: `gap in sequence (expected ${expectedSeq})` });
          expectedSeq = r.seq;
        }
        if (r.prev_hash !== prevHash) problems.push({ seq: r.seq, reason: 'prev_hash does not match the previous row' });
        if (mac(r) !== r.hash) problems.push({ seq: r.seq, reason: 'row content does not match its hash' });
        hashes.set(r.seq, r.hash);
        prevHash = r.hash;
        expectedSeq += 1;
        after = r.seq;
        checked += 1;
      }
    }
    const anchors = readAnchors();
    for (const a of anchors) {
      if (!hashes.has(a.seq)) problems.push({ seq: a.seq, reason: 'anchored event is missing from the database (truncation?)' });
      else if (hashes.get(a.seq) !== a.hash) problems.push({ seq: a.seq, reason: 'anchored hash differs from the database' });
    }
    const triggers = db.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' AND name IN ('audit_no_update','audit_no_delete')").all();
    if (triggers.length !== 2) problems.push({ seq: null, reason: 'append-only triggers are missing from the database' });
    return { ok: problems.length === 0, events: checked, anchors: anchors.length, problems: problems.slice(0, 50) };
  }

  return { append, verify, mac, GENESIS, head: () => models.audit.head() };
};
