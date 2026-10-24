'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','owner','viewer')),
  password_hash TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  failed_logins INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  created_at TEXT NOT NULL,
  password_changed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY,            -- SHA-256 of the cookie token; the raw token is never stored
  user_id TEXT NOT NULL REFERENCES users(id),
  csrf_token TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  ip TEXT,
  user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id),
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  original_name TEXT NOT NULL,
  mime TEXT NOT NULL,
  current_version INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_documents_deleted ON documents(deleted_at);

CREATE TABLE IF NOT EXISTS document_versions (
  document_id TEXT NOT NULL REFERENCES documents(id),
  version INTEGER NOT NULL,
  storage_key TEXT NOT NULL UNIQUE,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  uploaded_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  PRIMARY KEY (document_id, version)
);

CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES documents(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  level TEXT NOT NULL CHECK (level IN ('read','edit')),
  granted_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  revoked_by TEXT
);
-- At most one live grant per (document, person). History rows (revoked) are kept.
CREATE UNIQUE INDEX IF NOT EXISTS uq_grants_active ON grants(document_id, user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_grants_user ON grants(user_id);

-- Assistive suggestions. A row here grants NOTHING; only an owner's explicit grant request does.
CREATE TABLE IF NOT EXISTS suggestions (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES documents(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  level TEXT NOT NULL CHECK (level IN ('read')),
  reason TEXT NOT NULL,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  decision TEXT CHECK (decision IN ('accepted','rejected')),
  decided_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
  seq INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,
  actor_id TEXT,
  actor_email TEXT,
  action TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('success','denied','error')),
  document_id TEXT,
  target_user_id TEXT,
  ip TEXT,
  detail TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_doc ON audit_events(document_id, seq);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(actor_id, seq);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);

-- First line of defence for the audit trail: the application's own connection cannot rewrite history.
-- (Someone with raw database access can drop these; the HMAC chain + external anchor is what detects that.)
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
`;

/**
 * Thin wrapper over node:sqlite adding statement caching and nestable transactions.
 * tx() callbacks MUST be synchronous: the transaction depth is process-wide state, so an
 * await inside would let another request interleave into this transaction.
 */
function openDb(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const raw = new DatabaseSync(file);
  raw.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  raw.exec(SCHEMA);
  if (file !== ':memory:') {
    for (const f of [file, `${file}-wal`, `${file}-shm`]) {
      try { fs.chmodSync(f, 0o600); } catch { /* may not exist yet */ }
    }
  }

  const cache = new Map();
  const prepare = (sql) => {
    let st = cache.get(sql);
    if (!st) { st = raw.prepare(sql); cache.set(sql, st); }
    return st;
  };

  let depth = 0;
  let hooks = [];
  function tx(fn) {
    if (depth === 0) {
      raw.exec('BEGIN IMMEDIATE');
      depth = 1;
      try {
        const result = fn();
        if (result && typeof result.then === 'function') throw new Error('tx() callback must be synchronous');
        raw.exec('COMMIT');
        depth = 0;
        const toRun = hooks;
        hooks = [];
        for (const h of toRun) {
          try { h(); } catch (e) { console.error('post-commit hook failed:', e.message); }
        }
        return result;
      } catch (e) {
        try { raw.exec('ROLLBACK'); } catch { /* already rolled back */ }
        depth = 0;
        hooks = [];
        throw e;
      }
    }
    const name = `sp${depth}`;
    const hookMark = hooks.length;
    raw.exec(`SAVEPOINT ${name}`);
    depth += 1;
    try {
      const result = fn();
      if (result && typeof result.then === 'function') throw new Error('tx() callback must be synchronous');
      raw.exec(`RELEASE ${name}`);
      depth -= 1;
      return result;
    } catch (e) {
      raw.exec(`ROLLBACK TO ${name}`);
      raw.exec(`RELEASE ${name}`);
      depth -= 1;
      hooks.length = hookMark;
      throw e;
    }
  }

  return {
    prepare,
    exec: (sql) => raw.exec(sql),
    tx,
    onCommit: (fn) => { if (depth === 0) fn(); else hooks.push(fn); },
    close: () => raw.close(),
    raw,
  };
}

module.exports = { openDb };
