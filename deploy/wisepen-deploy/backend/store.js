// Durable session storage and brute-force throttling, both backed by SQLite.
//
// Both used to live in process memory. That meant every restart or deploy
// signed out every user — and, less obviously, wiped the failed-attempt
// counters, so restarting the server handed an attacker a clean slate. It also
// ruled out running more than one instance.
//
// SQLite is already a dependency and already the source of truth, so it does
// this job with no new infrastructure. Point DB_PATH at shared storage and
// several instances can share both tables.

import session from 'express-session';
import db from './db.js';

db.exec(`
CREATE TABLE IF NOT EXISTS sessions(sid TEXT PRIMARY KEY, expires INTEGER NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS sessions_expires ON sessions(expires);
CREATE TABLE IF NOT EXISTS login_attempts(key TEXT PRIMARY KEY, count INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0, seen INTEGER NOT NULL);
`);

/* ---------------------------------------------------------- session store */

const DEFAULT_TTL_MS = 8 * 60 * 60 * 1000;

export class SqliteSessionStore extends session.Store {
  constructor({ ttlMs = DEFAULT_TTL_MS, sweepMs = 10 * 60_000 } = {}) {
    super();
    this.ttlMs = ttlMs;
    this.statements = {
      get: db.prepare('SELECT data,expires FROM sessions WHERE sid=?'),
      set: db.prepare('INSERT INTO sessions(sid,expires,data) VALUES(?,?,?) ON CONFLICT(sid) DO UPDATE SET expires=excluded.expires,data=excluded.data'),
      touch: db.prepare('UPDATE sessions SET expires=? WHERE sid=?'),
      destroy: db.prepare('DELETE FROM sessions WHERE sid=?'),
      sweep: db.prepare('DELETE FROM sessions WHERE expires<=?'),
      all: db.prepare('SELECT sid,data FROM sessions WHERE expires>?'),
      count: db.prepare('SELECT COUNT(*) n FROM sessions WHERE expires>?'),
      clear: db.prepare('DELETE FROM sessions'),
    };
    this.sweep();
    // unref so an idle timer never holds the process open.
    this.timer = setInterval(() => this.sweep(), sweepMs);
    this.timer.unref?.();
  }

  // An expired row is deleted rather than returned, so a stale cookie cannot be
  // revived by a clock change.
  expiresAt(sess) {
    const cookieExpiry = sess?.cookie?.expires;
    return cookieExpiry ? new Date(cookieExpiry).getTime() : Date.now() + this.ttlMs;
  }

  sweep() {
    try {
      this.statements.sweep.run(Date.now());
    } catch (err) {
      console.error('session sweep failed', err);
    }
  }

  get(sid, cb) {
    try {
      const row = this.statements.get.get(sid);
      if (!row) return cb(null, null);
      if (row.expires <= Date.now()) {
        this.statements.destroy.run(sid);
        return cb(null, null);
      }
      cb(null, JSON.parse(row.data));
    } catch (err) {
      cb(err);
    }
  }

  set(sid, sess, cb) {
    try {
      this.statements.set.run(sid, this.expiresAt(sess), JSON.stringify(sess));
      cb(null);
    } catch (err) {
      cb(err);
    }
  }

  touch(sid, sess, cb) {
    try {
      this.statements.touch.run(this.expiresAt(sess), sid);
      cb(null);
    } catch (err) {
      cb(err);
    }
  }

  destroy(sid, cb) {
    try {
      this.statements.destroy.run(sid);
      cb(null);
    } catch (err) {
      cb(err);
    }
  }

  length(cb) {
    try {
      cb(null, this.statements.count.get(Date.now()).n);
    } catch (err) {
      cb(err);
    }
  }

  all(cb) {
    try {
      cb(null, this.statements.all.all(Date.now()).map((r) => JSON.parse(r.data)));
    } catch (err) {
      cb(err);
    }
  }

  clear(cb) {
    try {
      this.statements.clear.run();
      cb(null);
    } catch (err) {
      cb(err);
    }
  }
}

/* -------------------------------------------------------------- throttling */

// Escalating backoff, keyed per account. Surviving a restart is the point: an
// in-memory counter is cleared by the very thing an attacker can often cause.
const FREE_ATTEMPTS = 5;
const BASE_LOCK_MS = 30_000;
const MAX_LOCK_MS = 15 * 60_000;
const FORGET_AFTER_MS = 60 * 60_000;

const attempts = {
  get: db.prepare('SELECT count,locked_until,seen FROM login_attempts WHERE key=?'),
  upsert: db.prepare('INSERT INTO login_attempts(key,count,locked_until,seen) VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE SET count=excluded.count,locked_until=excluded.locked_until,seen=excluded.seen'),
  clear: db.prepare('DELETE FROM login_attempts WHERE key=?'),
  sweep: db.prepare('DELETE FROM login_attempts WHERE seen<? AND locked_until<?'),
};

setInterval(() => {
  try {
    const now = Date.now();
    attempts.sweep.run(now - FORGET_AFTER_MS, now);
  } catch (err) {
    console.error('login attempt sweep failed', err);
  }
}, 10 * 60_000).unref?.();

/** Milliseconds the caller must wait, or 0 if it may proceed. */
export function lockedFor(key) {
  const row = attempts.get.get(key);
  if (!row) return 0;
  return Math.max(0, row.locked_until - Date.now());
}

export function recordFailure(key) {
  const now = Date.now();
  const row = attempts.get.get(key) || { count: 0, locked_until: 0 };
  const count = row.count + 1;
  const lockedUntil = count > FREE_ATTEMPTS
    ? now + Math.min(BASE_LOCK_MS * 2 ** (count - FREE_ATTEMPTS - 1), MAX_LOCK_MS)
    : 0;
  attempts.upsert.run(key, count, lockedUntil, now);
  return { count, lockedUntil };
}

export const clearFailures = (key) => attempts.clear.run(key);

export const retryMessage = (ms) => {
  const seconds = Math.ceil(ms / 1000);
  if (seconds < 60) return `Too many attempts. Try again in ${seconds} seconds.`;
  return `Too many attempts. Try again in ${Math.ceil(seconds / 60)} minutes.`;
};
