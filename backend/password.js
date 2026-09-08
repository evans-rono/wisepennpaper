// Password hashing and strength policy.
//
// Split out of server.js so the rules live in one place and can be reasoned
// about on their own. Brute-force throttling lives in store.js, because it has
// to survive a restart and this module is deliberately free of database access.
//
// The guidance here follows NIST SP 800-63B: length and screening against
// known-bad choices do the real work; arbitrary composition rules ("must
// contain a symbol") do not.

import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';

const COST = 12;

export const MIN_LENGTH = 12;
// NIST asks for at least 64 accepted characters; the pre-hash below means we
// can allow far more, and the cap is only here to bound request work.
export const MAX_LENGTH = 200;

/* ------------------------------------------------------------- hashing */

// bcrypt only reads the first 72 bytes of its input and silently discards the
// rest, so "correct horse battery staple ..." style passphrases could collide
// on their first 72 bytes. Hashing to a fixed 44-byte digest first removes the
// truncation entirely. Hashes written this way carry a tag so the older,
// untagged ones still verify.
const PREHASH_TAG = 'sha256$';
const prep = (password) => crypto.createHash('sha256').update(String(password), 'utf8').digest('base64');

export const hashPassword = async (password) => PREHASH_TAG + (await bcrypt.hash(prep(password), COST));
export const hashPasswordSync = (password) => PREHASH_TAG + bcrypt.hashSync(prep(password), COST);

// A real hash to compare against when the account does not exist. Without it,
// a missing email returns before bcrypt ever runs and the response comes back
// measurably sooner — which is enough to enumerate registered addresses.
const DUMMY_HASH = hashPasswordSync(crypto.randomBytes(32).toString('hex'));

export async function verifyPassword(password, storedHash) {
  const stored = storedHash || DUMMY_HASH;
  const candidate = String(password ?? '');
  const match = stored.startsWith(PREHASH_TAG)
    ? await bcrypt.compare(prep(candidate), stored.slice(PREHASH_TAG.length))
    : await bcrypt.compare(candidate, stored); // pre-existing hash
  // Never report a match against the placeholder used for unknown accounts.
  return storedHash ? match : false;
}

// Blocking variant for the seed script, which runs top to bottom before the
// server exists. Never use it on a request path.
export function verifyPasswordSync(password, storedHash) {
  if (!storedHash) return false;
  const candidate = String(password ?? '');
  return storedHash.startsWith(PREHASH_TAG)
    ? bcrypt.compareSync(prep(candidate), storedHash.slice(PREHASH_TAG.length))
    : bcrypt.compareSync(candidate, storedHash);
}

// True for hashes written before the pre-hash change, so a successful login can
// quietly upgrade them.
export const needsRehash = (storedHash) => !String(storedHash || '').startsWith(PREHASH_TAG);

/* ------------------------------------------------ strength / screening */

// The passwords that actually show up in credential-stuffing lists, plus the
// ones this particular site invites. Not exhaustive — it is the cheap first
// filter, with PWNED_CHECK as the thorough one.
const COMMON = new Set([
  '123456', '123456789', '12345678', 'password', 'qwerty', '12345', '123123', '1234567890',
  '1234567', 'qwerty123', '000000', '1q2w3e', 'abc123', 'password1', 'iloveyou', 'monkey',
  'dragon', '111111', 'letmein', 'admin', 'welcome', 'login', 'princess', 'solo', 'master',
  'sunshine', 'football', 'baseball', 'shadow', 'superman', 'trustno1', 'passw0rd', 'zaq12wsx',
  'qazwsx', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz2wsx', 'starwars', 'whatever', 'freedom',
  'ninja', 'azerty', 'batman', 'pokemon', 'jordan', 'harley', 'ranger', 'hunter', 'buster',
  'thomas', 'tigger', 'robert', 'soccer', 'hockey', 'killer', 'george', 'charlie', 'andrew',
  'michelle', 'jessica', 'pepper', 'daniel', 'access', 'flower', 'matrix', 'secret', 'summer',
  'internet', 'service', 'computer', 'letmein123', 'welcome123', 'admin123', 'root', 'toor',
  'changeme', 'default', 'guest', 'test', 'testing', 'temp', 'temporary', 'newpassword',
  'passwordpassword', 'p@ssword', 'p@ssw0rd', 'password123', 'password1234', 'qwerty1234',
  'iloveyou1', 'sunshine1', 'nairobi', 'kenya', 'kenya123', 'safaricom', 'mpesa', 'jambo',
  'harambee', 'wisepen', 'wisepennpaper', 'publishing', 'publisher', 'manuscript',
]);

const SITE_WORDS = ['wisepen', 'wise pen', 'wisepennpaper', 'npaper', 'publishing', 'publish', 'manuscript'];

const LEET = { '@': 'a', '4': 'a', '3': 'e', '1': 'i', '!': 'i', '0': 'o', '$': 's', '5': 's', '7': 't', '+': 't' };

// Collapse the cosmetic variations people use to dodge a blocklist, so
// "P@ssw0rd!!" is recognised as "password".
const normalise = (s) =>
  s.toLowerCase()
    .replace(/[@4310!$57+]/g, (c) => LEET[c] ?? c)
    .replace(/[^a-z0-9]/g, '');

// The forms a blocklist should be consulted with. Decoding leet mangles a
// trailing "1234" into "i2ea", so the trailing-digit-stripped variants are
// checked too — otherwise "P@ssw0rd1234" sails through.
function variants(password) {
  const lower = password.toLowerCase();
  const out = new Set();
  for (const base of [lower, lower.replace(/[^a-z0-9]/g, ''), normalise(password)]) {
    out.add(base);
    out.add(base.replace(/[^a-z]+$/, '')); // drop a trailing 2026 / 123 / !!
    out.add(normalise(base.replace(/[^a-z]+$/, '')));
  }
  out.delete('');
  return out;
}

const isRepetitive = (s) => /^(.)\1+$/.test(s) || /^(..?.?.?)\1{2,}$/.test(s);

// Rows and alphabets a "run" can walk along, forwards or backwards.
const SEQUENCES = ['abcdefghijklmnopqrstuvwxyz', '1234567890', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'azertyuiop', 'qwertzuiop'];
const ADJACENT = new Set();
for (const row of SEQUENCES) {
  for (let i = 1; i < row.length; i++) {
    ADJACENT.add(row[i - 1] + row[i]);
    ADJACENT.add(row[i] + row[i - 1]);
  }
}

// Length of the longest stretch of neighbouring keys. Comparing that against
// the password's own length catches "qwertyuiopqwe" and "123456789012345",
// which a whole-string match misses because they run past the end of the row.
function longestRun(s) {
  const low = s.toLowerCase();
  let best = 1, run = 1;
  for (let i = 1; i < low.length; i++) {
    run = ADJACENT.has(low[i - 1] + low[i]) ? run + 1 : 1;
    if (run > best) best = run;
  }
  return best;
}

const isSequential = (s) => longestRun(s) >= Math.max(6, Math.ceil(s.length * 0.6));

const containsPersonal = (password, ...values) => {
  const norm = normalise(password);
  return values.filter(Boolean).some((value) => {
    const parts = String(value).toLowerCase().split(/[^a-z0-9]+/).filter((p) => p.length >= 4);
    return parts.some((p) => norm.includes(normalise(p)));
  });
};

const variety = (s) =>
  [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(s)).length;

/**
 * Screens a password. Returns { ok, score, problem }.
 * `score` is 0–4 and is only used for the strength meter's wording.
 */
export function assessPassword(password, { email = '', name = '' } = {}) {
  const pw = String(password ?? '');
  const bytes = Buffer.byteLength(pw, 'utf8');

  if (pw.length < MIN_LENGTH) {
    return { ok: false, score: 0, problem: `Use at least ${MIN_LENGTH} characters.` };
  }
  if (bytes > MAX_LENGTH) {
    return { ok: false, score: 0, problem: `Keep the password under ${MAX_LENGTH} characters.` };
  }
  if (/^\s|\s$/.test(pw)) {
    return { ok: false, score: 0, problem: 'Remove the space at the start or end.' };
  }

  const norm = normalise(pw);
  const forms = variants(pw);
  if ([...forms].some((v) => COMMON.has(v))) {
    return { ok: false, score: 0, problem: 'This is one of the most commonly used passwords. Choose something else.' };
  }
  if (isRepetitive(pw)) {
    return { ok: false, score: 0, problem: 'Avoid repeating the same characters or pattern.' };
  }
  if (isSequential(pw)) {
    return { ok: false, score: 0, problem: 'Avoid straight runs of keys such as abcdefgh or qwertyui.' };
  }
  if (containsPersonal(pw, email.split('@')[0], name)) {
    return { ok: false, score: 1, problem: 'Do not build the password out of your name or email address.' };
  }
  if (SITE_WORDS.some((w) => norm.includes(normalise(w)))) {
    return { ok: false, score: 1, problem: 'Do not use this website’s name in your password.' };
  }
  if (new Set(pw).size < 5) {
    return { ok: false, score: 1, problem: 'Use a wider mix of characters.' };
  }

  // Passed everything: grade it for the meter only.
  let score = 2;
  if (pw.length >= 16) score++;
  if (pw.length >= 20 || variety(pw) >= 3) score++;
  return { ok: true, score: Math.min(score, 4), problem: null };
}

/* -------------------------------------------------------- breach check */

// Opt-in (PWNED_CHECK=on). Uses the k-anonymity range API: only the first five
// characters of the SHA-1 are ever sent, never the password. Fails open — a
// third-party outage must not stop people signing up.
export async function isBreached(password) {
  if (process.env.PWNED_CHECK !== 'on') return false;
  const sha1 = crypto.createHash('sha1').update(String(password), 'utf8').digest('hex').toUpperCase();
  const [prefix, suffix] = [sha1.slice(0, 5), sha1.slice(5)];
  try {
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      signal: AbortSignal.timeout(2500),
      headers: { 'Add-Padding': 'true', 'User-Agent': 'wise-pen-platform' },
    });
    if (!res.ok) return false;
    const body = await res.text();
    return body.split('\n').some((line) => line.split(':')[0].trim() === suffix);
  } catch {
    return false;
  }
}
