// Time-based one-time passwords (RFC 6238) for staff sign-in, plus the base32
// encoding and recovery codes that go with them.
//
// Everything here is HMAC over node:crypto — a TOTP is a short, well-specified
// algorithm, and the authenticator apps are the complicated half.

import crypto from 'node:crypto';

const PERIOD = 30;   // seconds per step, as every authenticator app assumes
const DIGITS = 6;
const ALGORITHM = 'sha1'; // what Google Authenticator and friends expect
// One step either side, to tolerate clock drift between server and phone.
const DRIFT_STEPS = 1;

/* ------------------------------------------------------------- base32 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text) {
  let bits = 0;
  let value = 0;
  const out = [];
  for (const char of String(text).toUpperCase().replace(/[\s=-]/g, '')) {
    const index = ALPHABET.indexOf(char);
    if (index === -1) throw new Error('That is not a valid setup key.');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/* --------------------------------------------------------------- codes */

/** A fresh 160-bit secret, in the base32 form authenticator apps expect. */
export const generateSecret = () => base32Encode(crypto.randomBytes(20));

function codeAt(secret, counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac(ALGORITHM, base32Decode(secret)).update(buf).digest();
  // Dynamic truncation, RFC 4226 section 5.4.
  const offset = digest[digest.length - 1] & 0x0f;
  const value = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(value % 10 ** DIGITS).padStart(DIGITS, '0');
}

/** The code for a given moment; exported so tests can pin the clock. */
export const generateCode = (secret, at = Date.now()) =>
  codeAt(secret, Math.floor(at / 1000 / PERIOD));

/**
 * Checks a submitted code, allowing one step of drift either way.
 * Returns the matching step counter (so it can be recorded and not reused), or
 * null. The comparison is length-safe and constant-time.
 */
export function verifyCode(secret, submitted, at = Date.now()) {
  const cleaned = String(submitted ?? '').replace(/\D/g, '');
  if (cleaned.length !== DIGITS) return null;
  const current = Math.floor(at / 1000 / PERIOD);
  for (let drift = -DRIFT_STEPS; drift <= DRIFT_STEPS; drift++) {
    const expected = Buffer.from(codeAt(secret, current + drift));
    const given = Buffer.from(cleaned);
    if (expected.length === given.length && crypto.timingSafeEqual(expected, given)) {
      return current + drift;
    }
  }
  return null;
}

/** The URI an authenticator app reads from the setup QR code. */
export function otpauthUri({ secret, account, issuer }) {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: ALGORITHM.toUpperCase(),
    digits: String(DIGITS),
    period: String(PERIOD),
  });
  return `otpauth://totp/${label}?${params}`;
}

/** Groups the secret into readable blocks for anyone typing it in by hand. */
export const formatSecret = (secret) => secret.replace(/(.{4})/g, '$1 ').trim();

/* ----------------------------------------------------- recovery codes */

const RECOVERY_COUNT = 10;

/** Single-use codes for when the authenticator device is lost. */
export function generateRecoveryCodes(count = RECOVERY_COUNT) {
  return Array.from({ length: count }, () => {
    const raw = crypto.randomBytes(5).toString('hex').toUpperCase(); // 10 characters
    return `${raw.slice(0, 5)}-${raw.slice(5)}`;
  });
}

const normaliseRecovery = (code) => String(code ?? '').toUpperCase().replace(/[^A-Z0-9]/g, '');

// Stored as hashes: a leaked database should not hand over working codes.
export const hashRecoveryCode = (code) =>
  crypto.createHash('sha256').update(normaliseRecovery(code)).digest('hex');

/**
 * Consumes a recovery code from the stored list. Returns the remaining hashes
 * when it matched, or null when it did not.
 */
export function consumeRecoveryCode(storedHashes, submitted) {
  const target = hashRecoveryCode(submitted);
  if (!normaliseRecovery(submitted)) return null;
  let found = false;
  const remaining = storedHashes.filter((hash) => {
    if (!found && hash.length === target.length
      && crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(target))) {
      found = true;
      return false;
    }
    return true;
  });
  return found ? remaining : null;
}
