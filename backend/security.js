// CSRF protection and upload content verification.
//
// Both replace things that were taking the client's word for something:
// `csurf` (archived upstream, so no longer receiving fixes) and multer's
// fileFilter, which only ever saw the Content-Type the uploader chose to send.

import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { scanAndRemove } from './malware.js';
import { persistUpload, removeUpload } from './storage.js';

/* ------------------------------------------------------------------ CSRF */

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

const timingSafeEqual = (a, b) => {
  const x = Buffer.from(String(a ?? ''));
  const y = Buffer.from(String(b ?? ''));
  return x.length > 0 && x.length === y.length && crypto.timingSafeEqual(x, y);
};

/**
 * Signed double-submit cookie, the pattern OWASP recommends when there is no
 * server-side token store.
 *
 * The cookie is httpOnly, so a cross-origin page cannot read it, and the token
 * is HMAC-signed, so a party who can only *write* cookies for this domain (a
 * compromised sibling subdomain, say) still cannot mint a pair that validates.
 * Callers receive the token from GET /api/csrf or from a hidden field the
 * server renders, and echo it back in a header or in the form body.
 */
export function createCsrf({ cookieName = 'wpnp.csrf', secret, secure = false }) {
  const key = crypto.createHash('sha256').update('csrf-key:' + secret).digest();
  const sign = (nonce) => crypto.createHmac('sha256', key).update(nonce).digest('base64url');
  const mint = () => {
    const nonce = crypto.randomBytes(24).toString('base64url');
    return `${nonce}.${sign(nonce)}`;
  };

  const wellFormed = (token) => {
    if (typeof token !== 'string') return false;
    const dot = token.indexOf('.');
    if (dot < 1) return false;
    return timingSafeEqual(token.slice(dot + 1), sign(token.slice(0, dot)));
  };

  // Runs on every request so that any rendered page can carry a token.
  const issue = (req, res, next) => {
    if (!req.cookies) req.cookies = {};
    let token = req.cookies[cookieName];
    if (!wellFormed(token)) {
      token = mint();
      res.cookie(cookieName, token, { httpOnly: true, sameSite: 'lax', secure, path: '/' });
      req.cookies[cookieName] = token; // visible to verify() later in this request
    }
    req.csrfToken = () => token;
    next();
  };

  const verify = (req, res, next) => {
    if (SAFE_METHODS.has(req.method)) return next();
    const cookie = req.cookies?.[cookieName];
    const sent = req.get('csrf-token') || req.get('x-csrf-token') || req.body?._csrf || req.query?._csrf;
    if (!wellFormed(cookie) || !timingSafeEqual(sent, cookie)) {
      return next(Object.assign(new Error('Invalid CSRF token'), { code: 'EBADCSRFTOKEN' }));
    }
    next();
  };

  return { issue, verify };
}

/* -------------------------------------------------------- upload contents */

// Multer's fileFilter can only see the Content-Type the uploader supplied, so
// anything at all could arrive labelled application/pdf. These check the bytes
// actually written to disk, and the detected type — not the claimed one — is
// what gets stored and what names the file on disk.
const startsWith = (buf, bytes) => buf.length >= bytes.length && buf.subarray(0, bytes.length).equals(Buffer.from(bytes));

// A .docx is a zip. Reading the first entry's name separates a real Word file
// from an arbitrary archive that merely renamed itself.
function looksLikeDocx(buf) {
  if (!startsWith(buf, [0x50, 0x4b, 0x03, 0x04])) return false;
  if (buf.length < 34) return false;
  const nameLength = buf.readUInt16LE(26);
  const name = buf.subarray(30, Math.min(30 + nameLength, buf.length)).toString('latin1');
  return /^(\[Content_Types\]\.xml|_rels\/|word\/|docProps\/)/.test(name);
}

const SIGNATURES = [
  { mime: 'application/pdf', ext: '.pdf', test: (b) => startsWith(b, [0x25, 0x50, 0x44, 0x46, 0x2d]) },
  { mime: 'image/png', ext: '.png', test: (b) => startsWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) },
  { mime: 'image/jpeg', ext: '.jpg', test: (b) => startsWith(b, [0xff, 0xd8, 0xff]) },
  { mime: 'application/msword', ext: '.doc', test: (b) => startsWith(b, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) },
  {
    mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    ext: '.docx',
    test: looksLikeDocx,
  },
];

export async function detectFileType(filePath) {
  const handle = await fs.promises.open(filePath, 'r');
  try {
    const buf = Buffer.alloc(512);
    const { bytesRead } = await handle.read(buf, 0, 512, 0);
    const head = buf.subarray(0, bytesRead);
    return SIGNATURES.find((s) => s.test(head)) || null;
  } finally {
    await handle.close();
  }
}

// Signature checking proves a file is a Word document; it says nothing about
// what the document carries. A .docm renamed to .docx has the same OOXML zip
// structure and passes detectFileType unchanged, and legacy .doc is an OLE
// container that has held macro viruses since the nineties. The reader here is
// a staff member opening a stranger's manuscript, so the macro is the payload.
//
// Both formats name their macro storage in bytes that survive compression: a
// zip records each entry's path uncompressed in its local header, and OLE keeps
// its directory entry names as UTF-16. Scanning for those names needs no zip or
// OLE parser, and no third-party dependency to keep patched.
// Each marker has to be a name no ordinary manuscript contains. A bare "VBA"
// in UTF-16 would match a .doc whose *text* discusses macros, and rejecting an
// author's chapter about Word automation is a worse outcome than the risk it
// removes. These three are structural names, not prose.
const MACRO_MARKERS = [
  Buffer.from('vbaProject.bin', 'latin1'),      // OOXML: word/vbaProject.bin
  Buffer.from('vbaData.xml', 'latin1'),         // OOXML: word/vbaData.xml
  Buffer.from('_VBA_PROJECT', 'utf16le'),       // OLE compound file directory
];

async function containsMacros(filePath) {
  const handle = await fsp.open(filePath, 'r');
  try {
    const CHUNK = 256 * 1024;
    // The longest marker must not be split across a boundary and missed.
    const overlap = Math.max(...MACRO_MARKERS.map((m) => m.length));
    const buffer = Buffer.alloc(CHUNK + overlap);
    let position = 0, carried = 0;
    for (;;) {
      const { bytesRead } = await handle.read(buffer, carried, CHUNK, position);
      if (!bytesRead) return false;
      const view = buffer.subarray(0, carried + bytesRead);
      if (MACRO_MARKERS.some((marker) => view.includes(marker))) return true;
      carried = Math.min(overlap, view.length);
      view.subarray(view.length - carried).copy(buffer, 0);
      position += bytesRead;
    }
  } finally {
    await handle.close();
  }
}

const WORD_TYPES = new Set([
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
]);

/**
 * Express middleware for use *after* multer. Replaces each file's claimed type
 * with the detected one, renames it to the matching extension, and rejects the
 * request if any file is not one of the permitted formats.
 */
export function verifyUploads(req, res, next) {
  const files = req.files || [];
  if (!files.length) return next();

  (async () => {
    const persisted = [];
    try {
      for (const file of files) {
        const type = await detectFileType(file.path);
        if (!type) {
          throw Object.assign(new Error('One of the files is not a valid PDF, Word, JPG or PNG document.'),
            { status: 400, expose: true });
        }
        file.mimetype = type.mime; // the bytes, not the header the client sent
        if (WORD_TYPES.has(type.mime) && await containsMacros(file.path)) {
          throw Object.assign(new Error('That Word document contains macros, which we cannot accept. Open it in Word and save a copy as .docx (Word Document), which stores the text without them.'),
            { status: 400, expose: true });
        }
        const target = file.path.replace(/\.[^./\\]*$/, '') + type.ext;
        if (target !== file.path) {
          await fs.promises.rename(file.path, target);
          file.path = target;
          file.filename = path.basename(target);
        }
        await scanAndRemove(file);
        const stored = await persistUpload(file);
        file.filename = stored.storedName;
        file.storageDriver = stored.driver;
        persisted.push(stored.storedName);
      }
    } catch (error) {
      await Promise.allSettled(persisted.map((name) => removeUpload(name)));
      throw error;
    }
  })().then(next, (err) => {
    for (const file of files) fs.rmSync(file.path, { force: true });
    next(err);
  });
}

// Filenames come back to the browser in a Content-Disposition header and are
// shown to staff in the dashboard. Strip anything that could be read as a path
// or as header syntax; keep it recognisable to the person who uploaded it.
export function safeFileName(name, fallback = 'document') {
  const base = path
    .basename(String(name ?? ''))
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/["\\]/g, '')
    .trim()
    .slice(0, 120);
  return base || fallback;
}
