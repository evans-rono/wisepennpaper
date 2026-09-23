// Checks the "forgot password" path on a live deployment:
//   npm run reset:test -- someone@example.com
// It calls the real endpoint over HTTP, then reports whether a reset token was
// created and whether mail is configured to carry it.
//
// With --issue it mints a reset link locally and prints it, for the case where
// SMTP is not working yet and you still need to get into an account. That needs
// shell and database access, which is already enough to change a password hash
// directly, so it grants nothing new.
import 'dotenv/config';
import crypto from 'node:crypto';
import db from './db.js';

// cPanel's "Run JS script" button cannot pass arguments, and shared plans often
// have no terminal at all, so both inputs may also arrive as environment
// variables on the application.
const email = process.argv.find((a) => a.includes('@')) || process.env.RESET_TEST_EMAIL;
const issue = process.argv.includes('--issue') || process.env.RESET_TEST_ISSUE === 'on';
if (!email) {
  console.error('Usage: npm run reset:test -- someone@example.com [--issue]');
  console.error('Or set RESET_TEST_EMAIL (and RESET_TEST_ISSUE=on) and run with no arguments.');
  process.exit(1);
}

const base = (process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/+$/, '');
const ttl = Math.max(Number(process.env.PASSWORD_RESET_TTL_MINUTES) || 30, 5);
const hash = (v) => crypto.createHash('sha256').update(String(v)).digest('hex');
const user = db.prepare('SELECT id,name,email,is_active FROM users WHERE email=?').get(String(email).toLowerCase());

console.log(`Site        ${base}`);
console.log(`Mail        ${process.env.SMTP_HOST ? `${process.env.SMTP_HOST} as ${process.env.MAIL_FROM || process.env.SMTP_USER}` : 'SMTP_HOST is not set — no email can be sent'}`);
console.log(`Account     ${user ? `${user.name} (id ${user.id})${user.is_active === 0 ? ' — DEACTIVATED' : ''}` : 'no account with that email'}`);

if (issue) {
  if (!user) process.exit(1);
  const token = crypto.randomBytes(32).toString('base64url');
  const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  db.prepare('DELETE FROM password_reset_tokens WHERE user_id=?').run(user.id);
  db.prepare('INSERT INTO password_reset_tokens(user_id,token_hash,code_hash,expires_at) VALUES(?,?,?,?)')
    .run(user.id, hash(token), hash(code), new Date(Date.now() + ttl * 60_000).toISOString());
  console.log(`\nReset link  ${base}/reset-password?token=${encodeURIComponent(token)}`);
  console.log(`Code        ${code}`);
  console.log(`Expires     in ${ttl} minutes, single use`);
  db.close();
  process.exit(0);
}

// The real endpoint is CSRF-protected, exactly as the browser sees it.
const csrfRes = await fetch(`${base}/api/csrf`);
const cookie = (csrfRes.headers.getSetCookie?.() || []).map((c) => c.split(';')[0]).join('; ');
const { csrfToken } = await csrfRes.json();
const res = await fetch(`${base}/api/auth/forgot-password`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken, cookie },
  body: JSON.stringify({ email }),
});
const body = await res.json().catch(() => ({}));
console.log(`\nRequest     ${res.status} ${body.message || body.error || ''}`);

const row = user && db.prepare(
  'SELECT created_at,expires_at,used_at FROM password_reset_tokens WHERE user_id=? ORDER BY id DESC LIMIT 1').get(user.id);
console.log(`Token row   ${row ? `created ${row.created_at}, expires ${row.expires_at}` : 'none — no email would have been sent'}`);
console.log(`\nNow check the inbox for ${email} (and its spam folder).`);
console.log('If nothing arrives, the send error is in the application log:');
console.log('  cPanel > Setup Node.js App > your app > Log, or stderr from the running process.');
db.close();
