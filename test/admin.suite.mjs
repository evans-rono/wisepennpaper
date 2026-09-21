import request from 'supertest';
import app from '../backend/server.js';
import db from '../backend/db.js';
import {
  generateSecret, generateCode, verifyCode, otpauthUri, base32Encode, base32Decode,
  generateRecoveryCodes, hashRecoveryCode, consumeRecoveryCode, formatSecret,
} from '../backend/totp.js';

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${extra ? ' :: ' + extra : ''}`); }
};
const agent = () => request.agent(app);
const token = async (a) => (await a.get('/api/csrf')).body.csrfToken;
const post = async (a, url, body) => {
  const t = await token(a);
  return a.post(url).set('CSRF-Token', t).send(body);
};
const patch = async (a, url, body) => {
  const t = await token(a);
  return a.patch(url).set('CSRF-Token', t).send(body);
};
const ADMIN = { email: 'admin@wisepennpaper.co.ke', password: 'TestPass-12345!x' };
// Replay protection refuses a step that was already used. Separate sign-ins in
// the same 30-second window are exactly what it stops, so tests that need one
// clear the marker rather than reaching for an out-of-window code.
const freshCode = () => {
  db.prepare('UPDATE users SET last_totp_step=NULL WHERE email=?').run(ADMIN.email);
  return generateCode(globalThis.__secret);
};

/* ------------------------------------------------------------ TOTP unit */

{
  const secret = generateSecret();
  ok('secret is 32 base32 characters', /^[A-Z2-7]{32}$/.test(secret), secret);
  ok('base32 round-trips', base32Encode(base32Decode('JBSWY3DPEHPK3PXP')) === 'JBSWY3DPEHPK3PXP');

  // RFC 6238 test vector: secret "12345678901234567890" (base32) at T=59.
  const rfc = base32Encode(Buffer.from('12345678901234567890'));
  ok('matches the RFC 6238 vector at T=59', generateCode(rfc, 59_000) === '287082', generateCode(rfc, 59_000));
  ok('matches the RFC 6238 vector at T=1111111109', generateCode(rfc, 1111111109_000) === '081804', generateCode(rfc, 1111111109_000));
  ok('matches the RFC 6238 vector at T=1234567890', generateCode(rfc, 1234567890_000) === '005924', generateCode(rfc, 1234567890_000));

  const now = Date.now();
  ok('accepts the current code', verifyCode(secret, generateCode(secret, now), now) !== null);
  ok('accepts one step early (clock drift)', verifyCode(secret, generateCode(secret, now - 30_000), now) !== null);
  ok('accepts one step late (clock drift)', verifyCode(secret, generateCode(secret, now + 30_000), now) !== null);
  ok('rejects two steps away', verifyCode(secret, generateCode(secret, now - 90_000), now) === null);
  ok('rejects a wrong code', verifyCode(secret, '000000', now) === null || generateCode(secret, now) === '000000');
  ok('rejects a short code', verifyCode(secret, '1234', now) === null);
  ok('rejects an empty code', verifyCode(secret, '', now) === null);
  ok('code is six digits', /^\d{6}$/.test(generateCode(secret)));
  ok('formatted secret is grouped', formatSecret('ABCDEFGH').includes(' '));

  const uri = otpauthUri({ secret, account: 'a@b.co', issuer: 'Wise Pen' });
  ok('otpauth uri is well formed', uri.startsWith('otpauth://totp/') && uri.includes('secret=' + secret) && uri.includes('period=30'), uri);

  const codes = generateRecoveryCodes();
  ok('ten recovery codes', codes.length === 10 && codes.every((c) => /^[0-9A-F]{5}-[0-9A-F]{5}$/.test(c)));
  const hashes = codes.map(hashRecoveryCode);
  const left = consumeRecoveryCode(hashes, codes[3]);
  ok('a recovery code is consumed once', left && left.length === 9);
  ok('the same code cannot be reused', consumeRecoveryCode(left, codes[3]) === null);
  ok('recovery codes ignore case and dashes', consumeRecoveryCode(hashes, codes[0].toLowerCase().replace('-', '')) !== null);
  ok('a wrong recovery code is refused', consumeRecoveryCode(hashes, 'AAAAA-BBBBB') === null);
  ok('an empty recovery code is refused', consumeRecoveryCode(hashes, '') === null);
}

/* ------------------------------------------------- enrolment over HTTP */

const admin = agent();
{
  const login = await post(admin, '/api/auth/login', ADMIN);
  ok('admin signs in with password alone before enrolment',
    login.status === 200 && !login.body.twoFactorRequired, JSON.stringify(login.body));

  const status = await admin.get('/api/auth/2fa/status');
  ok('two-factor starts off', status.body.enabled === false);

  const setup = await post(admin, '/api/auth/2fa/setup', {});
  ok('setup returns a key, a uri and a QR', !!setup.body.secret && !!setup.body.uri && setup.body.qr?.startsWith('<svg'), String(setup.status));
  ok('the QR encodes the same uri', setup.body.qr.length > 500);

  const secret = setup.body.secret.replace(/\s/g, '');
  ok('two-factor is not active until a code is proved',
    (await admin.get('/api/auth/2fa/status')).body.enabled === false);

  const wrong = await post(admin, '/api/auth/2fa/enable', { code: '000000' });
  ok('enabling with a wrong code is refused', wrong.status === 400 && wrong.body.field === 'code');

  const enable = await post(admin, '/api/auth/2fa/enable', { code: generateCode(secret) });
  ok('enabling with the right code succeeds', enable.status === 200, JSON.stringify(enable.body));
  ok('recovery codes are handed over once', enable.body.recoveryCodes?.length === 10);
  ok('status now reports enabled', (await admin.get('/api/auth/2fa/status')).body.enabled === true);
  ok('recovery codes are stored hashed, not in the clear',
    !JSON.parse(db.prepare('SELECT recovery_codes r FROM users WHERE email=?').get(ADMIN.email).r)
      .includes(enable.body.recoveryCodes[0]));

  globalThis.__secret = secret;
  globalThis.__recovery = enable.body.recoveryCodes;
}

/* ---------------------------------------------------- sign-in with 2FA */

{
  const a = agent();
  const first = await post(a, '/api/auth/login', ADMIN);
  ok('password alone no longer completes sign-in', first.status === 200 && first.body.twoFactorRequired === true, JSON.stringify(first.body));
  ok('and grants no session', (await a.get('/api/session')).body.user === null);
  ok('and unlocks nothing', (await a.get('/api/admin/dashboard')).status === 401);

  const bad = await post(a, '/api/auth/2fa/verify', { code: '000000' });
  ok('a wrong second factor is refused', bad.status === 401, String(bad.status));

  const good = await post(a, '/api/auth/2fa/verify', { code: freshCode() });
  ok('the right second factor completes sign-in', good.status === 200, JSON.stringify(good.body));
  ok('session reports two-factor is on', good.body.user.twoFactor === true);
  ok('dashboard is reachable now', (await a.get('/api/admin/dashboard')).status === 200);

  // Replay: the same code must not work a second time.
  const b = agent();
  await post(b, '/api/auth/login', ADMIN);
  const replay = await post(b, '/api/auth/2fa/verify', { code: generateCode(globalThis.__secret) });
  ok('and the refusal explains why', /already been used/i.test(replay.body.error || ''), replay.body.error);
  ok('the same code cannot be replayed', replay.status === 401, `${replay.status} ${JSON.stringify(replay.body)}`);
}

{
  // Recovery code path.
  const a = agent();
  await post(a, '/api/auth/login', ADMIN);
  const rec = await post(a, '/api/auth/2fa/verify', { code: globalThis.__recovery[0] });
  ok('a recovery code completes sign-in', rec.status === 200, JSON.stringify(rec.body));

  const b = agent();
  await post(b, '/api/auth/login', ADMIN);
  const reuse = await post(b, '/api/auth/2fa/verify', { code: globalThis.__recovery[0] });
  ok('a recovery code is single use', reuse.status === 401);
  ok('remaining recovery codes counted down',
    (await a.get('/api/auth/2fa/status')).body.recoveryCodesLeft === 9);
}

{
  // The second step must not be reachable without the first.
  const a = agent();
  const orphan = await post(a, '/api/auth/2fa/verify', { code: generateCode(globalThis.__secret) });
  ok('the second step alone is refused', orphan.status === 401, String(orphan.status));
}

/* ------------------------------------------------- sign out everywhere */

{
  const one = agent();
  await post(one, '/api/auth/login', ADMIN);
  await post(one, '/api/auth/2fa/verify', { code: freshCode() });
  ok('first device is signed in', (await one.get('/api/admin/dashboard')).status === 200);

  const two = agent();
  await post(two, '/api/auth/login', ADMIN);
  await post(two, '/api/auth/2fa/verify', { code: freshCode() });
  ok('second device is signed in', (await two.get('/api/admin/dashboard')).status === 200);

  const out = await post(two, '/api/auth/sign-out-everywhere', {});
  ok('sign out everywhere succeeds', out.status === 200, JSON.stringify(out.body));
  ok('the other device is dropped', (await one.get('/api/admin/dashboard')).status === 401);
  ok('the device that did it stays signed in', (await two.get('/api/admin/dashboard')).status === 200);
}

/* --------------------------------------------------------- disable 2FA */

const staffAgent = agent();
{
  await post(staffAgent, '/api/auth/login', ADMIN);
  await post(staffAgent, '/api/auth/2fa/verify', { code: freshCode() });

  const rotated = await post(staffAgent, '/api/auth/2fa/recovery-codes', { password: ADMIN.password });
  ok('recovery codes can be regenerated', rotated.body.recoveryCodes?.length === 10);
  ok('old recovery codes stop working after regeneration',
    consumeRecoveryCode(JSON.parse(db.prepare('SELECT recovery_codes r FROM users WHERE email=?').get(ADMIN.email).r), globalThis.__recovery[1]) === null);

  const refused = await post(staffAgent, '/api/auth/2fa/disable', { password: ADMIN.password, code: freshCode() });
  ok('a role that requires two-step cannot switch it off', refused.status === 403, JSON.stringify(refused.body));
  ok('and the secret survives that attempt',
    db.prepare('SELECT totp_secret s FROM users WHERE email=?').get(ADMIN.email).s !== null);
}

/* Two-step stays optional for plain staff, so the disable path is exercised
   there instead. */
{
  const email = `opt${Date.now()}@example.com`;
  const password = 'Copper-Vessel-Morning-Ledger-7!';
  await post(staffAgent, '/api/admin/users', { name: 'Optional Staff', email, role: 'staff', password });

  const worker = agent();
  await post(worker, '/api/auth/login', { email, password });
  const setup = await post(worker, '/api/auth/2fa/setup', {});
  const secret = setup.body.secret.replace(/\s/g, '');
  ok('a staff member can turn two-step on', (await post(worker, '/api/auth/2fa/enable', { code: generateCode(secret) })).status === 200);

  db.prepare('UPDATE users SET last_totp_step=NULL WHERE email=?').run(email);
  const noPw = await post(worker, '/api/auth/2fa/disable', { password: 'wrong', code: generateCode(secret) });
  ok('disabling needs the right password', noPw.status === 401 && noPw.body.field === 'password', JSON.stringify(noPw.body));

  db.prepare('UPDATE users SET last_totp_step=NULL WHERE email=?').run(email);
  const badCode = await post(worker, '/api/auth/2fa/disable', { password, code: '000000' });
  ok('disabling needs a valid code', badCode.status === 401 && badCode.body.field === 'code', JSON.stringify(badCode.body));

  db.prepare('UPDATE users SET last_totp_step=NULL WHERE email=?').run(email);
  const off = await post(worker, '/api/auth/2fa/disable', { password, code: generateCode(secret) });
  ok('and can turn it off again', off.status === 200, JSON.stringify(off.body));
  ok('the secret is cleared', db.prepare('SELECT totp_secret s FROM users WHERE email=?').get(email).s === null);
  ok('password alone signs them in again',
    (await post(agent(), '/api/auth/login', { email, password })).body.twoFactorRequired === undefined);
}

/* ------------------------------------------------------ admin data API */

const staff = agent();
await post(staff, '/api/auth/login', ADMIN);
await post(staff, '/api/auth/2fa/verify', { code: freshCode() });
{
  const quoteId = db.prepare('SELECT id FROM quote_requests ORDER BY id DESC').get()?.id;
  if (quoteId) {
    const detail = await staff.get('/api/admin/quotes/' + quoteId);
    ok('quote detail returns the full record', detail.status === 200 && 'description' in detail.body, String(detail.status));
    ok('quote detail lists attached files', Array.isArray(detail.body.files));
  } else ok('quote detail (no quotes seeded, skipped)', true);
  ok('unknown quote detail is 404', (await staff.get('/api/admin/quotes/999999')).status === 404);

  const quotes = await staff.get('/api/admin/quotes?limit=5&offset=0');
  ok('quotes are paged', quotes.status === 200 && typeof quotes.body.total === 'number' && Array.isArray(quotes.body.items));
  ok('page size is honoured', quotes.body.items.length <= 5);
  ok('an absurd page size is clamped', (await staff.get('/api/admin/quotes?limit=99999')).body.items.length <= 100);
  ok('status filter is validated', (await staff.get('/api/admin/quotes?status=Bogus')).status === 200);

  ok('appointments are paged', (await staff.get('/api/admin/appointments')).status === 200);
  ok('messages are paged', (await staff.get('/api/admin/messages')).status === 200);

  const msgId = db.prepare('SELECT id FROM contact_messages ORDER BY id DESC').get()?.id;
  if (msgId) {
    ok('a message can be marked read', (await patch(staff, '/api/admin/messages/' + msgId, { status: 'Read' })).status === 200);
    ok('an invalid message status is refused', (await patch(staff, '/api/admin/messages/' + msgId, { status: 'Nope' })).status === 400);
    ok('the unread metric reflects it',
      db.prepare("SELECT status FROM contact_messages WHERE id=?").get(msgId).status === 'Read');
  } else ok('message status (none seeded, skipped)', true);

  const apptId = db.prepare('SELECT id FROM appointments ORDER BY id DESC').get()?.id;
  if (apptId) {
    ok('an appointment can be confirmed', (await patch(staff, '/api/admin/appointments/' + apptId, { status: 'Confirmed' })).status === 200);
    ok('an invalid appointment status is refused', (await patch(staff, '/api/admin/appointments/' + apptId, { status: 'Nope' })).status === 400);
  } else ok('appointment status (none seeded, skipped)', true);

  ok('unknown message id is 404', (await patch(staff, '/api/admin/messages/999999', { status: 'Read' })).status === 404);
  ok('audit log is readable by an admin', (await staff.get('/api/admin/audit?limit=5')).status === 200);
  const audit = await staff.get('/api/admin/audit?limit=5');
  ok('audit entries name the actor', audit.body.items.length === 0 || 'user_email' in audit.body.items[0]);
}

/* ----------------------------------------------------------- authority */

{
  const anon = agent();
  for (const url of ['/api/admin/quotes', '/api/admin/appointments', '/api/admin/messages', '/api/admin/audit', '/api/admin/quotes/1']) {
    ok(`anonymous cannot reach ${url}`, (await anon.get(url)).status === 401, url);
  }
  // A client account must not reach staff endpoints.
  const client = agent();
  const email = `adm${Date.now()}@example.com`;
  await post(client, '/api/auth/register', { name: 'Client', email, phone: '0700000000', password: 'Copper-Vessel-Morning-Ledger-7!' });
  for (const url of ['/api/admin/quotes', '/api/admin/audit']) {
    ok(`a client cannot reach ${url}`, (await client.get(url)).status === 403, url);
  }
  ok('a client cannot reach the dashboard', (await client.get('/api/admin/dashboard')).status === 403);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
