import request from 'supertest';
import app from '../backend/server.js';
import { assessPassword, hashPasswordSync, verifyPassword, needsRehash } from '../backend/password.js';
import db from '../backend/db.js';
import bcrypt from 'bcryptjs';

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${extra ? ' :: ' + extra : ''}`); }
};

const agent = () => request.agent(app);
const token = async (a) => (await a.get('/api/csrf')).body.csrfToken;
let n = 0;
const email = () => `pw${Date.now()}-${++n}@example.com`;

const register = async (a, body) => {
  const t = await token(a);
  return a.post('/api/auth/register').set('CSRF-Token', t)
    .send({ name: 'Test Person', phone: '0700000000', ...body });
};

const login = async (a, body) => {
  const t = await token(a);
  return a.post('/api/auth/login').set('CSRF-Token', t).send(body);
};

/* ---------------------------------------------- policy (unit level) */

const rejects = [
  ['too short', 'Short1!aa'],
  ['common password', 'password1234'],
  ['leetspeak common', 'P@ssw0rd1234'],
  ['repeated character', 'aaaaaaaaaaaaaa'],
  ['repeated pattern', 'abcabcabcabcabc'],
  ['keyboard run', 'qwertyuiopqwe'],
  ['alphabet run', 'abcdefghijklm'],
  ['digit run', '123456789012345'],
  ['site name', 'wisepennpaper2026'],
  ['too few distinct chars', 'ababababababab'],
];
for (const [label, pw] of rejects) {
  ok(`policy rejects ${label}`, assessPassword(pw).ok === false, JSON.stringify(assessPassword(pw)));
}
ok('policy rejects name-derived',
  assessPassword('Amina-Wanjiru-2026x', { name: 'Amina Wanjiru' }).ok === false);
ok('policy rejects email-derived',
  assessPassword('jkamau-secret-9912', { email: 'jkamau@example.com' }).ok === false);
ok('policy accepts a punctuated passphrase', assessPassword('Quiet-Lantern-Harbour-Method-9!').ok === true,
  JSON.stringify(assessPassword('Quiet-Lantern-Harbour-Method-9!')));
// Composition rules, on top of length and the blocklist. Each fixture is
// missing exactly one rule, so a failure names the rule that broke.
ok('policy requires a capital', assessPassword('quiet-lantern-harbour-7!').ok === false);
ok('policy requires a number', assessPassword('Quiet-Lantern-Harbour!').ok === false);
ok('policy requires a special character', assessPassword('Quiet lantern harbour 7').ok === false);
ok('a space alone is not a special character', assessPassword('Quiet lantern harbour 77').ok === false);
ok('staff need 16 characters', assessPassword('Short-Pass-12', { role: 'admin' }).ok === false);
ok('policy accepts a strong mixed password', assessPassword('Tr0mbone-Vault-91xz').ok === true);
ok('policy rejects over-long input', assessPassword('a1B!'.repeat(80)).ok === false);
ok('score rises with length',
  assessPassword('Tr0mbone-Vault-91xz-Lantern-Harbour').score >= assessPassword('Tr0mbone-Vlt91').score);

/* ------------------------------------------- bcrypt 72-byte truncation */

const base = 'Quiet-Harbour-Lantern-Method-Truncation-Check-Nairobi-Studio-2026-Extra-Tail';
ok('truncation fixture exceeds 72 bytes', Buffer.byteLength(base) > 72, String(Buffer.byteLength(base)));
const longA = base + 'ONE';
const longB = base + 'TWO';
ok('plain bcrypt would have collided past 72 bytes',
  bcrypt.compareSync(longB, bcrypt.hashSync(longA, 4)) === true);
const tagged = hashPasswordSync(longA);
ok('pre-hashing keeps long passphrases distinct', (await verifyPassword(longB, tagged)) === false);
ok('pre-hashed password still verifies', (await verifyPassword(longA, tagged)) === true);

/* ------------------------------------------------------- legacy hashes */

const legacy = bcrypt.hashSync('legacy-passphrase-here', 10);
ok('legacy hash still verifies', (await verifyPassword('legacy-passphrase-here', legacy)) === true);
ok('legacy hash flagged for rehash', needsRehash(legacy) === true);
ok('new hash not flagged for rehash', needsRehash(tagged) === false);
ok('empty stored hash never matches', (await verifyPassword('anything', null)) === false);

/* ------------------------------------------------- registration policy */

{
  const a = agent();
  const weak = await register(a, { email: email(), password: 'password1234' });
  ok('register rejects a common password', weak.status === 400, JSON.stringify(weak.body));
  ok('register names the offending field', weak.body.field === 'password', JSON.stringify(weak.body));
}
{
  const a = agent();
  const short = await register(a, { email: email(), password: 'Short1!aa' });
  ok('register rejects under 12 characters', short.status === 400);
}
{
  const a = agent();
  const e = email();
  const derived = await register(a, { email: e, password: e.split('@')[0] + '-2026' });
  ok('register rejects an email-derived password', derived.status === 400, JSON.stringify(derived.body));
}

/* ------------------------------------- session regeneration + happy path */

const goodPassword = 'Quiet-Lantern-Harbour-Method-9!';
const userEmail = email();
let userSid;
{
  const a = agent();
  const before = await a.get('/api/session'); // establishes a session cookie
  const pre = before.headers['set-cookie']?.find((c) => c.startsWith('wpnp.sid'));
  const res = await register(a, { email: userEmail, password: goodPassword });
  ok('register succeeds with a good passphrase', res.status === 201, JSON.stringify(res.body));
  const post = res.headers['set-cookie']?.find((c) => c.startsWith('wpnp.sid'));
  ok('register regenerates the session id', !!post && post !== pre, `${pre} -> ${post}`);
  ok('register stores a tagged hash',
    db.prepare('SELECT password_hash h FROM users WHERE email=?').get(userEmail).h.startsWith('sha256$'));
  ok('auth responses are no-store', res.headers['cache-control'] === 'no-store', res.headers['cache-control']);
}
{
  const a = agent();
  const res = await login(a, { email: userEmail, password: goodPassword });
  ok('login succeeds', res.status === 200, JSON.stringify(res.body));
  userSid = res.headers['set-cookie']?.find((c) => c.startsWith('wpnp.sid'));
  ok('login sets a session cookie', !!userSid);
}

/* -------------------------------------------- enumeration / timing parity */

{
  const time = async (body) => {
    const t = process.hrtime.bigint();
    await login(agent(), body);
    return Number(process.hrtime.bigint() - t) / 1e6;
  };
  const runs = 3;
  let missing = 0, wrong = 0;
  for (let i = 0; i < runs; i++) {
    missing += await time({ email: `nobody-${i}-${Date.now()}@example.com`, password: goodPassword });
    wrong += await time({ email: userEmail, password: 'definitely-not-the-password-x' });
  }
  const ratio = (missing / runs) / (wrong / runs);
  ok('unknown account costs the same as a wrong password (no timing oracle)',
    ratio > 0.5 && ratio < 2, `ratio ${ratio.toFixed(2)} (missing ${(missing / runs).toFixed(0)}ms, wrong ${(wrong / runs).toFixed(0)}ms)`);

  const a = await login(agent(), { email: `nobody-x@example.com`, password: 'whatever-here-1' });
  const b = await login(agent(), { email: userEmail, password: 'wrong-password-here-1' });
  ok('both failures return the same status and message',
    a.status === b.status && a.body.error === b.body.error, `${a.body.error} / ${b.body.error}`);
}

/* --------------------------------------------------- per-account throttle */

{
  const target = email();
  await register(agent(), { email: target, password: 'Copper-Vessel-Morning-Ledger-7!' });
  let locked = null;
  for (let i = 0; i < 8 && !locked; i++) {
    const r = await login(agent(), { email: target, password: 'wrong-guess-number-' + i });
    if (r.status === 429) locked = { attempt: i + 1, body: r.body };
  }
  ok('repeated wrong guesses lock the account', !!locked, 'never locked');
  ok('lock message tells the user when to retry', /try again in/i.test(locked?.body?.error || ''), locked?.body?.error);
  ok('lock applies to the correct password too',
    (await login(agent(), { email: target, password: 'Copper-Vessel-Morning-Ledger-7!' })).status === 429);
  // A different account is unaffected by the first one's lockout.
  ok('other accounts are not affected',
    (await login(agent(), { email: userEmail, password: goodPassword })).status === 200);
}

/* ------------------------------------------------------- change password */

{
  const a = agent();
  await login(a, { email: userEmail, password: goodPassword });
  const change = async (body) => {
    const t = await token(a);
    return a.post('/api/auth/password').set('CSRF-Token', t).send(body);
  };

  ok('rejects a wrong current password',
    (await change({ current_password: 'nope-nope-nope', new_password: 'Copper-Vessel-Morning-Ledger-7!' })).status === 401);

  const weak = await change({ current_password: goodPassword, new_password: 'password1234' });
  ok('rejects a weak new password', weak.status === 400, JSON.stringify(weak.body));
  ok('names the new_password field', weak.body.field === 'new_password');

  const same = await change({ current_password: goodPassword, new_password: goodPassword });
  ok('rejects reusing the current password', same.status === 400, JSON.stringify(same.body));

  const newPassword = 'Copper-Vessel-Morning-Ledger-7!';
  const done = await change({ current_password: goodPassword, new_password: newPassword });
  ok('accepts a good new password', done.status === 200, JSON.stringify(done.body));
  const rotated = done.headers['set-cookie']?.find((c) => c.startsWith('wpnp.sid'));
  ok('password change rotates the session', !!rotated && rotated !== userSid);

  ok('old password no longer works',
    (await login(agent(), { email: userEmail, password: goodPassword })).status === 401);
  ok('new password works',
    (await login(agent(), { email: userEmail, password: newPassword })).status === 200);
  ok('change is recorded in the audit log',
    db.prepare("SELECT COUNT(*) n FROM audit_logs WHERE action='password_change'").get().n > 0);
}

{
  const anon = agent();
  const t = await token(anon);
  const res = await anon.post('/api/auth/password').set('CSRF-Token', t)
    .send({ current_password: 'x', new_password: 'Copper-Vessel-Morning-Ledger-7!' });
  ok('change password requires a session', res.status === 401, String(res.status));
}

/* -------------------------------------------- legacy hash upgrade on login */

{
  const e = email();
  const pw = 'Brass-Compass-Evening-Tide-4!';
  db.prepare('INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?,?)')
    .run('Legacy User', e, '0700000000', bcrypt.hashSync(pw, 10), 'client');
  const res = await login(agent(), { email: e, password: pw });
  ok('a pre-existing hash still signs in', res.status === 200, JSON.stringify(res.body));
  const after = db.prepare('SELECT password_hash h FROM users WHERE email=?').get(e).h;
  ok('and is upgraded to the new scheme on the way through', after.startsWith('sha256$'), after.slice(0, 12));
  ok('still signs in after the upgrade',
    (await login(agent(), { email: e, password: pw })).status === 200);
}

/* ----------------------------------------------------------- logout */

{
  const a = agent();
  await login(a, { email: userEmail, password: 'Copper-Vessel-Morning-Ledger-7!' });
  ok('session is live before logout', (await a.get('/api/session')).body.user !== null);
  const lt = await token(a);
  await a.post('/api/auth/logout').set('CSRF-Token', lt);
  ok('session is gone after logout', (await a.get('/api/session')).body.user === null);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
