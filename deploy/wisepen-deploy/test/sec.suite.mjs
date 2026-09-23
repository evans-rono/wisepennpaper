import request from 'supertest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import app from '../backend/server.js';
import { createCsrf, detectFileType, safeFileName } from '../backend/security.js';

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${extra ? ' :: ' + extra : ''}`); }
};

const agent = () => request.agent(app);
const token = async (a) => (await a.get('/api/csrf')).body.csrfToken;
const CONTACT = { name: 'Test Person', email: 't@example.com', subject: 'Hello there', message: 'A message body long enough.' };

/* ------------------------------------------------------------ CSRF unit */

{
  const csrf = createCsrf({ secret: 'unit-test-secret-value', secure: false });
  const run = (mw, req, res = {}) => new Promise((resolve) => mw(req, res, (err) => resolve(err)));
  const mkRes = () => ({ cookie() {}, setHeader() {} });

  const req = { method: 'GET', cookies: {}, get: () => undefined };
  await run(csrf.issue, req, mkRes());
  const good = req.csrfToken();
  ok('issue mints a token', typeof good === 'string' && good.includes('.'));

  const verifyWith = async (cookie, sent, method = 'POST') =>
    run(csrf.verify, { method, cookies: { 'wpnp.csrf': cookie }, get: (h) => (h.toLowerCase() === 'csrf-token' ? sent : undefined), body: {}, query: {} });

  ok('accepts a matching signed pair', (await verifyWith(good, good)) === undefined);
  ok('rejects a missing token', (await verifyWith(good, undefined))?.code === 'EBADCSRFTOKEN');
  ok('rejects a mismatched token', (await verifyWith(good, good.slice(0, -2) + 'xy'))?.code === 'EBADCSRFTOKEN');
  ok('rejects a missing cookie', (await verifyWith(undefined, good))?.code === 'EBADCSRFTOKEN');

  // An attacker who can only write cookies still cannot forge a valid pair.
  const forged = crypto.randomBytes(24).toString('base64url') + '.' + crypto.randomBytes(32).toString('base64url');
  ok('rejects a forged (unsigned) pair', (await verifyWith(forged, forged))?.code === 'EBADCSRFTOKEN');

  // A token minted under a different secret must not validate here.
  const other = createCsrf({ secret: 'a-completely-different-secret', secure: false });
  const oreq = { method: 'GET', cookies: {}, get: () => undefined };
  await run(other.issue, oreq, mkRes());
  const foreign = oreq.csrfToken();
  ok('rejects a token signed with another secret', (await verifyWith(foreign, foreign))?.code === 'EBADCSRFTOKEN');

  // Tampering with the nonce while keeping the signature must fail.
  const [nonce, sig] = good.split('.');
  const tampered = nonce.slice(0, -1) + (nonce.at(-1) === 'A' ? 'B' : 'A') + '.' + sig;
  ok('rejects a tampered nonce', (await verifyWith(tampered, tampered))?.code === 'EBADCSRFTOKEN');

  for (const m of ['GET', 'HEAD', 'OPTIONS']) {
    ok(`${m} needs no token`, (await verifyWith(undefined, undefined, m)) === undefined);
  }
}

/* --------------------------------------------------------- CSRF over HTTP */

{
  const a = agent();
  const t = await token(a);
  ok('GET /api/csrf returns a token', typeof t === 'string' && t.length > 20);
  const cookies = (await a.get('/api/csrf')).headers['set-cookie'] || [];
  const csrfCookie = cookies.find((c) => c.startsWith('wpnp.csrf'));
  ok('csrf cookie is httpOnly', !csrfCookie || /HttpOnly/i.test(csrfCookie), csrfCookie);

  ok('valid token is accepted', (await a.post('/api/contact').set('CSRF-Token', t).send(CONTACT)).status === 201);
  ok('no token is rejected', (await request(app).post('/api/contact').send(CONTACT)).status === 403);

  const b = agent();
  await token(b);
  ok('another session\'s token is rejected',
    (await b.post('/api/contact').set('CSRF-Token', t).send(CONTACT)).status === 403);

  ok('token in the form body is accepted (no-JS path)',
    (await a.post('/api/contact').type('form').send({ ...CONTACT, _csrf: t })).status === 201);

  const stale = await token(a);
  ok('rejects a token whose signature was altered',
    (await a.post('/api/contact').set('CSRF-Token', stale.slice(0, -3) + 'aaa').send(CONTACT)).status === 403);

  ok('the error is a 403 with a readable message',
    (await request(app).post('/api/contact').send(CONTACT)).body.error?.includes('Security token'));
}

/* --------------------------------------------- upload content verification */

const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(64)]);
const PDF = Buffer.concat([Buffer.from('%PDF-1.7\n'), Buffer.alloc(64)]);
const JPG = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(64)]);
const HTML = Buffer.from('<html><script>alert(1)</script></html>');
const EXE = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(64)]);
const ZIP = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(60)]);

function docx() {
  const name = Buffer.from('[Content_Types].xml', 'latin1');
  const head = Buffer.alloc(30);
  head.writeUInt32LE(0x04034b50, 0);
  head.writeUInt16LE(name.length, 26);
  return Buffer.concat([head, name, Buffer.alloc(64)]);
}

{
  const tmp = path.join(process.cwd(), '.sec-tmp');
  fs.mkdirSync(tmp, { recursive: true });
  const sniff = async (buf) => {
    const p = path.join(tmp, 'probe-' + crypto.randomBytes(6).toString('hex'));
    fs.writeFileSync(p, buf);
    const t = await detectFileType(p);
    fs.rmSync(p, { force: true });
    return t;
  };
  ok('detects PNG', (await sniff(PNG))?.ext === '.png');
  ok('detects PDF', (await sniff(PDF))?.ext === '.pdf');
  ok('detects JPEG', (await sniff(JPG))?.ext === '.jpg');
  ok('detects DOCX', (await sniff(docx()))?.ext === '.docx');
  ok('rejects HTML', (await sniff(HTML)) === null);
  ok('rejects an executable', (await sniff(EXE)) === null);
  ok('rejects a plain zip posing as docx', (await sniff(ZIP)) === null);
  ok('rejects an empty file', (await sniff(Buffer.alloc(0))) === null);
  fs.rmSync(tmp, { recursive: true, force: true });
}

const quoteFields = {
  full_name: 'Test Person', email: 't@example.com', phone: '0700000000',
  project_type: 'Book', project_title: 'My Book',
  description: 'A description comfortably over twenty characters long.',
};

const submitQuote = async (a, t, attach) => {
  const r = a.post('/api/quotes').field('_csrf', t);
  for (const [k, v] of Object.entries(quoteFields)) r.field(k, v);
  if (attach) r.attach('files', attach.buf, { filename: attach.name, contentType: attach.type });
  return r;
};

{
  const a = agent();
  const t = await token(a);
  const good = await submitQuote(a, t, { buf: PNG, name: 'cover.png', type: 'image/png' });
  ok('accepts a genuine PNG', good.status === 201, JSON.stringify(good.body));

  // The core fix: bytes decide, not the Content-Type the client claims.
  const a2 = agent();
  const t2 = await token(a2);
  const lie = await submitQuote(a2, t2, { buf: HTML, name: 'manuscript.pdf', type: 'application/pdf' });
  ok('rejects HTML disguised as a PDF', lie.status === 400, `${lie.status} ${JSON.stringify(lie.body)}`);

  const a3 = agent();
  const t3 = await token(a3);
  const exe = await submitQuote(a3, t3, { buf: EXE, name: 'notes.docx', type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });
  ok('rejects an executable disguised as a Word file', exe.status === 400, String(exe.status));

  const a4 = agent();
  const t4 = await token(a4);
  const nasty = await submitQuote(a4, t4, { buf: PDF, name: '../../../etc/pa"ss wd.pdf', type: 'application/pdf' });
  ok('accepts the file but neutralises a traversal filename', nasty.status === 201, String(nasty.status));
}

{
  // Whatever landed on disk must have a server-chosen name and a real extension.
  const dir = path.join(process.cwd(), 'uploads');
  const names = fs.readdirSync(dir).filter((n) => n !== '.gitkeep');
  ok('stored names carry no client-supplied path', names.every((n) => !n.includes('..') && !n.includes('/')));
  ok('stored names use a verified extension', names.every((n) => /^[0-9]+-[0-9a-f]{24}\.(pdf|png|jpg|doc|docx)$/.test(n)),
    names.slice(0, 3).join(', '));
}

ok('safeFileName strips directories', safeFileName('../../etc/passwd') === 'passwd');
ok('safeFileName strips quotes and control chars', safeFileName('a"b c.pdf') === 'abc.pdf');
ok('safeFileName falls back when empty', safeFileName('   ') === 'document');
ok('safeFileName bounds the length', safeFileName('x'.repeat(400)).length <= 120);

/* ------------------------------------------------------------- rate limits */

{
  // Ordinary browsing must never trip the API limiter.
  let blocked = 0;
  const a = agent();
  for (let i = 0; i < 150; i++) if ((await a.get('/api/services')).status === 429) blocked++;
  ok('150 ordinary API reads are not rate limited', blocked === 0, `${blocked} blocked`);

  const headers = (await agent().get('/api/services')).headers;
  // draft-7 emits a combined header: "limit=600, remaining=599, reset=60"
  const limit = Number(/limit=(\d+)/.exec(headers['ratelimit'] || '')?.[1]);
  ok('limit headers advertise a generous ceiling', limit >= 600, headers['ratelimit']);
}

{
  // Successful sign-ins must not consume the credential budget.
  const email = `sec${Date.now()}@example.com`;
  const pw = 'Copper-Vessel-Morning-Ledger-7!';
  const reg = agent();
  await reg.post('/api/auth/register').set('CSRF-Token', await token(reg))
    .send({ name: 'Sec Test', email, phone: '0700000000', password: pw });
  let blocked = 0;
  for (let i = 0; i < 25; i++) {
    const a = agent();
    const r = await a.post('/api/auth/login').set('CSRF-Token', await token(a)).send({ email, password: pw });
    if (r.status === 429) blocked++;
  }
  ok('25 successful sign-ins are not rate limited', blocked === 0, `${blocked} blocked`);
}

/* ---------------------------------------------------------------- headers */

{
  const res = await agent().get('/');
  const h = res.headers;
  ok('CSP present without unsafe-inline', h['content-security-policy'] && !h['content-security-policy'].includes('unsafe-inline'));
  ok('CSP denies framing', h['content-security-policy'].includes("frame-ancestors 'none'"));
  ok('CSP restricts form targets', h['content-security-policy'].includes("form-action 'self'"));
  ok('Permissions-Policy set', (h['permissions-policy'] || '').includes('geolocation=()'), h['permissions-policy']);
  ok('Referrer-Policy set', h['referrer-policy'] === 'strict-origin-when-cross-origin', h['referrer-policy']);
  ok('nosniff set', h['x-content-type-options'] === 'nosniff');
  ok('COOP set', h['cross-origin-opener-policy'] === 'same-origin', h['cross-origin-opener-policy']);
  ok('no x-powered-by', !h['x-powered-by']);
  const auth = await agent().get('/api/session');
  ok('auth responses are no-store', auth.headers['cache-control'] === 'no-store');
}

/* ------------------------------------------------------------ misc surface */

{
  const long = 'a'.repeat(5000);
  const r = await agent().get('/api/search?q=' + long);
  ok('an oversized search term is accepted but bounded', r.status === 200);

  const a = agent();
  const t = await token(a);
  const bad = await a.post('/api/quotes').field('_csrf', t).field('full_name', 'x');
  ok('an invalid quote returns a generic message',
    bad.status === 400 && !/zod|multer|undefined|at Object/i.test(bad.body.error || ''), JSON.stringify(bad.body));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
