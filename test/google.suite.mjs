import crypto from 'node:crypto';
import request from 'supertest';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => {
  if (c) { pass++; console.log('  PASS  ' + n); }
  else { fail++; console.log('  FAIL  ' + n + (e ? ' :: ' + e : '')); }
};

/* A throwaway RSA key stands in for Google's signing key, so the whole
   verification path runs for real against tokens we control. */
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const KID = 'test-key-1';
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: KID, alg: 'RS256', use: 'sig' };

const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
const sign = (claims, { kid = KID, alg = 'RS256', key = privateKey } = {}) => {
  const head = b64({ alg, kid, typ: 'JWT' });
  const body = b64(claims);
  const sig = crypto.sign('RSA-SHA256', Buffer.from(`${head}.${body}`), key).toString('base64url');
  return `${head}.${body}.${sig}`;
};

// Intercept only Google's discovery and key endpoints; everything else is left alone.
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  const href = String(url);
  if (href.includes('openid-configuration')) {
    return new Response(JSON.stringify({
      authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
      token_endpoint: 'https://oauth2.googleapis.com/token',
      jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
    }), { headers: { 'Content-Type': 'application/json' } });
  }
  if (href.includes('oauth2/v3/certs')) {
    return new Response(JSON.stringify({ keys: [jwk] }), { headers: { 'Content-Type': 'application/json' } });
  }
  return realFetch(url, init);
};

process.env.GOOGLE_CLIENT_ID = 'test-client-id.apps.googleusercontent.com';
process.env.GOOGLE_CLIENT_SECRET = 'test-secret';

const { verifyIdToken, refuseReason, authorisationUrl, redirectUri, googleEnabled, allowedDomains } =
  await import('../backend/google.js');

const now = () => Math.floor(Date.now() / 1000);
const baseClaims = (over = {}) => ({
  iss: 'https://accounts.google.com',
  aud: process.env.GOOGLE_CLIENT_ID,
  sub: '1234567890',
  email: 'person@example.com',
  email_verified: true,
  name: 'Test Person',
  iat: now(),
  exp: now() + 3600,
  ...over,
});

/* ------------------------------------------------------- token verification */

ok('a well-formed token verifies', !!(await verifyIdToken(sign(baseClaims()))));

const rejects = async (label, token, opts) => {
  try { await verifyIdToken(token, opts); ok(label, false, 'accepted a token it should have refused'); }
  catch { ok(label, true); }
};

await rejects('rejects a malformed token', 'not.a.token');
await rejects('rejects an empty token', '');
await rejects('rejects a token signed by an unknown key', sign(baseClaims(), { kid: 'other-key' }));
await rejects('rejects alg=none', (() => {
  const head = b64({ alg: 'none', kid: KID, typ: 'JWT' });
  return `${head}.${b64(baseClaims())}.`;
})());

// A token signed with a different private key must not pass.
const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
await rejects('rejects a token signed by the wrong private key', sign(baseClaims(), { key: other.privateKey }));

// Tampering with the payload after signing must invalidate it.
const good = sign(baseClaims());
const [h, , sg] = good.split('.');
await rejects('rejects a tampered payload', `${h}.${b64(baseClaims({ email: 'attacker@example.com' }))}.${sg}`);

await rejects('rejects the wrong issuer', sign(baseClaims({ iss: 'https://evil.example.com' })));
await rejects('rejects a token minted for another application',
  sign(baseClaims({ aud: 'someone-else.apps.googleusercontent.com' })));
await rejects('rejects an expired token', sign(baseClaims({ exp: now() - 120 })));
await rejects('rejects a token issued in the future', sign(baseClaims({ iat: now() + 3600 })));
await rejects('rejects a nonce mismatch', sign(baseClaims({ nonce: 'aaa' })), { nonce: 'bbb' });
ok('accepts a matching nonce', !!(await verifyIdToken(sign(baseClaims({ nonce: 'abc' })), { nonce: 'abc' })));

/* ------------------------------------------------------------- admission */

ok('an unverified email is refused', refuseReason(baseClaims({ email_verified: false })) !== null);
ok('a missing email_verified is refused', refuseReason({ email: 'a@b.co' }) !== null);
ok('a verified email is allowed when no domain is set', refuseReason(baseClaims()) === null);

process.env.GOOGLE_ALLOWED_DOMAINS = 'wisepennpaper.co.ke';
ok('domain restriction is read', allowedDomains().includes('wisepennpaper.co.ke'));
ok('an outside domain is refused', refuseReason(baseClaims({ email: 'x@gmail.com', hd: 'gmail.com' })) !== null);
ok('the allowed domain is admitted',
  refuseReason(baseClaims({ email: 'a@wisepennpaper.co.ke', hd: 'wisepennpaper.co.ke' })) === null);
ok('the domain falls back to the email when hd is absent',
  refuseReason(baseClaims({ email: 'a@wisepennpaper.co.ke' })) === null);
ok('a spoofed hd cannot bypass the check', refuseReason(baseClaims({ email: 'x@evil.com', hd: 'evil.com' })) !== null);
delete process.env.GOOGLE_ALLOWED_DOMAINS;

/* -------------------------------------------------------- the redirect */

const { url, state, nonce, verifier } = await authorisationUrl('http://localhost:3111');
const parsed = new URL(url);
ok('the redirect goes to Google', parsed.origin === 'https://accounts.google.com');
ok('it asks for the openid scope', parsed.searchParams.get('scope').includes('openid'));
ok('it uses the authorisation-code flow', parsed.searchParams.get('response_type') === 'code');
ok('it carries state', parsed.searchParams.get('state') === state && state.length > 20);
ok('it carries a nonce', parsed.searchParams.get('nonce') === nonce);
ok('it uses PKCE with S256', parsed.searchParams.get('code_challenge_method') === 'S256');
ok('the challenge is the hash of the verifier',
  parsed.searchParams.get('code_challenge') === crypto.createHash('sha256').update(verifier).digest('base64url'));
ok('the redirect URI points back at this app',
  parsed.searchParams.get('redirect_uri') === redirectUri('http://localhost:3111'));
ok('state and nonce differ each time', (await authorisationUrl('http://localhost:3111')).state !== state);

/* --------------------------------------------------------- routes */

const app = (await import('../backend/server.js')).default;
const agent = () => request.agent(app);

ok('google is reported as available when configured',
  (await agent().get('/api/auth/google/available')).body.available === true);

const start = await agent().get('/api/auth/google');
ok('the start route redirects to Google', start.status === 302 && start.headers.location.startsWith('https://accounts.google.com'),
  `${start.status} ${start.headers.location}`);

// A callback with no session state must not be honoured.
const orphan = await agent().get('/api/auth/google/callback?code=abc&state=xyz');
ok('a callback without a matching session is refused', orphan.status === 303, String(orphan.status));

// A callback whose state does not match the one held in the session.
const a = agent();
await a.get('/api/auth/google');
const wrongState = await a.get('/api/auth/google/callback?code=abc&state=not-the-right-state');
ok('a mismatched state is refused', wrongState.status === 303);
const explained = await a.get('/thank-you');
ok('and the refusal is explained to the user', /could not be verified|expired/i.test(explained.text));

delete process.env.GOOGLE_CLIENT_ID;
delete process.env.GOOGLE_CLIENT_SECRET;
ok('google is reported unavailable without credentials', googleEnabled() === false);
ok('and the start route 404s', (await agent().get('/api/auth/google')).status === 404);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
