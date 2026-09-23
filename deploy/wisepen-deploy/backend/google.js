// Sign in with Google, via the OpenID Connect authorisation-code flow.
//
// Server-side redirect rather than Google's JavaScript button: the button would
// require loading a third-party script, which means putting an external origin
// back into the script-src policy. This keeps the CSP as it is.
//
// The ID token's signature is verified against Google's published keys, so a
// token the caller made up — or one minted for a different application — is
// rejected before it is looked at.

import crypto from 'node:crypto';

const DISCOVERY = 'https://accounts.google.com/.well-known/openid-configuration';
const ISSUERS = new Set(['https://accounts.google.com', 'accounts.google.com']);

export const googleEnabled = () => !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);

/** Workspace domains allowed to sign in, or null for "any Google account". */
export const allowedDomains = () =>
  (process.env.GOOGLE_ALLOWED_DOMAINS || '')
    .split(',').map((d) => d.trim().toLowerCase()).filter(Boolean);

/* ------------------------------------------------------ discovery + keys */

let cachedConfig = null;
let cachedKeys = { at: 0, keys: [] };

async function fetchJson(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) throw new Error(`Google returned ${res.status} for ${url}`);
  return res.json();
}

async function config() {
  // The document is effectively static; one fetch per process is plenty.
  cachedConfig ??= await fetchJson(DISCOVERY);
  return cachedConfig;
}

async function signingKeys() {
  // Google rotates these, so they are refreshed rather than pinned.
  if (Date.now() - cachedKeys.at < 60 * 60_000 && cachedKeys.keys.length) return cachedKeys.keys;
  const { jwks_uri: jwksUri } = await config();
  const { keys } = await fetchJson(jwksUri);
  cachedKeys = { at: Date.now(), keys };
  return keys;
}

/* ------------------------------------------------------------ ID tokens */

const b64url = (input) => Buffer.from(input, 'base64url');

/**
 * Verifies signature, issuer, audience and expiry, and returns the claims.
 * Throws on anything that does not check out.
 */
export async function verifyIdToken(idToken, { nonce } = {}) {
  const parts = String(idToken || '').split('.');
  if (parts.length !== 3) throw new Error('Malformed identity token');
  const [rawHeader, rawPayload, rawSignature] = parts;

  const header = JSON.parse(b64url(rawHeader).toString('utf8'));
  const claims = JSON.parse(b64url(rawPayload).toString('utf8'));
  if (header.alg !== 'RS256') throw new Error('Unexpected token algorithm');

  const jwk = (await signingKeys()).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('Identity token was not signed by a known Google key');

  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const signed = Buffer.from(`${rawHeader}.${rawPayload}`);
  if (!crypto.verify('RSA-SHA256', signed, key, b64url(rawSignature))) {
    throw new Error('Identity token signature does not verify');
  }

  if (!ISSUERS.has(claims.iss)) throw new Error('Identity token came from the wrong issuer');
  // Without the audience check, a token Google issued for some other
  // application would be accepted here.
  if (claims.aud !== process.env.GOOGLE_CLIENT_ID) throw new Error('Identity token was issued for another application');
  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== 'number' || claims.exp < now - 60) throw new Error('Identity token has expired');
  if (typeof claims.iat === 'number' && claims.iat > now + 300) throw new Error('Identity token is not valid yet');
  if (nonce && claims.nonce !== nonce) throw new Error('Identity token does not match this sign-in attempt');

  return claims;
}

/* ------------------------------------------------------------ the flow */

export const redirectUri = (baseUrl) => `${baseUrl.replace(/\/+$/, '')}/api/auth/google/callback`;

/**
 * Builds the URL to send the browser to, plus the one-time values that have to
 * be kept in the session and checked when Google sends the browser back.
 */
export async function authorisationUrl(baseUrl) {
  const { authorization_endpoint: endpoint } = await config();
  const state = crypto.randomBytes(24).toString('base64url');
  const nonce = crypto.randomBytes(24).toString('base64url');
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');

  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri(baseUrl),
    response_type: 'code',
    scope: 'openid email profile',
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    prompt: 'select_account',
  });
  const domains = allowedDomains();
  // A hint only — the hd claim is still checked on the way back.
  if (domains.length === 1) params.set('hd', domains[0]);

  return { url: `${endpoint}?${params}`, state, nonce, verifier };
}

export async function exchangeCode({ code, verifier, baseUrl }) {
  const { token_endpoint: endpoint } = await config();
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    signal: AbortSignal.timeout(8000),
    body: new URLSearchParams({
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri(baseUrl),
      grant_type: 'authorization_code',
      code_verifier: verifier,
    }),
  });
  if (!res.ok) throw new Error('Google would not exchange that sign-in code');
  return res.json();
}

/**
 * Decides whether a set of verified claims may sign in at all.
 * Returns null when acceptable, or a message explaining the refusal.
 */
export function refuseReason(claims) {
  // An unverified address is the one that matters: without this check, anyone
  // able to have Google issue a token for an address they do not own gets in.
  if (claims.email_verified !== true) return 'That Google account has no verified email address.';
  const domains = allowedDomains();
  if (domains.length) {
    const domain = String(claims.hd || claims.email || '').split('@').pop().toLowerCase();
    if (!domains.includes(domain)) return 'That Google account is not part of an allowed organisation.';
  }
  return null;
}
