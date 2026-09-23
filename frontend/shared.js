// Shared browser helpers used by app.js, portal.js and admin.js.
// Previously each of those carried its own near-identical copy of esc() and api().

const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);

// The server ignores these verbs, so they never need a token — and asking for
// one first would put an extra blocking round trip in front of every page's data.
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

// One shared in-flight promise rather than one fetch per caller. Parallel api()
// calls used to each see an empty token and request their own, and each response
// reset the cookie, so the token we kept was silently invalidated and the next
// POST failed with "token expired".
let csrfPromise = null;
const csrfToken = () =>
  (csrfPromise ??= fetch('/api/csrf')
    .then((r) => r.json())
    .then((d) => d.csrfToken)
    .catch((e) => {
      csrfPromise = null;
      throw e;
    }));

export async function api(url, options = {}, retried = false) {
  const method = (options.method || 'GET').toUpperCase();
  if (!SAFE_METHODS.has(method)) {
    options.headers = { ...(options.headers || {}), 'CSRF-Token': await csrfToken() };
  }
  const res = await fetch(url, options);
  // An error page or a dropped connection will not be JSON; do not let that
  // mask the real status with a parse error.
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 403) csrfPromise = null; // expired token: refetch on the next call
    // The token is cached for the life of the page, so anything that changes
    // the cookie underneath it — a restart, a long-open tab, a second tab that
    // refreshed it — leaves the first write of the session failing. Clearing
    // the cache and letting the *caller* try again is what made a button need
    // pressing twice: the second press worked because the first one repaired
    // the token. Do that repair here instead, once, and only for a stale token.
    if (data.code === 'EBADCSRFTOKEN' && !retried) return api(url, options, true);
    const err = Error(data.error || 'Request failed');
    err.status = res.status;
    // Which input the message is about, when the server can say.
    if (data.field) err.field = data.field;
    throw err;
  }
  return data;
}

export const postJson = (url, body) =>
  api(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

export const patchJson = (url, body) =>
  api(url, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

export const getSession = () => api('/api/session');
export const logout = () => api('/api/auth/logout', { method: 'POST' });

export const isStaff = (role) => ['super_admin', 'admin', 'staff'].includes(role);
export const homeFor = (user) => (isStaff(user?.role) ? '/admin' : '/portal');
export const formData = (form) => {
  const data = Object.fromEntries(new FormData(form));
  form.querySelectorAll('input[data-phone-number]').forEach((input) => {
    const country = form.querySelector(`select[data-phone-country="${input.dataset.phoneNumber}"]`);
    if (country) data[input.name] = `${country.value}:${input.value.trim()}`;
  });
  for (const key of Object.keys(data)) {
    if (key === 'email' || key.endsWith('_email')) data[key] = String(data[key]).trim().toLowerCase();
  }
  return data;
};

// Data the server rendered into the page, so the browser does not refetch what
// it was already given. Absent only if the page was served without the app.
export function bootstrap(id = 'bootstrap') {
  const el = document.getElementById(id);
  if (!el) return null;
  try {
    return JSON.parse(el.textContent);
  } catch {
    return null;
  }
}

// styles.css opts into cross-document view transitions. When one is skipped —
// a redirect, or a navigation the browser decides not to animate — the
// transition's ready promise rejects with an AbortError that no code owns, and
// it surfaces as an unhandled rejection in the console. These handlers claim it.
// Every page imports this module, so registering here covers all of them.
for (const event of ['pagereveal', 'pageswap']) {
  addEventListener(event, (e) => e.viewTransition?.ready.catch(() => {}));
}

// The button only overrides the system preference; with no stored choice the
// stylesheet's prefers-color-scheme block is in charge. theme.js applies the
// stored value before paint — this just handles switching it.
export function initThemeToggle() {
  const btn = document.querySelector('#themeToggle');
  if (!btn) return;
  const media = matchMedia('(prefers-color-scheme: dark)');
  const current = () => document.documentElement.dataset.theme || (media.matches ? 'dark' : 'light');

  const relabel = () => {
    const dark = current() === 'dark';
    btn.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
    btn.setAttribute('aria-pressed', String(dark));
  };

  btn.addEventListener('click', () => {
    const next = current() === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem('theme', next);
    } catch {
      // Not persisted, but the page still switches for this visit.
    }
    relabel();
  });

  media.addEventListener('change', relabel);
  relabel();
}

// The Google button is hidden in the markup and revealed only if the server has
// credentials configured, so an unconfigured deployment never offers a route
// that would immediately fail.
export async function revealGoogleSignIn() {
  const blocks = document.querySelectorAll('[data-google]');
  if (!blocks.length) return;
  try {
    const { available } = await api('/api/auth/google/available');
    if (available) blocks.forEach((b) => { b.hidden = false; });
  } catch {
    // Leave the buttons hidden; the password form still works.
  }
}

export function setStatus(form, msg, ok = true) {
  const p = form.querySelector('.form-status');
  if (!p) return;
  p.textContent = msg;
  p.className = 'form-status ' + (ok ? 'ok' : 'err');
}

// The disable-button / show-progress / report-failure dance that every form on
// the site repeats. Returns null when the request failed, so callers can bail
// without repeating the error branch.
export async function submitForm(form, run, pending = 'Sending…') {
  const btn = form.querySelector('button[type=submit], button:not([type])');
  if (btn) btn.disabled = true;
  setStatus(form, pending);
  try {
    return await run();
  } catch (err) {
    setStatus(form, err.message, false);
    // Put the cursor on the input the server complained about.
    const target = err.field && form.querySelector(`[name="${err.field}"]`);
    if (target) {
      target.focus();
      target.select?.();
    }
    return null;
  } finally {
    if (btn) btn.disabled = false;
  }
}
