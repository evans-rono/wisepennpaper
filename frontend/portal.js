import { esc, api, postJson, getSession, logout, isStaff, formData, setStatus, submitForm, initThemeToggle, revealGoogleSignIn } from '/shared.js';
import { enhancePasswords } from '/password.js';
import { enhancePhoneFields, enhanceEmailFields, setDynamicDateTime } from '/phone.js';

const el = (sel) => document.querySelector(sel);
const els = (sel) => [...document.querySelectorAll(sel)];

const date = (value) => {
  if (!value) return '—';
  const d = new Date(String(value).replace(' ', 'T'));
  return Number.isNaN(d.getTime()) ? esc(value)
    : d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
};

const money = (row) => `${esc(row.currency || 'KES')} ${Number(row.amount || 0).toLocaleString('en-KE', { minimumFractionDigits: 2 })}`;

// One vocabulary for every status the API returns, so a colour always means
// the same thing across projects, quotes, consultations and invoices.
const TONE = {
  ok: ['completed', 'complete', 'paid', 'confirmed', 'approved', 'delivered'],
  warn: ['pending', 'new', 'draft', 'assessment', 'awaiting', 'sent', 'unread'],
  err: ['overdue', 'cancelled', 'declined', 'rejected'],
};
const chip = (status) => {
  const key = String(status || '').toLowerCase();
  const tone = Object.keys(TONE).find((t) => TONE[t].some((w) => key.includes(w))) || 'live';
  return `<span class="chip ${tone}">${esc(status || 'Unknown')}</span>`;
};

const empty = (title, body, action = '') =>
  `<div class="empty-state"><h3>${esc(title)}</h3><p>${esc(body)}</p>${action}</div>`;

const table = (headers, rows) => `<div class="table-wrap"><table class="table">
  <thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead>
  <tbody>${rows.join('')}</tbody></table></div>`;

/* ------------------------------------------------------- sign-in / sign-up */
function initAuthTabs() {
  const tabs = els('.auth-tabs [role=tab]');
  if (!tabs.length) return;
  const show = (name) => {
    tabs.forEach((t) => t.setAttribute('aria-selected', String(t.dataset.authTab === name)));
    el('#login').hidden = name !== 'login';
    el('#register').hidden = name !== 'register';
  };
  tabs.forEach((t) => t.addEventListener('click', () => show(t.dataset.authTab)));
  // /portal?new=1 comes from the "Create account" button on the public site.
  if (new URLSearchParams(location.search).has('new')) show('register');
}

/* ------------------------------------------------------------------ tabs */
function initTabs() {
  const tabs = els('.tabs [role=tab]');
  const select = (name) => {
    tabs.forEach((t) => {
      const on = t.dataset.tab === name;
      t.setAttribute('aria-selected', String(on));
      el('#panel-' + t.dataset.tab).hidden = !on;
    });
  };
  tabs.forEach((t, i) => {
    t.addEventListener('click', () => select(t.dataset.tab));
    t.addEventListener('keydown', (e) => {
      const step = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
      if (!step) return;
      e.preventDefault();
      const next = tabs[(i + step + tabs.length) % tabs.length];
      next.focus();
      select(next.dataset.tab);
    });
  });
  select('projects');
}

/* -------------------------------------------------------------- rendering */
const statTiles = (data) => {
  const open = data.projects.filter((p) => !['Completed', 'Cancelled'].includes(p.status)).length;
  const unpaid = data.invoices.filter((i) => String(i.status).toLowerCase() !== 'paid');
  const owed = unpaid.reduce((sum, i) => sum + Number(i.amount || 0), 0);
  return [
    ['Active projects', open],
    ['Quote requests', data.quotes.length],
    ['Consultations', data.appointments.length],
    ['Outstanding', unpaid.length ? `KES ${owed.toLocaleString('en-KE')}` : 'None'],
  ].map(([label, value]) => `<div class="stat-tile"><strong>${esc(value)}</strong><span>${esc(label)}</span></div>`).join('');
};

const projectCard = (p) => `<article class="panel project-card">
  <div class="card-head">
    <div><small>${esc(p.reference)}</small><h3>${esc(p.title)}</h3></div>
    ${chip(p.status)}
  </div>
  ${p.description ? `<p>${esc(p.description)}</p>` : ''}
  <div class="progress-row">
    <div class="progress" role="progressbar" aria-valuenow="${esc(p.progress)}" aria-valuemin="0"
         aria-valuemax="100" aria-label="Progress for ${esc(p.title)}"><i data-progress="${esc(p.progress)}"></i></div>
    <b>${esc(p.progress)}%</b>
  </div>
  ${p.milestones.length ? `<ul class="milestones">${p.milestones.map((m) =>
    `<li class="${esc(String(m.status).toLowerCase())}">${esc(m.title)}<span>${esc(m.status)}</span></li>`).join('')}</ul>` : ''}
  <details class="thread">
    <summary>Project conversation<span class="count">${p.messages.length}</span></summary>
    <div class="message-thread">${p.messages.length
      ? p.messages.map((m) => `<p><b>${esc(m.sender)}</b><small>${date(m.created_at)}</small><span>${esc(m.body)}</span></p>`).join('')
      : '<p class="muted">No messages yet. Anything you send here reaches the team handling this project.</p>'}</div>
    <form class="message-form" data-project-id="${esc(p.id)}">
      <label>Reply<textarea name="body" rows="3" maxlength="2000" required placeholder="Write a message about this project"></textarea></label>
      <button class="btn small" type="submit">Send message</button>
      <p class="form-status" role="status"></p>
    </form>
  </details>
</article>`;

function renderProjects(data) {
  const host = el('#projects');
  host.innerHTML = data.projects.length
    ? data.projects.map(projectCard).join('')
    : empty('No active projects yet', 'Once a quote is accepted it appears here with its stages, progress and messages.',
      '<p><a class="btn small" href="/#quote">Request a quote</a></p>');

  // Widths through the CSSOM: a style attribute would need 'unsafe-inline'.
  host.querySelectorAll('[data-progress]').forEach((bar) => {
    bar.style.width = Math.max(0, Math.min(100, Number(bar.dataset.progress) || 0)) + '%';
  });

  host.querySelectorAll('.message-form').forEach((form) => {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!form.reportValidity()) return;
      const res = await submitForm(form, () => postJson(
        `/api/client/projects/${encodeURIComponent(form.dataset.projectId)}/messages`,
        { body: form.elements.body.value },
      ), 'Sending…');
      if (!res) return;
      form.reset();
      await load();
    });
  });
}

const renderQuotes = (rows) => el('#quotes').innerHTML = rows.length
  ? table(['Reference', 'Project', 'Submitted', 'Status'], rows.map((q) => `<tr>
      <td><code>${esc(q.reference)}</code></td>
      <td>${esc(q.project_title)}<small>${esc(q.project_type || '')}</small></td>
      <td>${date(q.created_at)}</td><td>${chip(q.status)}</td></tr>`))
  : empty('No quote requests yet', 'Requests you submit on the website appear here with their reference and status.',
    '<p><a class="btn small" href="/#quote">Request a quote</a></p>');

const renderAppointments = (rows) => el('#appointments').innerHTML = rows.length
  ? table(['Reference', 'Type', 'Requested for', 'Status'], rows.map((a) => `<tr>
      <td><code>${esc(a.reference)}</code></td>
      <td>${esc(a.consultation_type)}</td>
      <td>${date(a.preferred_date)}<small>${esc(a.preferred_time || '')}</small></td>
      <td>${chip(a.status)}</td></tr>`))
  : empty('No consultations booked', 'Book one from the website and it appears here once requested.',
    '<p><a class="btn small" href="/#quote">Book a consultation</a></p>');

const renderInvoices = (rows) => el('#invoices').innerHTML = rows.length
  ? table(['Invoice', 'Amount', 'Due', 'Status'], rows.map((i) => `<tr>
      <td><code>${esc(i.number)}</code></td>
      <td>${money(i)}</td><td>${date(i.due_date)}</td><td>${chip(i.status)}</td></tr>`))
  : empty('No invoices yet', 'Invoices raised against your projects appear here.');

/* ---------------------------------------------------------- two-factor */
async function renderSecurity() {
  const state = el('#twoFactorState');
  const area = el('#twoFactorArea');
  let status;
  try {
    status = await api('/api/auth/2fa/status');
  } catch {
    state.textContent = 'Unavailable';
    return;
  }
  state.textContent = status.enabled ? 'On' : 'Off';
  state.className = 'status-line ' + (status.enabled ? 'on' : 'off');

  area.innerHTML = status.enabled
    ? `<form id="recoveryForm" class="inline-form">
         <label>Password<input type="password" name="password" autocomplete="current-password" required></label>
         <button class="btn ghost small" type="submit">New recovery codes</button>
         <p class="form-status" role="status"></p>
       </form>
       <details class="danger-zone">
         <summary>Turn off two-step verification</summary>
         <form id="disableForm" class="inline-form">
           <label>Password<input type="password" name="password" autocomplete="current-password" required></label>
           <label>Current code<input name="code" inputmode="numeric" autocomplete="one-time-code" required></label>
           <button class="btn ghost danger small" type="submit">Turn off</button>
           <p class="form-status" role="status"></p>
         </form>
       </details>`
    : '<button type="button" class="btn small" id="startTwoFactor">Turn on two-step verification</button>';

  el('#startTwoFactor')?.addEventListener('click', startTwoFactorSetup);

  const recovery = el('#recoveryForm');
  recovery?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await submitForm(recovery, () => postJson('/api/auth/2fa/recovery-codes',
      { password: recovery.password.value }), 'Generating…');
    if (res) showRecoveryCodes(res.recoveryCodes, 'New recovery codes');
  });

  const disable = el('#disableForm');
  disable?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await submitForm(disable, () => postJson('/api/auth/2fa/disable',
      { password: disable.password.value, code: disable.code.value }), 'Turning off…');
    if (res) renderSecurity();
  });

  enhancePasswords(area);
}

async function startTwoFactorSetup() {
  const area = el('#twoFactorArea');
  area.innerHTML = '<p class="loading">Preparing…</p>';
  let setup;
  try {
    setup = await postJson('/api/auth/2fa/setup', {});
  } catch (err) {
    area.innerHTML = `<p class="form-status err">${esc(err.message)}</p>`;
    return;
  }
  area.innerHTML = `<ol class="setup-steps">
    <li>Scan this with Google Authenticator, Microsoft Authenticator, 1Password or similar.
      <div class="qr">${setup.qr}</div>
      <p class="field-help">Cannot scan? Enter this key by hand: <code class="setup-key">${esc(setup.secret)}</code></p>
    </li>
    <li><form id="confirmTwoFactor" class="inline-form">
      <label>Enter the six-digit code it shows<input name="code" inputmode="numeric"
        autocomplete="one-time-code" placeholder="123456" required></label>
      <button class="btn small" type="submit">Confirm and turn on</button>
      <p class="form-status" role="status"></p>
    </form></li></ol>`;

  const form = el('#confirmTwoFactor');
  form.code.focus();
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await submitForm(form, () => postJson('/api/auth/2fa/enable', { code: form.code.value }),
      'Checking the code…');
    if (!res) return form.code.select();
    showRecoveryCodes(res.recoveryCodes, 'Two-step verification is on');
  });
}

// Recovery codes are shown once and never again, so this stays on screen until
// the reader dismisses it, and offers a copy that needs no download.
function showRecoveryCodes(codes, heading) {
  const area = el('#twoFactorArea');
  area.innerHTML = `<div class="recovery-box">
    <h3>${esc(heading)}</h3>
    <p class="field-help">Save these recovery codes somewhere safe. Each one signs you in once if you lose your phone, and they are never shown again.</p>
    <ul class="recovery-codes">${codes.map((c) => `<li><code>${esc(c)}</code></li>`).join('')}</ul>
    <div class="form-row">
      <button type="button" class="btn ghost small" id="copyCodes">Copy codes</button>
      <button type="button" class="btn small" id="doneCodes">I have saved them</button>
    </div>
    <p class="form-status" role="status"></p>
  </div>`;
  el('#copyCodes').addEventListener('click', async () => {
    const status = area.querySelector('.form-status');
    try {
      await navigator.clipboard.writeText(codes.join('\n'));
      status.textContent = 'Copied to your clipboard.';
    } catch {
      status.textContent = 'Copying was blocked. Select the codes and copy them by hand.';
    }
  });
  el('#doneCodes').addEventListener('click', renderSecurity);
}

/* ------------------------------------------------------------------ load */
function showNotice(html) {
  el('#auth').classList.add('hidden');
  el('#portal').classList.add('hidden');
  const notice = el('#notice');
  notice.innerHTML = html;
  notice.classList.remove('hidden');
  notice.querySelector('[data-reload]')?.addEventListener('click', () => location.reload());
}

async function load() {
  let user = null;
  try {
    ({ user } = await getSession());
  } catch (err) {
    console.error(err);
  }
  if (!user) return; // the sign-in / register forms are already on screen
  if (isStaff(user.role)) {
    return showNotice(`<h1>You are signed in as staff</h1>
      <p>The client portal only shows projects belonging to a client account.</p>
      <p><a class="btn" href="/admin">Go to the dashboard</a></p>`);
  }

  let data;
  try {
    data = await api('/api/client/portal');
  } catch (err) {
    return showNotice(`<h1>We could not load your account</h1>
      <p>${esc(err.message)}</p><p><button class="btn" type="button" data-reload>Try again</button></p>`);
  }

  el('#auth').classList.add('hidden');
  el('#portal').classList.remove('hidden');
  el('#welcome').textContent = user.name ? `Welcome back, ${user.name.split(' ')[0]}` : 'Your account';
  el('#whoami').textContent = user.email || '';
  el('#portalStats').innerHTML = statTiles(data);

  const profile = el('#profileForm');
  profile.elements.name.value = user.name || '';
  profile.elements.email.value = user.email || '';
  profile.elements.phone.value = user.phone || '';
  profile.dataset.loaded = 'true';

  renderProjects(data);
  renderQuotes(data.quotes);
  renderAppointments(data.appointments);
  renderInvoices(data.invoices);
  renderSecurity();
}

/* --------------------------------------------------------------- wiring */
for (const id of ['login', 'register']) {
  const form = el('#' + id);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!form.reportValidity()) return;
    const res = await submitForm(form, () => postJson('/api/auth/' + id, formData(form)), 'Checking your details…');
    if (!res) return;
    setStatus(form, 'Signed in.');
    load().catch((err) => setStatus(form, err.message, false));
  });
}

el('#forgotPassword').addEventListener('click', async () => {
  const form = el('#login');
  if (!form.email.value.trim()) return setStatus(form, 'Enter your email address first.', false);
  try {
    await postJson('/api/auth/forgot-password', { email: form.email.value.trim() });
    setStatus(form, 'If the account exists, an email with a reset link and six-digit verification code has been sent.');
  } catch (err) { setStatus(form, err.message, false); }
});

el('#profileForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  const result = await submitForm(form, () => api('/api/client/profile', {
    method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(formData(form)),
  }), 'Saving…');
  if (result) setStatus(form, 'Your details were updated.');
});

const passwordForm = el('#passwordForm');
passwordForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!passwordForm.reportValidity()) return;
  const { current_password, new_password } = formData(passwordForm);
  const res = await submitForm(passwordForm,
    () => postJson('/api/auth/password', { current_password, new_password }), 'Updating your password…');
  if (!res) return;
  passwordForm.reset();
  // reset() leaves the meter showing the old reading.
  passwordForm.querySelectorAll('input[type=password]').forEach((i) => i.dispatchEvent(new Event('input')));
  setStatus(passwordForm, 'Password updated. Other devices have been signed out.');
});

el('#logout').addEventListener('click', () => {
  logout().catch(() => {}).finally(() => location.reload());
});

initAuthTabs();
initTabs();
enhancePasswords(document);
enhancePhoneFields();
enhanceEmailFields();
setDynamicDateTime();
initThemeToggle();
revealGoogleSignIn();

load().catch((err) => {
  console.error(err);
  showNotice('<h1>Something went wrong</h1><p>Please refresh the page and try again.</p>');
});
