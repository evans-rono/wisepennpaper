import { esc, api, postJson, getSession, logout, isStaff, formData, setStatus, submitForm, initThemeToggle, revealGoogleSignIn } from '/shared.js';
import { enhancePasswords } from '/password.js';
import { enhancePhoneFields, enhanceEmailFields, setDynamicDateTime } from '/phone.js';

const el = (sel) => document.querySelector(sel);

const SECTIONS = [
  ['#quotes', (x) => `<small>${esc(x.reference)}</small><h3>${esc(x.project_title)}</h3><p>${esc(x.status)}</p>`],
  ['#appointments', (x) => `<small>${esc(x.reference)}</small><h3>${esc(x.consultation_type)}</h3>
     <p>${esc(x.preferred_date)} • ${esc(x.status)}</p>`],
  ['#invoices', (x) => `<h3>${esc(x.number)}</h3><p>${esc(x.currency || 'KES')} ${esc(x.amount)} • ${esc(x.status)}</p>`],
];

function showNotice(html) {
  el('#auth').classList.add('hidden');
  el('#portal').classList.add('hidden');
  const notice = el('#notice');
  notice.innerHTML = html;
  notice.classList.remove('hidden');
  // Inline onclick would need 'unsafe-inline' in the script policy.
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
    // A staff account has no client portal record, so the API would just deny
    // it. Say so instead of showing the sign-in form to someone signed in.
    return showNotice(`<h1>You are signed in as staff</h1>
      <p>The client portal only shows projects belonging to a client account.</p>
      <p><a class="btn" href="/admin">Go to the dashboard</a></p>`);
  }

  let data;
  try {
    data = await api('/api/client/portal');
  } catch (err) {
    return showNotice(`<h1>We could not load your projects</h1>
      <p>${esc(err.message)}</p><p><button class="btn" type="button" data-reload>Try again</button></p>`);
  }

  el('#auth').classList.add('hidden');
  el('#portal').classList.remove('hidden');
  const profile = el('#profileForm');
  profile.elements.name.value = user.name || '';
  profile.elements.email.value = user.email || '';
  profile.elements.phone.value = user.phone || '';
  profile.dataset.loaded = 'true';

  el('#projects').innerHTML = data.projects.length
    ? data.projects.map((p) => `<article class="panel project-card">
        <small>${esc(p.reference)}</small><h3>${esc(p.title)}</h3>
        <p>${esc(p.status)} • ${esc(p.progress)}%</p>
        <div class="progress" role="progressbar" aria-valuenow="${esc(p.progress)}" aria-valuemin="0"
             aria-valuemax="100" aria-label="Progress for ${esc(p.title)}"><i data-progress="${esc(p.progress)}"></i></div>
        <ol>${p.milestones.map((m) => `<li>${esc(m.title)} — ${esc(m.status)}</li>`).join('')}</ol>
        <div class="project-messages">
          <h4>Project conversation</h4>
          <div class="message-thread">${p.messages.length
            ? p.messages.map((m) => `<p><b>${esc(m.sender)}</b><small>${esc(String(m.created_at).slice(0, 16).replace('T', ' '))}</small><span>${esc(m.body)}</span></p>`).join('')
            : '<p class="muted">No messages yet.</p>'}</div>
          <form class="message-form" data-project-id="${esc(p.id)}">
            <label>Reply<textarea name="body" rows="3" maxlength="2000" required placeholder="Write a message about this project"></textarea></label>
            <button class="btn small" type="submit">Send message</button>
            <p class="form-status" role="status"></p>
          </form>
        </div>
      </article>`).join('')
    : '<p>No active projects yet.</p>';

  // Set through the CSSOM rather than a style attribute, so the page needs no
  // 'unsafe-inline' in the style-src policy.
  el('#projects').querySelectorAll('[data-progress]').forEach((bar) => {
    bar.style.width = Math.max(0, Math.min(100, Number(bar.dataset.progress) || 0)) + '%';
  });

  el('#projects').querySelectorAll('.message-form').forEach((form) => {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!form.reportValidity()) return;
      const button = form.querySelector('button');
      const status = form.querySelector('.form-status');
      button.disabled = true;
      status.textContent = 'Sending…';
      try {
        await postJson(`/api/client/projects/${encodeURIComponent(form.dataset.projectId)}/messages`, {
          body: form.elements.body.value,
        });
        form.reset();
        status.textContent = 'Message sent.';
        await load();
      } catch (err) {
        status.textContent = err.message;
        status.classList.add('err');
      } finally {
        button.disabled = false;
      }
    });
  });

  for (const [sel, render] of SECTIONS) {
    const items = data[sel.slice(1)] || [];
    el(sel).innerHTML = items.length
      ? items.map((x) => `<article class="panel">${render(x)}</article>`).join('')
      : '<p>Nothing to show.</p>';
  }
}

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
  try { await postJson('/api/auth/forgot-password', { email: form.email.value.trim() }); setStatus(form, 'If the account exists, an email with a reset link and six-digit verification code has been sent.'); }
  catch (err) { setStatus(form, err.message, false); }
});

el('#profileForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  const result = await submitForm(form, () => api('/api/client/profile', { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(formData(form)) }), 'Saving information…');
  if (result) setStatus(form, 'Client information updated.');
});

const passwordForm = el('#passwordForm');
passwordForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!passwordForm.reportValidity()) return;
  const { current_password, new_password } = formData(passwordForm);
  const res = await submitForm(
    passwordForm,
    () => postJson('/api/auth/password', { current_password, new_password }),
    'Updating your password…',
  );
  if (!res) return;
  passwordForm.reset();
  // reset() leaves the meter showing the old reading.
  passwordForm.querySelectorAll('input[type=password]').forEach((i) => i.dispatchEvent(new Event('input')));
  setStatus(passwordForm, 'Password updated. Other devices have been signed out.');
});

el('#logout').addEventListener('click', () => {
  logout().catch(() => {}).finally(() => location.reload());
});

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
