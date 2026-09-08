import {
  esc, api, postJson, patchJson, getSession, logout, isStaff,
  formData, setStatus, submitForm, bootstrap, initThemeToggle, revealGoogleSignIn,
} from '/shared.js';
import { enhancePasswords } from '/password.js';

const $ = (sel, root = document) => root.querySelector(sel);
const boot = bootstrap('adminBoot') || {};

const setState = (state) => { document.body.dataset.state = state; };

/* ------------------------------------------------------------- sign in */

const loginForm = $('#loginForm');
const twoFactorForm = $('#twoFactorForm');

function showSecondStep(show) {
  loginForm.hidden = show;
  twoFactorForm.hidden = !show;
  if (show) twoFactorForm.code.focus();
  else {
    loginForm.password.value = '';
    loginForm.email.focus();
  }
}

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!loginForm.reportValidity()) return;
  const res = await submitForm(loginForm, () => postJson('/api/auth/login', formData(loginForm)),
    'Checking your details…');
  if (!res) return;
  if (res.twoFactorRequired) {
    setStatus(loginForm, '');
    return showSecondStep(true);
  }
  if (!isStaff(res.user?.role)) {
    return setStatus(loginForm, 'That account does not have staff access.', false);
  }
  enterDashboard(res.user);
});

twoFactorForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!twoFactorForm.reportValidity()) return;
  const res = await submitForm(twoFactorForm,
    () => postJson('/api/auth/2fa/verify', { code: twoFactorForm.code.value }), 'Verifying…');
  if (!res) {
    twoFactorForm.code.select();
    return;
  }
  if (!isStaff(res.user?.role)) {
    return setStatus(twoFactorForm, 'That account does not have staff access.', false);
  }
  enterDashboard(res.user);
});

$('[data-restart]').addEventListener('click', () => {
  twoFactorForm.reset();
  setStatus(twoFactorForm, '');
  showSecondStep(false);
});

/* ----------------------------------------------------------- dashboard */

let me = boot.user || null;
let services = [];

async function enterDashboard(user) {
  me = user;
  setState('signed-in');
  $('#whoami').textContent = `${user.name} · ${user.role.replace('_', ' ')}`;
  // Content tabs are visible to all staff (read-only for plain staff); the
  // team, site details and activity log are for managers only.
  const manager = ['super_admin', 'admin'].includes(user.role);
  for (const id of ['#tab-audit', '#tab-settings', '#tab-team']) $(id).hidden = !manager;
  // An admin who has not enrolled cannot use anything else, so send them
  // straight to where they can fix that rather than to a wall of 403s.
  if (user.mustEnrol) {
    $('#metrics').innerHTML = `<p class="enrol-banner">Two-step verification is required for your role.
      Set it up below to open the dashboard.</p>`;
    return selectTab('security');
  }
  await refreshMetrics();
  selectTab('quotes');
}

async function refreshMetrics() {
  const metrics = $('#metrics');
  try {
    const { metrics: values } = await api('/api/admin/dashboard');
    metrics.innerHTML = Object.entries(values).map(([key, value]) =>
      `<article class="metric"><b>${esc(value)}</b><span>${esc(label(key))}</span></article>`).join('');
  } catch (err) {
    metrics.innerHTML = `<p class="form-status err">${esc(err.message)}</p>`;
  }
}

const label = (key) =>
  key.replace(/([A-Z])/g, (m) => ' ' + m.toLowerCase()).replace(/^./, (c) => c.toUpperCase());

const dateOnly = (value) => String(value ?? '').slice(0, 16).replace('T', ' ');
const kb = (bytes) => `${Math.max(1, Math.round(bytes / 1024))} KB`;

const table = (heads, rows) =>
  `<div class="table-wrap"><table class="table"><thead><tr>${
    heads.map((h) => `<th scope="col">${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows}</tbody></table></div>`;

const empty = (message) => `<p class="empty-state">${esc(message)}</p>`;

const statusSelect = (name, options, current, labelText) =>
  `<label class="sr-only" for="${esc(name)}">${esc(labelText)}</label>
   <select id="${esc(name)}" data-status="${esc(name)}">${
    options.map((o) => `<option${o === current ? ' selected' : ''}>${esc(o)}</option>`).join('')
  }</select><small class="row-status" role="status"></small>`;

const QUOTE_STATUSES = ['New', 'Under Review', 'Contacted', 'Quotation Sent', 'Approved', 'In Progress', 'Completed', 'Cancelled'];
const APPOINTMENT_STATUSES = ['Pending', 'Confirmed', 'Completed', 'Cancelled'];
const MESSAGE_STATUSES = ['Unread', 'Read', 'Replied', 'Archived'];

/* ------------------------------------------------------------- paging */

const PAGE = 25;
const offsets = { quotes: 0, appointments: 0, messages: 0, audit: 0, portfolio: 0, testimonials: 0, faqs: 0, blog: 0 };

const pager = (tab, total) => {
  const from = offsets[tab];
  if (total <= PAGE) return '';
  return `<div class="pager">
    <button type="button" class="btn ghost small" data-page="prev"${from === 0 ? ' disabled' : ''}>Previous</button>
    <span>${from + 1}–${Math.min(from + PAGE, total)} of ${total}</span>
    <button type="button" class="btn ghost small" data-page="next"${from + PAGE >= total ? ' disabled' : ''}>Next</button>
  </div>`;
};

/* --------------------------------------------------------------- tabs */

const TABS = {
  async quotes(panel) {
    const { total, items } = await api(`/api/admin/quotes?limit=${PAGE}&offset=${offsets.quotes}`);
    panel.innerHTML = (items.length ? table(
      ['Reference', 'Client', 'Project', 'Service', 'Status', 'Received', ''],
      items.map((q) => `<tr>
        <td><code>${esc(q.reference)}</code></td>
        <td>${esc(q.full_name)}<br><small>${esc(q.email)}</small></td>
        <td>${esc(q.project_title)}</td>
        <td>${esc(q.service || '—')}</td>
        <td>${statusSelect(`quote-${q.id}`, QUOTE_STATUSES, q.status, `Status for ${q.reference}`)}</td>
        <td>${esc(dateOnly(q.created_at))}</td>
        <td><button type="button" class="btn ghost small" data-quote-detail="${esc(q.id)}">View</button></td>
      </tr>`).join('')) : empty('No quote requests yet.')) + pager('quotes', total);

    bindStatusSelects(panel, (id) => `/api/admin/quotes/${id.replace('quote-', '')}`);
    panel.querySelectorAll('[data-quote-detail]').forEach((b) =>
      b.addEventListener('click', () => openQuote(b.dataset.quoteDetail)));
  },

  async appointments(panel) {
    const { total, items } = await api(`/api/admin/appointments?limit=${PAGE}&offset=${offsets.appointments}`);
    panel.innerHTML = (items.length ? table(
      ['Reference', 'Client', 'Type', 'Preferred', 'Status'],
      items.map((a) => `<tr>
        <td><code>${esc(a.reference)}</code></td>
        <td>${esc(a.full_name)}<br><small>${esc(a.email)}</small><br><small>${esc(a.phone)}</small></td>
        <td>${esc(a.consultation_type)}${a.project_info ? `<br><small>${esc(a.project_info)}</small>` : ''}</td>
        <td>${esc(a.preferred_date)} ${esc(a.preferred_time)}</td>
        <td>${statusSelect(`appointment-${a.id}`, APPOINTMENT_STATUSES, a.status, `Status for ${a.reference}`)}</td>
      </tr>`).join('')) : empty('No consultation requests yet.')) + pager('appointments', total);

    bindStatusSelects(panel, (id) => `/api/admin/appointments/${id.replace('appointment-', '')}`);
  },

  async messages(panel) {
    const { total, items } = await api(`/api/admin/messages?limit=${PAGE}&offset=${offsets.messages}`);
    panel.innerHTML = (items.length ? table(
      ['From', 'Subject', 'Message', 'Received', 'Status'],
      items.map((m) => `<tr${m.status === 'Unread' ? ' class="unread"' : ''}>
        <td>${esc(m.name)}<br><small>${esc(m.email)}</small>${m.phone ? `<br><small>${esc(m.phone)}</small>` : ''}</td>
        <td>${esc(m.subject)}</td>
        <td class="message-cell">${esc(m.message)}</td>
        <td>${esc(dateOnly(m.created_at))}</td>
        <td>${statusSelect(`message-${m.id}`, MESSAGE_STATUSES, m.status, `Status for message from ${m.name}`)}</td>
      </tr>`).join('')) : empty('No enquiries yet.')) + pager('messages', total);

    bindStatusSelects(panel, (id) => `/api/admin/messages/${id.replace('message-', '')}`, refreshMetrics);
  },

  async projects(panel) {
    const { items } = await api('/api/admin/projects');
    panel.innerHTML = items.length ? items.map((p) => `<article class="panel project-admin-card">
      <div class="project-admin-head"><div><small>${esc(p.reference)}</small><h2>${esc(p.title)}</h2><p>${esc(p.client_name)} · ${esc(p.client_email)}</p></div><b>${esc(p.status)} · ${esc(p.progress)}%</b></div>
      <div class="message-thread">${p.messages.length
        ? p.messages.map((m) => `<p><b>${esc(m.sender)}</b><small>${esc(String(m.created_at).slice(0, 16).replace('T', ' '))}</small><span>${esc(m.body)}</span></p>`).join('')
        : '<p class="muted">No messages yet.</p>'}</div>
      <form class="message-form" data-admin-project-id="${esc(p.id)}"><label>Reply<textarea name="body" rows="3" maxlength="2000" required placeholder="Write a message to the client"></textarea></label><button class="btn small" type="submit">Send reply</button><p class="form-status" role="status"></p></form>
    </article>`).join('') : empty('No projects have been created yet.');
    panel.querySelectorAll('[data-admin-project-id]').forEach((form) => form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!form.reportValidity()) return;
      const button = form.querySelector('button');
      const status = form.querySelector('.form-status');
      button.disabled = true;
      status.textContent = 'Sending…';
      try { await postJson(`/api/admin/projects/${encodeURIComponent(form.dataset.adminProjectId)}/messages`, { body: form.elements.body.value }); await selectTab('projects'); }
      catch (err) { status.textContent = err.message; status.classList.add('err'); button.disabled = false; }
    }));
  },

  async services(panel) {
    services = await api('/api/services');
    const canEdit = ['super_admin', 'admin'].includes(me?.role);
    panel.innerHTML = `
      ${canEdit ? `<form id="serviceForm" class="panel account-form">
        <h2>Add a service</h2>
        <label>Name<input name="name" required minlength="2"></label>
        <label>Summary<input name="summary" required minlength="10"></label>
        <label>Description<textarea name="description" rows="3" required minlength="20"></textarea></label>
        <label class="check"><input type="checkbox" name="featured"> Feature on the homepage</label>
        <button class="btn" type="submit">Add service</button>
        <p class="form-status" role="status"></p>
      </form>` : ''}
      ${services.length ? table(
        ['Name', 'Summary', 'Featured', canEdit ? 'Actions' : ''].filter(Boolean),
        services.map((s) => `<tr>
          <td><b>${esc(s.name)}</b><br><small><code>/services/${esc(s.slug)}</code></small></td>
          <td>${esc(s.summary)}</td>
          <td>${s.featured ? 'Yes' : 'No'}</td>
          ${canEdit ? `<td class="row-actions">
            <button type="button" class="btn ghost small" data-service-edit="${esc(s.id)}">Edit</button>
            <button type="button" class="btn ghost small danger" data-service-delete="${esc(s.id)}">Delete</button>
            <small class="row-status" role="status"></small>
          </td>` : ''}
        </tr>`).join('')) : empty('No services published yet.')}`;

    if (canEdit) bindServiceActions(panel);
  },

  portfolio: (panel) => contentTab(panel, 'portfolio'),
  testimonials: (panel) => contentTab(panel, 'testimonials'),
  faqs: (panel) => contentTab(panel, 'faqs'),
  blog: (panel) => contentTab(panel, 'blog'),

  async settings(panel) {
    const { settings } = await api('/api/admin/settings');
    const field = (name, label, hint = '') =>
      `<label>${esc(label)}<input name="${esc(name)}" value="${esc(settings[name] ?? '')}"></label>
       ${hint ? `<small class="field-help">${esc(hint)}</small>` : ''}`;
    panel.innerHTML = `
      <form id="settingsForm" class="panel account-form">
        <h2>Contact details</h2>
        <p class="field-help">These appear in the site footer, the contact section and the structured data search engines read.</p>
        ${field('company_name', 'Company name')}
        ${field('tagline', 'Tagline')}
        ${field('email', 'Email address')}
        ${field('phone', 'Telephone')}
        ${field('whatsapp', 'WhatsApp number', 'Digits only, including the country code — for example 254700000000.')}
        ${field('address', 'Location')}
        ${field('hours', 'Working hours')}

        <h2>Homepage statistics</h2>
        <p class="field-help">Leave a figure blank to hide it. If all five are blank the whole band is hidden, which is the right state until you have verified numbers.</p>
        ${field('books_published', 'Books published')}
        ${field('authors_supported', 'Authors supported')}
        ${field('projects_completed', 'Projects completed')}
        ${field('years_experience', 'Years of experience')}
        ${field('organisations_served', 'Organisations served')}

        <button class="btn" type="submit">Save site details</button>
        <p class="form-status" role="status"></p>
      </form>`;

    const form = $('#settingsForm');
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const res = await submitForm(form, () => patchJson('/api/admin/settings', formData(form)), 'Saving…');
      if (res) setStatus(form, 'Saved. The public site reflects this immediately.');
    });
  },

  async team(panel) {
    const { items } = await api('/api/admin/users');
    const canSuper = me?.role === 'super_admin';
    const roleOptions = (current) => ['staff', 'admin', 'super_admin']
      .map((r) => `<option value="${r}"${r === current ? ' selected' : ''}>${r.replace('_', ' ')}</option>`).join('');

    panel.innerHTML = `
      <form id="staffForm" class="panel account-form">
        <h2>Add a colleague</h2>
        <label>Full name<input name="name" required minlength="2"></label>
        <label>Email<input type="email" name="email" required></label>
        <label>Phone<input name="phone"></label>
        <label>Role<select name="role">
          <option value="staff">staff — dashboard only</option>
          <option value="admin">admin — can also edit content and the team</option>
          ${canSuper ? '<option value="super_admin">super admin — full control</option>' : ''}
        </select></label>
        <label>Temporary password<input type="password" name="password" required minlength="12" data-pw-meter></label>
        <small class="field-help">Ask them to change it once they are in. Admin roles must set up two-step verification before the dashboard opens.</small>
        <button class="btn" type="submit">Create account</button>
        <p class="form-status" role="status"></p>
      </form>
      ${table(['Name', 'Role', 'Two-step', 'Last sign-in', 'Status', 'Actions'],
        items.map((u) => `<tr${u.is_active ? '' : ' class="inactive"'}>
          <td><b>${esc(u.name)}</b><br><small>${esc(u.email)}</small></td>
          <td>${String(u.id) === String(me.id)
            ? `<span class="role-fixed">${esc(u.role.replace('_', ' '))} <small>(you)</small></span>`
            : `<label class="sr-only" for="role-${esc(u.id)}">Role for ${esc(u.name)}</label>
               <select id="role-${esc(u.id)}" data-role="${esc(u.id)}">${roleOptions(u.role)}</select>`}</td>
          <td>${u.two_factor ? '<span class="pill on">on</span>' : '<span class="pill off">off</span>'}</td>
          <td>${esc(dateOnly(u.last_login_at) || 'never')}</td>
          <td>${u.is_active ? 'Active' : 'Deactivated'}</td>
          <td class="row-actions">
            ${String(u.id) === String(me.id) ? '<small class="muted">—</small>' : `
              <button type="button" class="btn ghost small" data-toggle-active="${esc(u.id)}" data-active="${u.is_active ? '1' : '0'}">${u.is_active ? 'Deactivate' : 'Reactivate'}</button>
              ${u.two_factor ? `<button type="button" class="btn ghost small" data-reset-2fa="${esc(u.id)}">Reset 2FA</button>` : ''}`}
            <small class="row-status" role="status"></small>
          </td>
        </tr>`).join(''))}`;

    const form = $('#staffForm');
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!form.reportValidity()) return;
      const res = await submitForm(form, () => postJson('/api/admin/users', formData(form)), 'Creating account…');
      if (res) await selectTab('team');
    });

    const rowAction = (el, run) => async () => {
      const note = el.parentElement.querySelector('.row-status');
      note.textContent = 'Saving…';
      note.className = 'row-status';
      try { await run(); await selectTab('team'); }
      catch (err) { note.textContent = err.message; note.className = 'row-status err'; }
    };

    panel.querySelectorAll('[data-toggle-active]').forEach((b) =>
      b.addEventListener('click', rowAction(b, () =>
        patchJson('/api/admin/users/' + b.dataset.toggleActive, { is_active: b.dataset.active !== '1' }))));

    panel.querySelectorAll('[data-reset-2fa]').forEach((b) =>
      b.addEventListener('click', rowAction(b, () => {
        if (!confirm('Clear this person\'s two-step verification? They will set it up again on their next sign-in.')) throw Error('Cancelled');
        return postJson('/api/admin/users/' + b.dataset.reset2fa + '/reset-2fa', {});
      })));

    panel.querySelectorAll('[data-role]').forEach((sel) => {
      const note = sel.parentElement.querySelector('.row-status') || sel.closest('tr').querySelector('.row-status');
      let previous = sel.value;
      sel.addEventListener('change', async () => {
        sel.disabled = true;
        try { await patchJson('/api/admin/users/' + sel.dataset.role, { role: sel.value }); await selectTab('team'); }
        catch (err) { sel.value = previous; note.textContent = err.message; note.className = 'row-status err'; sel.disabled = false; }
      });
    });
  },

  async security(panel) {
    const status = await api('/api/auth/2fa/status');
    panel.innerHTML = `
      <div class="security-grid">
        <section class="panel">
          <h2>Two-step verification</h2>
          <p class="status-line ${status.enabled ? 'on' : 'off'}">
            ${status.enabled ? 'On' : 'Off'}${status.enabled && status.confirmedAt ? ` · since ${esc(dateOnly(status.confirmedAt))}` : ''}
          </p>
          <p class="field-help">A code from your phone, in addition to your password. Staff accounts can reach every client record, so this is strongly recommended.</p>
          <div id="twoFactorArea"></div>
        </section>

        <section class="panel">
          <h2>Sessions</h2>
          <p class="field-help">Signs out every other browser and device using this account. You stay signed in here.</p>
          <button type="button" class="btn ghost" id="signOutEverywhere">Sign out everywhere else</button>
          <p class="form-status" role="status" id="sessionStatus"></p>
        </section>
      </div>`;

    renderTwoFactorArea(status);
    $('#signOutEverywhere').addEventListener('click', async () => {
      const note = $('#sessionStatus');
      note.textContent = 'Signing out other sessions…';
      note.className = 'form-status';
      try {
        await postJson('/api/auth/sign-out-everywhere', {});
        note.textContent = 'Other sessions have been signed out.';
        note.className = 'form-status ok';
      } catch (err) {
        note.textContent = err.message;
        note.className = 'form-status err';
      }
    });
  },

  async audit(panel) {
    const { total, items } = await api(`/api/admin/audit?limit=${PAGE}&offset=${offsets.audit}`);
    panel.innerHTML = (items.length ? table(
      ['When', 'Who', 'Action', 'Entity', 'Address'],
      items.map((a) => `<tr>
        <td>${esc(dateOnly(a.created_at))}</td>
        <td>${esc(a.user_name || 'anonymous')}${a.user_email ? `<br><small>${esc(a.user_email)}</small>` : ''}</td>
        <td><code>${esc(a.action)}</code></td>
        <td>${esc(a.entity)}${a.entity_id ? ` <small>${esc(a.entity_id)}</small>` : ''}</td>
        <td><small>${esc(a.ip || '')}</small></td>
      </tr>`).join('')) : empty('Nothing recorded yet.')) + pager('audit', total);
  },
};

/* -------------------------------------------------------------- content */

// portfolio, testimonials, FAQs and articles are the same table-plus-editor
// pattern, so they share one description and one implementation. `fields`
// drives both the table columns and the editor form.
const CONTENT_TYPES = {
  portfolio: {
    title: 'Portfolio', noun: 'project',
    empty: 'No projects published yet. Anything added here appears in the Selected work section.',
    fields: [
      { name: 'title', label: 'Project title', required: true, inTable: true },
      { name: 'client', label: 'Client', inTable: true },
      { name: 'category', label: 'Category', required: true, inTable: true,
        options: ['Books', 'Corporate', 'Educational', 'Branding'] },
      { name: 'description', label: 'Description', type: 'textarea', required: true },
      { name: 'completion_date', label: 'Completed', type: 'date' },
      { name: 'outcome', label: 'Outcome', type: 'textarea' },
      { name: 'featured', label: 'Feature first', type: 'checkbox', inTable: true },
    ],
  },
  testimonials: {
    title: 'Testimonials', noun: 'testimonial',
    empty: 'No testimonials yet. Only published ones appear on the homepage.',
    fields: [
      { name: 'client_name', label: 'Client name', required: true, inTable: true },
      { name: 'organisation', label: 'Organisation', inTable: true },
      { name: 'testimonial', label: 'What they said', type: 'textarea', required: true },
      { name: 'rating', label: 'Rating (1–5)', type: 'number', min: 1, max: 5, inTable: true },
      { name: 'published', label: 'Published', type: 'checkbox', inTable: true },
    ],
  },
  faqs: {
    title: 'FAQs', noun: 'question',
    empty: 'No questions yet.',
    fields: [
      { name: 'question', label: 'Question', required: true, inTable: true },
      { name: 'answer', label: 'Answer', type: 'textarea', required: true },
      { name: 'category', label: 'Group', inTable: true },
      { name: 'sort_order', label: 'Order', type: 'number', inTable: true },
      { name: 'published', label: 'Published', type: 'checkbox', inTable: true },
    ],
  },
  blog: {
    title: 'Articles', noun: 'article',
    empty: 'No articles yet. Drafts stay private until you publish them.',
    fields: [
      { name: 'title', label: 'Title', required: true, inTable: true },
      { name: 'excerpt', label: 'Excerpt', type: 'textarea', required: true },
      { name: 'content', label: 'Article', type: 'textarea', rows: 10, required: true },
      { name: 'status', label: 'Status', options: ['draft', 'published'], inTable: true },
    ],
  },
};

const cell = (item, field) => {
  const value = item[field.name];
  if (field.type === 'checkbox') return value ? 'Yes' : 'No';
  return esc(value ?? '—');
};

async function contentTab(panel, type) {
  const spec = CONTENT_TYPES[type];
  const canEdit = ['super_admin', 'admin'].includes(me?.role);
  const { total, items } = await api(`/api/admin/content/${type}?limit=${PAGE}&offset=${offsets[type] || 0}`);
  const columns = spec.fields.filter((f) => f.inTable);

  panel.innerHTML = `
    <div class="content-head">
      <h2>${esc(spec.title)}</h2>
      ${canEdit ? `<button type="button" class="btn small" data-new>Add ${esc(spec.noun)}</button>` : ''}
    </div>
    ${items.length
      ? table([...columns.map((f) => f.label), canEdit ? 'Actions' : ''].filter(Boolean),
          items.map((item) => `<tr>
            ${columns.map((f) => `<td>${cell(item, f)}</td>`).join('')}
            ${canEdit ? `<td class="row-actions">
              <button type="button" class="btn ghost small" data-edit="${esc(item.id)}">Edit</button>
              <button type="button" class="btn ghost small danger" data-delete="${esc(item.id)}">Delete</button>
              <small class="row-status" role="status"></small>
            </td>` : ''}
          </tr>`).join(''))
      : empty(spec.empty)}
    ${pager(type, total)}`;

  if (!canEdit) return;
  panel.querySelector('[data-new]')?.addEventListener('click', () => openEditor(type, null));
  panel.querySelectorAll('[data-edit]').forEach((b) =>
    b.addEventListener('click', () => openEditor(type, items.find((i) => String(i.id) === b.dataset.edit))));
  panel.querySelectorAll('[data-delete]').forEach((b) =>
    b.addEventListener('click', async () => {
      if (!confirm(`Delete this ${spec.noun}? This cannot be undone.`)) return;
      const note = b.parentElement.querySelector('.row-status');
      note.textContent = 'Deleting…';
      note.className = 'row-status';
      try {
        await api(`/api/admin/content/${type}/${b.dataset.delete}`, { method: 'DELETE' });
        await selectTab(type);
      } catch (err) {
        note.textContent = err.message;
        note.className = 'row-status err';
      }
    }));
}

const editorModal = $('#editorModal');
editorModal.querySelector('.close').addEventListener('click', () => editorModal.close());
editorModal.addEventListener('click', (e) => { if (e.target === editorModal) editorModal.close(); });

function editorField(field, item) {
  const value = item?.[field.name] ?? '';
  const required = field.required ? ' required' : '';
  if (field.type === 'checkbox') {
    return `<label class="check"><input type="checkbox" name="${esc(field.name)}"${value ? ' checked' : ''}> ${esc(field.label)}</label>`;
  }
  if (field.options) {
    return `<label>${esc(field.label)}<select name="${esc(field.name)}"${required}>${
      field.options.map((o) => `<option${String(value) === o ? ' selected' : ''}>${esc(o)}</option>`).join('')
    }</select></label>`;
  }
  if (field.type === 'textarea') {
    return `<label>${esc(field.label)}<textarea name="${esc(field.name)}" rows="${field.rows || 4}"${required}>${esc(value)}</textarea></label>`;
  }
  const extra = [field.min != null ? `min="${field.min}"` : '', field.max != null ? `max="${field.max}"` : ''].join(' ');
  return `<label>${esc(field.label)}<input type="${field.type || 'text'}" name="${esc(field.name)}" value="${esc(value)}" ${extra}${required}></label>`;
}

function openEditor(type, item) {
  const spec = CONTENT_TYPES[type];
  $('#editorTitle').textContent = `${item ? 'Edit' : 'New'} ${spec.noun}`;
  $('#editorFields').innerHTML = spec.fields.map((f) => editorField(f, item)).join('');
  const form = $('#editorForm');
  setStatus(form, '');
  editorModal.showModal();

  form.onsubmit = async (e) => {
    e.preventDefault();
    if (!form.reportValidity()) return;
    const body = {};
    for (const field of spec.fields) {
      const input = form.elements[field.name];
      if (!input) continue;
      if (field.type === 'checkbox') body[field.name] = input.checked;
      else if (input.value !== '') body[field.name] = input.value;
    }
    const url = item ? `/api/admin/content/${type}/${item.id}` : `/api/admin/content/${type}`;
    const res = await submitForm(form, () => (item ? patchJson(url, body) : postJson(url, body)), 'Saving…');
    if (!res) return;
    editorModal.close();
    await selectTab(type);
  };
}

/* ------------------------------------------------------ row interactions */

// Every status dropdown behaves the same: save on change, report the outcome
// inline, and roll back if the server refused.
function bindStatusSelects(panel, urlFor, after) {
  panel.querySelectorAll('[data-status]').forEach((el) => {
    const note = el.parentElement.querySelector('.row-status');
    let previous = el.value;
    el.addEventListener('change', async () => {
      el.disabled = true;
      note.textContent = 'Saving…';
      note.className = 'row-status';
      try {
        await patchJson(urlFor(el.dataset.status), { status: el.value });
        previous = el.value;
        note.textContent = 'Saved';
        note.className = 'row-status ok';
        el.closest('tr')?.classList.toggle('unread', el.value === 'Unread');
        await after?.();
      } catch (err) {
        el.value = previous;
        note.textContent = err.message;
        note.className = 'row-status err';
      } finally {
        el.disabled = false;
      }
    });
  });
}

function bindServiceActions(panel) {
  const form = $('#serviceForm', panel);
  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!form.reportValidity()) return;
    const body = { ...formData(form), featured: form.featured.checked };
    const res = await submitForm(form, () => postJson('/api/admin/services', body), 'Adding service…');
    if (!res) return;
    await selectTab('services');
    setStatus($('#serviceForm'), 'Service added.');
  });

  panel.querySelectorAll('[data-service-edit]').forEach((b) =>
    b.addEventListener('click', () => editService(b)));

  panel.querySelectorAll('[data-service-delete]').forEach((b) =>
    b.addEventListener('click', async () => {
      const service = services.find((s) => String(s.id) === b.dataset.serviceDelete);
      if (!confirm(`Delete "${service?.name}"? Its page at /services/${service?.slug} will stop working.`)) return;
      const note = b.parentElement.querySelector('.row-status');
      note.textContent = 'Deleting…';
      note.className = 'row-status';
      try {
        await api('/api/admin/services/' + b.dataset.serviceDelete, { method: 'DELETE' });
        await selectTab('services');
      } catch (err) {
        note.textContent = err.message;
        note.className = 'row-status err';
      }
    }));
}

// Editing happens in the row itself rather than in yet another dialog.
function editService(button) {
  const service = services.find((s) => String(s.id) === button.dataset.serviceEdit);
  if (!service) return;
  const row = button.closest('tr');
  row.innerHTML = `
    <td><input value="${esc(service.name)}" data-field="name" aria-label="Name"></td>
    <td><input value="${esc(service.summary)}" data-field="summary" aria-label="Summary"></td>
    <td><label class="check"><input type="checkbox" data-field="featured"${service.featured ? ' checked' : ''} aria-label="Featured"></label></td>
    <td class="row-actions">
      <button type="button" class="btn small" data-save>Save</button>
      <button type="button" class="btn ghost small" data-cancel>Cancel</button>
      <small class="row-status" role="status"></small>
    </td>`;

  const note = row.querySelector('.row-status');
  row.querySelector('[data-cancel]').addEventListener('click', () => selectTab('services'));
  row.querySelector('[data-save]').addEventListener('click', async () => {
    const body = {};
    row.querySelectorAll('[data-field]').forEach((f) => {
      body[f.dataset.field] = f.type === 'checkbox' ? f.checked : f.value;
    });
    note.textContent = 'Saving…';
    note.className = 'row-status';
    try {
      await patchJson('/api/admin/services/' + service.id, body);
      await selectTab('services');
    } catch (err) {
      note.textContent = err.message;
      note.className = 'row-status err';
    }
  });
}

/* -------------------------------------------------------- quote detail */

const quoteModal = $('#quoteModal');
quoteModal.querySelector('.close').addEventListener('click', () => quoteModal.close());
quoteModal.addEventListener('click', (e) => { if (e.target === quoteModal) quoteModal.close(); });

async function openQuote(id) {
  const detail = $('#quoteDetail');
  detail.innerHTML = '<p class="loading">Loading…</p>';
  quoteModal.showModal();
  let q;
  try {
    q = await api('/api/admin/quotes/' + id);
  } catch (err) {
    detail.innerHTML = `<p class="form-status err">${esc(err.message)}</p>`;
    return;
  }

  $('#quoteModalTitle').textContent = `${q.reference} · ${q.project_title}`;
  const row = (term, value) => (value ? `<div><dt>${esc(term)}</dt><dd>${esc(value)}</dd></div>` : '');

  detail.innerHTML = `
    <dl class="detail-grid">
      ${row('Client', q.full_name)}${row('Email', q.email)}${row('Phone', q.phone)}
      ${row('Organisation', q.organisation)}${row('Location', q.location)}
      ${row('Project type', q.project_type)}${row('Service', q.service)}
      ${row('Audience', q.target_audience)}${row('Size', q.page_word_estimate)}
      ${row('Quantity', q.quantity)}${row('Wanted by', q.expected_date)}
      ${row('Budget', q.budget)}${row('Received', dateOnly(q.created_at))}
      ${row('Assigned to', q.assigned_name)}
    </dl>

    <h3>Brief</h3>
    <p class="brief">${esc(q.description)}</p>

    <h3>Attached files</h3>
    ${q.files.length
      ? `<ul class="file-list">${q.files.map((f) => `<li>
          <a href="/api/files/${esc(f.id)}">${esc(f.original_name)}</a>
          <small>${esc(f.mime_type)} · ${esc(kb(f.size))}</small></li>`).join('')}</ul>`
      : '<p class="muted">No files were attached.</p>'}

    <form id="quoteNotesForm">
      <label>Internal notes<textarea name="admin_notes" rows="4"
        placeholder="Visible to staff only.">${esc(q.admin_notes || '')}</textarea></label>
      <button class="btn" type="submit">Save notes</button>
      <p class="form-status" role="status"></p>
    </form>`;

  const notes = $('#quoteNotesForm');
  notes.addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await submitForm(notes,
      () => patchJson('/api/admin/quotes/' + q.id, { status: q.status, admin_notes: notes.admin_notes.value }),
      'Saving notes…');
    if (res) setStatus(notes, 'Notes saved.');
  });
}

/* ------------------------------------------------- two-factor enrolment */

function renderTwoFactorArea(status) {
  const area = $('#twoFactorArea');

  if (!status.enabled) {
    area.innerHTML = '<button type="button" class="btn" id="startTwoFactor">Set up two-step verification</button>';
    $('#startTwoFactor').addEventListener('click', startTwoFactorSetup);
    return;
  }

  area.innerHTML = `
    <p class="field-help">${status.recoveryCodesLeft} recovery code${status.recoveryCodesLeft === 1 ? '' : 's'} remaining.</p>
    <form id="recoveryForm" class="inline-form">
      <label>Password<input type="password" name="password" autocomplete="current-password" required></label>
      <button class="btn ghost" type="submit">Generate new recovery codes</button>
      <p class="form-status" role="status"></p>
    </form>
    <details class="danger-zone">
      <summary>Turn off two-step verification</summary>
      <form id="disableForm" class="inline-form">
        <label>Password<input type="password" name="password" autocomplete="current-password" required></label>
        <label>Current code<input name="code" inputmode="numeric" autocomplete="one-time-code" required></label>
        <button class="btn ghost danger" type="submit">Turn off</button>
        <p class="form-status" role="status"></p>
      </form>
    </details>`;

  const recovery = $('#recoveryForm');
  recovery.addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await submitForm(recovery,
      () => postJson('/api/auth/2fa/recovery-codes', { password: recovery.password.value }), 'Generating…');
    if (!res) return;
    recovery.reset();
    showRecoveryCodes(res.recoveryCodes, 'New recovery codes');
  });

  const disable = $('#disableForm');
  disable.addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await submitForm(disable,
      () => postJson('/api/auth/2fa/disable', { password: disable.password.value, code: disable.code.value }),
      'Turning off…');
    if (res) selectTab('security');
  });

  enhancePasswords(area);
}

async function startTwoFactorSetup() {
  const area = $('#twoFactorArea');
  area.innerHTML = '<p class="loading">Preparing…</p>';
  let setup;
  try {
    setup = await postJson('/api/auth/2fa/setup', {});
  } catch (err) {
    area.innerHTML = `<p class="form-status err">${esc(err.message)}</p>`;
    return;
  }

  area.innerHTML = `
    <ol class="setup-steps">
      <li>Scan this with Google Authenticator, 1Password, Authy or similar.
        <div class="qr">${setup.qr}</div>
        <p class="field-help">Cannot scan? Enter this key by hand:
          <code class="setup-key">${esc(setup.secret)}</code></p>
      </li>
      <li>
        <form id="confirmTwoFactor" class="inline-form">
          <label>Enter the six-digit code it shows<input name="code" inputmode="numeric"
            autocomplete="one-time-code" placeholder="123456" required></label>
          <button class="btn" type="submit">Confirm and turn on</button>
          <p class="form-status" role="status"></p>
        </form>
      </li>
    </ol>`;

  const form = $('#confirmTwoFactor');
  form.code.focus();
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await submitForm(form, () => postJson('/api/auth/2fa/enable', { code: form.code.value }),
      'Checking the code…');
    if (!res) {
      form.code.select();
      return;
    }
    showRecoveryCodes(res.recoveryCodes, 'Two-step verification is on');
  });
}

// Recovery codes are shown once and never again, so this is deliberately
// interruptive and offers a copy that does not rely on a download.
function showRecoveryCodes(codes, heading) {
  const area = $('#twoFactorArea');
  area.innerHTML = `
    <div class="recovery">
      <h3>${esc(heading)}</h3>
      <p class="field-help"><b>Save these now.</b> Each one signs you in once if you lose your phone.
        They will not be shown again.</p>
      <ul class="recovery-codes">${codes.map((c) => `<li><code>${esc(c)}</code></li>`).join('')}</ul>
      <div class="form-row">
        <button type="button" class="btn ghost small" id="copyCodes">Copy codes</button>
        <button type="button" class="btn small" id="codesSaved">I have saved them</button>
      </div>
      <p class="form-status" role="status" id="copyStatus"></p>
    </div>`;

  $('#copyCodes').addEventListener('click', async () => {
    const note = $('#copyStatus');
    try {
      await navigator.clipboard.writeText(codes.join('\n'));
      note.textContent = 'Copied to the clipboard.';
      note.className = 'form-status ok';
    } catch {
      note.textContent = 'Copying was blocked — select and copy them by hand.';
      note.className = 'form-status err';
    }
  });
  $('#codesSaved').addEventListener('click', () => selectTab('security'));
}

/* --------------------------------------------------------------- tabs */

const tabButtons = () => [...document.querySelectorAll('[data-tab]')].filter((b) => !b.hidden);

async function selectTab(name) {
  const panel = $('#panel');
  tabButtons().forEach((b) => {
    const on = b.dataset.tab === name;
    b.className = 'btn' + (on ? '' : ' ghost');
    b.setAttribute('aria-selected', String(on));
    b.tabIndex = on ? 0 : -1;
  });
  panel.setAttribute('aria-labelledby', 'tab-' + name);
  panel.innerHTML = '<p class="loading">Loading…</p>';
  try {
    await TABS[name](panel);
  } catch (err) {
    panel.innerHTML = `<p class="form-status err">${esc(err.message)}</p>`;
  }
  panel.querySelectorAll('[data-page]').forEach((b) =>
    b.addEventListener('click', () => {
      offsets[name] = Math.max(0, offsets[name] + (b.dataset.page === 'next' ? PAGE : -PAGE));
      selectTab(name);
    }));
}

// Arrow-key navigation, which is what a tablist is expected to support.
$('.tabs').addEventListener('keydown', (e) => {
  const moves = { ArrowRight: 1, ArrowLeft: -1, Home: 'first', End: 'last' };
  if (!(e.key in moves)) return;
  const buttons = tabButtons();
  const current = buttons.findIndex((b) => b.getAttribute('aria-selected') === 'true');
  const next = moves[e.key] === 'first' ? 0
    : moves[e.key] === 'last' ? buttons.length - 1
    : (current + moves[e.key] + buttons.length) % buttons.length;
  e.preventDefault();
  buttons[next].focus();
  selectTab(buttons[next].dataset.tab);
});

document.querySelectorAll('[data-tab]').forEach((b) =>
  b.addEventListener('click', () => selectTab(b.dataset.tab)));

$('#logout').addEventListener('click', () => {
  logout().catch(() => {}).finally(() => location.reload());
});

/* --------------------------------------------------------------- start */

enhancePasswords(document);
initThemeToggle();
revealGoogleSignIn();

if (me && isStaff(me.role)) {
  enterDashboard(me).catch((err) => console.error(err));
} else {
  // The server rendered the signed-out state; confirm it, in case the session
  // was established in another tab while this page sat open.
  getSession()
    .then(({ user }) => { if (user && isStaff(user.role)) enterDashboard(user); })
    .catch(() => {});
}
