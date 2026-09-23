import {
  esc, api, postJson, getSession, logout, isStaff, homeFor,
  formData, bootstrap, setStatus, submitForm, initThemeToggle,
} from '/shared.js';
import { enhancePhoneFields, enhanceEmailFields, setDynamicDateTime } from '/phone.js';

// Services, FAQs and settings are rendered into the page by the server, so
// there is nothing to fetch on load. This is the same data again as JSON, for
// the one part that stays interactive: the service detail dialog.
const data = bootstrap() || {};
const services = data.services || [];

/* ---------------------------------------------------------------- dialogs */

// Native <dialog> gives us the focus trap, the backdrop, Escape-to-close and
// focus restoration that the old hand-rolled modals never had.
function bindDialog(d) {
  if (!d) return;
  d.querySelector('.close')?.addEventListener('click', () => d.close());
  // The dialog element is the padded area around the card; clicking it is a
  // click on the backdrop.
  d.addEventListener('click', (e) => {
    if (e.target === d) d.close();
  });
}

function openDialog(id) {
  const d = document.querySelector('#' + id);
  if (d && !d.open) d.showModal();
  return d;
}

/* ------------------------------------------------------------------- nav */

function bindNav() {
  const toggle = document.querySelector('.menu');
  const links = document.querySelector('#navlinks');
  if (!toggle || !links) return;

  const setOpen = (open) => {
    links.classList.toggle('open', open);
    toggle.setAttribute('aria-expanded', String(open));
  };

  toggle.addEventListener('click', () => setOpen(!links.classList.contains('open')));
  // Every link is a same-page jump, so the menu has to get out of the way.
  links.querySelectorAll('a').forEach((a) => a.addEventListener('click', () => setOpen(false)));
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && links.classList.contains('open')) {
      setOpen(false);
      toggle.focus();
    }
  });
}

/* -------------------------------------------------------------- auth nav */

async function renderAuthNav() {
  const nav = document.querySelector('#authNav');
  if (!nav) return;
  let user = null;
  try {
    user = (await getSession()).user;
  } catch {
    // Signed-out visitors and a failed session lookup look the same here, and
    // the sign-in buttons are the right fallback for both.
  }
  // Signing in happens on the client portal, which is also where a reset link
  // and a staff redirect land. A second copy in a dialog here would be a
  // separate implementation of the same forms.
  nav.innerHTML = user
    ? `<a class="btn ghost small" href="${homeFor(user)}">${isStaff(user.role) ? 'Dashboard' : 'My projects'}</a>
       <button class="btn ghost small" data-auth="signout">Sign out</button>`
    : `<a class="btn ghost small" href="/portal">Sign in</a>
       <a class="btn small" href="/portal?new=1">Create account</a>`;
  nav.hidden = false;
  nav.querySelectorAll('[data-auth="signout"]').forEach((b) => {
    b.addEventListener('click', () => logout().catch(() => {}).finally(() => location.reload()));
  });

  // A phone-width bar fits the wordmark, the theme toggle and the menu button
  // and no more: leaving these here pushed the menu button off the screen
  // entirely. The same element moves into the drawer rather than being drawn
  // twice, so the signed-in and signed-out states stay in one place.
  const narrow = matchMedia('(max-width: 700px)');
  const place = () => {
    const drawer = document.querySelector('#navlinks');
    const menu = document.querySelector('.nav-actions .menu');
    if (!drawer || !menu) return;
    if (narrow.matches) drawer.append(nav);
    else menu.before(nav);
  };
  place();
  narrow.addEventListener('change', place);
}

/* --------------------------------------------------------------- services */

function bindServices() {
  const d = document.querySelector('#serviceModal');
  bindDialog(d);
  if (!d) return;

  // The cards link to the real /services/<slug> page, which is what crawlers
  // and no-JS visitors follow. With scripting on, the dialog is quicker.
  document.querySelectorAll('[data-service]').forEach((link) =>
    link.addEventListener('click', (e) => {
      const s = services.find((x) => String(x.id) === link.dataset.service);
      if (!s) return; // no bootstrap data: let the link navigate
      e.preventDefault();
      showService(d, s);
    }));
}

// The dialog explains what the service involves and stops there: no call to
// action and no link onward. The quote form is a scroll away on the same page,
// and /services/<slug> is still where the card's own href goes without script.
function showService(d, s) {
  const list = (items) => (items || []).map((x) => `<li>${esc(x)}</li>`).join('');
  d.querySelector('#serviceModalTitle').textContent = s.name;
  d.querySelector('#serviceDetail').innerHTML = `
    <p class="lead">${esc(s.description)}</p>
    <h3>Benefits</h3><ul>${list(s.benefits)}</ul>
    <h3>Process</h3><ol>${list(s.process)}</ol>
    <h3>Deliverables</h3><ul>${list(s.deliverables)}</ul>`;
  d.showModal();
}

/* ----------------------------------------------------------------- search */

function bindSearch() {
  const d = document.querySelector('#searchModal');
  const input = document.querySelector('#searchInput');
  const results = document.querySelector('#searchResults');
  bindDialog(d);
  if (!d || !input || !results) return;

  document.querySelector('.search-open')?.addEventListener('click', () => {
    input.value = '';
    results.innerHTML = '';
    d.showModal();
    input.focus();
  });

  let timer;
  let seq = 0;
  input.addEventListener('input', () => {
    clearTimeout(timer);
    const term = input.value.trim();
    if (term.length < 2) {
      results.innerHTML = '';
      return;
    }
    timer = setTimeout(async () => {
      const mine = ++seq;
      try {
        const found = await api('/api/search?q=' + encodeURIComponent(term));
        if (mine !== seq) return; // a newer keystroke already went out
        const items = Object.entries(found).flatMap(([type, list]) =>
          list.map((x) => `<div class="search-item"><small>${esc(type)}</small>
            <h3>${esc(x.name || x.title || x.question)}</h3>
            <p>${esc(x.summary || x.description || x.excerpt || x.answer)}</p></div>`));
        results.innerHTML = items.length
          ? `<p class="search-count">${items.length} result${items.length === 1 ? '' : 's'}</p>${items.join('')}`
          : '<p class="search-count">No results found.</p>';
      } catch (err) {
        if (mine !== seq) return;
        results.innerHTML = `<p class="search-count err">${esc(err.message)}</p>`;
      }
    }, 250);
  });
}

/* ------------------------------------------------------------------ forms */

function bindQuoteForm() {
  const q = document.querySelector('#quoteForm');
  if (!q) return;
  // Without this class every step is visible and the form posts natively, so
  // the quote request still works with scripting turned off.
  q.classList.add('stepped');
  const steps = [...q.querySelectorAll('.form-step')];
  const crumbs = [...document.querySelectorAll('.mini-process li')];
  let step = 1;

  const fieldsIn = (el) => [...el.querySelectorAll('input,select,textarea')];

  const draw = () => {
    steps.forEach((x) => x.classList.toggle('active', +x.dataset.step === step));
    q.querySelector('.prev').hidden = step === 1;
    q.querySelector('.next').hidden = step === steps.length;
    q.querySelector('.submit').hidden = step !== steps.length;
    crumbs.forEach((x, i) => {
      x.classList.toggle('on', i + 1 === step);
      x.setAttribute('aria-current', i + 1 === step ? 'step' : 'false');
    });
  };

  q.querySelector('.next').addEventListener('click', () => {
    const active = steps.find((x) => +x.dataset.step === step);
    if (fieldsIn(active).every((f) => f.reportValidity())) {
      step++;
      draw();
    }
  });
  q.querySelector('.prev').addEventListener('click', () => {
    step--;
    draw();
  });

  q.addEventListener('submit', async (e) => {
    e.preventDefault();
    // reportValidity() on the whole form would try to focus fields inside the
    // display:none steps, which browsers refuse to do — it just aborts the
    // submit with a console warning. Find the bad step and go back to it.
    const bad = steps.find((el) => !fieldsIn(el).every((f) => f.checkValidity()));
    if (bad) {
      step = +bad.dataset.step;
      draw();
      fieldsIn(bad).some((f) => !f.reportValidity());
      return;
    }
    const res = await submitForm(q, () => api('/api/quotes', { method: 'POST', body: new FormData(q) }),
      'Submitting securely…');
    if (!res) return;
    q.reset();
    step = 1;
    draw();
    setStatus(q, `Thank you. Your request reference is ${res.reference}. Please keep it for follow-up.`);
  });

  draw();
}

function bindSimpleForms() {
  const forms = [
    ['contactForm', '/api/contact', 'Message received. Our team will respond using your contact details.'],
    ['appointmentForm', '/api/appointments', 'Consultation request received. We will confirm the slot with you.'],
  ];
  for (const [id, url, success] of forms) {
    const form = document.querySelector('#' + id);
    if (!form) continue;
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!form.reportValidity()) return;
      const res = await submitForm(form, () => postJson(url, formData(form)));
      if (!res) return;
      form.reset();
      setStatus(form, res.reference ? `${success} Reference: ${res.reference}` : success);
    });
  }
}

/* ------------------------------------------------------------------- init */

// Each binding is independent: one failure must not leave the quote form dead.
for (const bind of [initThemeToggle, bindNav, bindServices, bindSearch, bindQuoteForm, bindSimpleForms]) {
  try {
    bind();
  } catch (err) {
    console.error(`${bind.name} failed`, err);
  }
}

renderAuthNav().catch((err) => console.error('renderAuthNav failed', err));
enhancePhoneFields();
enhanceEmailFields();
setDynamicDateTime();

const year = document.querySelector('#year');
if (year) year.textContent = new Date().getFullYear();
