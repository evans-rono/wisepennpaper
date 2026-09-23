// Server-side rendering for the public pages.
//
// The site used to ship an empty shell and let the browser fetch services,
// FAQs and contact details after load. That made the real content
// invisible to crawlers, put "Loading…" in the first paint, and left the page
// dead without JavaScript. Templates in frontend/ now carry <!--ssr:name--> …
// <!--/ssr:name--> slots that this module fills before the HTML goes out.

import fs from 'node:fs';
import path from 'node:path';
import db from './db.js';

const PUBLIC = path.join(path.resolve('.'), 'frontend');
const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ESCAPES[c]);

// The wordmark used to arrive through <use href="/logo.svg#logo">, a reference
// into a separate file. WebKit has never supported that, so on Safari, iPhone
// and iPad the header had a hole in it where the logo should be. The symbol is
// inlined into every page instead, leaving <use href="#logo"> as a reference
// within the same document, which every browser resolves. The artwork itself
// still lives in exactly one place: frontend/logo.svg, read once from here.
let sprite;
function logoSprite() {
  if (process.env.NODE_ENV === 'production' && sprite !== undefined) return sprite;
  const file = fs.readFileSync(path.join(PUBLIC, 'logo.svg'), 'utf8');
  const symbol = file.match(/<symbol[\s\S]*?<\/symbol>/)?.[0] ?? '';
  sprite = `<svg class="svg-sprite" aria-hidden="true" focusable="false" xmlns="http://www.w3.org/2000/svg">${symbol}</svg>`;
  return sprite;
}

const templates = new Map();
function template(name) {
  // Cached in production, re-read in development so edits show up on refresh.
  if (process.env.NODE_ENV === 'production' && templates.has(name)) return templates.get(name);
  const html = fs.readFileSync(path.join(PUBLIC, name), 'utf8')
    .replace(/<body[^>]*>/, (openTag) => openTag + logoSprite());
  templates.set(name, html);
  return html;
}

// Replaces the body of every matching slot. A slot with no entry in `slots`
// keeps whatever placeholder the template already had.
const fill = (html, slots) =>
  html.replace(/<!--ssr:([a-zA-Z]+)-->[\s\S]*?<!--\/ssr:\1-->/g, (whole, name) =>
    (Object.hasOwn(slots, name) ? slots[name] : whole));

export const baseUrl = (req) =>
  (process.env.BASE_URL || `${req.protocol}://${req.get('host') || 'localhost'}`).replace(/\/+$/, '');

// Escaping "<" is enough to make the payload safe inside <script>: it prevents
// both </script> and <!-- from ever appearing.
const jsonScript = (id, data) =>
  `<script type="application/json" id="${esc(id)}">${JSON.stringify(data).replace(/</g, '\\u003c')}</script>`;

const ldScript = (data) =>
  `<script type="application/ld+json">${JSON.stringify(data).replace(/</g, '\\u003c')}</script>`;

const csrfField = (req) =>
  `<input type="hidden" name="_csrf" value="${esc(typeof req.csrfToken === 'function' ? req.csrfToken() : '')}">`;

const dial = (s) => String(s ?? '').replace(/[^\d+]/g, '');
const list = (items, tag = 'ul') =>
  (items?.length ? `<${tag}>${items.map((x) => `<li>${esc(x)}</li>`).join('')}</${tag}>` : '');

/* ------------------------------------------------------------------- data */

const parseJson = (value, fallback = []) => {
  try {
    return JSON.parse(value ?? '');
  } catch {
    return fallback;
  }
};

const settings = () =>
  Object.fromEntries(db.prepare('SELECT key,value FROM settings').all().map((x) => [x.key, x.value]));

const services = () =>
  db.prepare('SELECT * FROM services ORDER BY sort_order,name').all().map((x) => ({
    ...x,
    benefits: parseJson(x.benefits),
    process: parseJson(x.process),
    deliverables: parseJson(x.deliverables),
    faqs: parseJson(x.faqs),
  }));

export const serviceBySlug = (slug) => {
  const row = db.prepare('SELECT * FROM services WHERE slug=?').get(slug);
  if (!row) return null;
  return {
    ...row,
    benefits: parseJson(row.benefits),
    process: parseJson(row.process),
    deliverables: parseJson(row.deliverables),
    faqs: parseJson(row.faqs),
  };
};

export const serviceSlugs = () => db.prepare('SELECT slug FROM services ORDER BY sort_order,name').all();

/* --------------------------------------------------------------- metadata */

const ORG_NAME = 'The Wise Pen N’ Paper';

function organisation(base, s, serviceNames = []) {
  const ld = {
    '@context': 'https://schema.org',
    '@type': 'ProfessionalService',
    name: s.company_name || ORG_NAME,
    url: base + '/',
    logo: base + '/favicon.svg',
    image: base + '/og-image.png',
    description: s.tagline || 'Publishing, content development and creative services.',
    areaServed: { '@type': 'Country', name: 'Kenya' },
  };
  if (s.phone) ld.telephone = s.phone;
  if (s.email) ld.email = s.email;
  if (s.address) ld.address = { '@type': 'PostalAddress', addressLocality: s.address, addressCountry: 'KE' };
  if (s.hours) ld.openingHours = s.hours;
  if (serviceNames.length) ld.serviceType = serviceNames;
  return ld;
}

// index.html carries its own <title> and og:title; this only adds what depends
// on the deployment URL and the database.
function homeHead(base, s, serviceNames) {
  return [
    `<link rel="canonical" href="${esc(base)}/">`,
    `<meta property="og:url" content="${esc(base)}/">`,
    `<meta property="og:image" content="${esc(base)}/og-image.png">`,
    `<meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">`,
    `<meta property="og:image:alt" content="${esc(ORG_NAME)} — turning ideas into books, brands and stories that matter.">`,
    `<meta name="twitter:image" content="${esc(base)}/og-image.png">`,
    ldScript(organisation(base, s, serviceNames)),
  ].join('\n');
}

// page.html has no static metadata of its own, so this writes the whole head.
function pageHead(base, { title, description, urlPath, robots, jsonLd }) {
  const url = base + urlPath;
  const tags = [
    `<title>${esc(title)}</title>`,
    `<meta name="description" content="${esc(description)}">`,
    `<link rel="canonical" href="${esc(url)}">`,
    `<meta property="og:site_name" content="${esc(ORG_NAME)}">`,
    `<meta property="og:type" content="website">`,
    `<meta property="og:title" content="${esc(title)}">`,
    `<meta property="og:description" content="${esc(description)}">`,
    `<meta property="og:url" content="${esc(url)}">`,
    `<meta property="og:image" content="${esc(base)}/og-image.png">`,
    `<meta property="og:locale" content="en_KE">`,
    `<meta name="twitter:card" content="summary_large_image">`,
    `<meta name="twitter:title" content="${esc(title)}">`,
    `<meta name="twitter:description" content="${esc(description)}">`,
    `<meta name="twitter:image" content="${esc(base)}/og-image.png">`,
  ];
  if (robots) tags.push(`<meta name="robots" content="${esc(robots)}">`);
  if (jsonLd) tags.push(ldScript(jsonLd));
  return tags.join('\n');
}

/* ---------------------------------------------------------------- content */

const SERVICE_ICONS = ['✎', '✓', '▤', '▦', '◈', '▥', '✦', '◎'];


const serviceCards = (rows) =>
  rows.length
    ? rows.map((s, i) => `<article class="service-card">
        <div class="service-icon" aria-hidden="true">${SERVICE_ICONS[i % SERVICE_ICONS.length]}</div>
        <h3>${esc(s.name)}</h3>
        <p>${esc(s.summary)}</p>
        <p><a class="service-more" href="/services/${esc(s.slug)}" data-service="${esc(s.id)}">View service details →</a></p>
      </article>`).join('')
    : '<article class="empty"><h3>Services are being published</h3><p>Our service list will appear here shortly.</p></article>';

const serviceOptions = (rows) =>
  rows.map((s) => `<option value="${esc(s.id)}">${esc(s.name)}</option>`).join('');

// Every section that can come up empty says so the same way: a card, matching
// the services and resources blocks. A bare grey line under a full-width
// heading read like a section that had failed to load.


const faqItems = (rows) =>
  rows.map((f) => `<details><summary>${esc(f.question)}</summary><p>${esc(f.answer)}</p></details>`).join('');

const blogCards = (rows) =>
  rows.length
    ? rows.map((p) => `<article>
        <small>${esc(p.category || 'Resource')}</small>
        <h3>${esc(p.title)}</h3>
        <p>${esc(p.excerpt)}</p>
      </article>`).join('')
    : `<article class="empty"><h3>Publishing resources are coming soon</h3>
       <p>Articles and guidance will appear here shortly.</p></article>`;

const contactBlock = (s) => {
  const rows = [];
  if (s.phone) rows.push(`<p><b>Phone</b><a href="tel:${esc(dial(s.phone))}">${esc(s.phone)}</a></p>`);
  if (s.email) rows.push(`<p><b>Email</b><a href="mailto:${esc(s.email)}">${esc(s.email)}</a></p>`);
  if (s.address) rows.push(`<p><b>Location</b><span>${esc(s.address)}</span></p>`);
  if (s.hours) rows.push(`<p><b>Working hours</b><span>${esc(s.hours)}</span></p>`);
  // A wa.me link with no number is a broken link, so the button only appears
  // once the setting is filled in.
  const whatsapp = s.whatsapp
    ? `<a class="btn whatsapp" href="https://wa.me/${esc(dial(s.whatsapp))}?text=${
        encodeURIComponent('Hello Wise Pen N’ Paper, I would like to discuss a publishing project.')
      }">Chat on WhatsApp</a>`
    : '';
  return `<div class="contact-list">${rows.join('')}</div>${whatsapp}`;
};

/* ------------------------------------------------------------------ pages */

export function renderHome(req) {
  const base = baseUrl(req);
  const s = settings();
  const rows = services();
  const csrf = csrfField(req);

  return fill(template('index.html'), {
    head: homeHead(base, s, rows.map((x) => x.name)),
    services: serviceCards(rows),
    serviceOptions: serviceOptions(rows),
    faqs: faqItems(db.prepare('SELECT * FROM faqs WHERE published=1 ORDER BY sort_order').all()),
    blog: blogCards(db.prepare(`SELECT b.*,c.name category FROM blog_posts b
      LEFT JOIN categories c ON c.id=b.category_id
      WHERE b.status='published' ORDER BY b.published_at DESC`).all()),
    contact: contactBlock(s),
    csrf,
    // Only what stays interactive in the browser: the service detail dialog.
    bootstrap: jsonScript('bootstrap', {
      services: rows.map(({ id, slug, name, summary, description, benefits, process, deliverables }) =>
        ({ id, slug, name, summary, description, benefits, process, deliverables })),
    }),
  });
}

const shell = (req, head, main) => fill(template('page.html'), { head, main });

export function renderService(req, service) {
  const base = baseUrl(req);
  const s = settings();
  const url = `/services/${service.slug}`;
  const description = service.meta_description || service.summary;

  const faqs = service.faqs?.length
    ? `<h2>Common questions</h2>${service.faqs
        .map((f) => `<details><summary>${esc(f.question ?? f.q ?? '')}</summary><p>${esc(f.answer ?? f.a ?? '')}</p></details>`)
        .join('')}`
    : '';

  const jsonLd = {
    '@context': 'https://schema.org',
    '@graph': [
      {
        '@type': 'Service',
        name: service.name,
        description,
        url: base + url,
        serviceType: service.name,
        areaServed: { '@type': 'Country', name: 'Kenya' },
        provider: organisation(base, s),
      },
      {
        '@type': 'BreadcrumbList',
        itemListElement: [
          { '@type': 'ListItem', position: 1, name: 'Home', item: base + '/' },
          { '@type': 'ListItem', position: 2, name: 'Services', item: base + '/#services' },
          { '@type': 'ListItem', position: 3, name: service.name, item: base + url },
        ],
      },
    ],
  };

  const main = `<article class="section text-page">
    <nav class="crumbs" aria-label="Breadcrumb"><a href="/">Home</a> <span aria-hidden="true">›</span>
      <a href="/#services">Services</a> <span aria-hidden="true">›</span> <span>${esc(service.name)}</span></nav>
    <p class="eyebrow">Publishing service</p>
    <h1>${esc(service.name)}</h1>
    <p class="lead">${esc(service.summary)}</p>
    <p>${esc(service.description)}</p>
    ${service.benefits?.length ? `<h2>Benefits</h2>${list(service.benefits)}` : ''}
    ${service.process?.length ? `<h2>How it works</h2>${list(service.process, 'ol')}` : ''}
    ${service.deliverables?.length ? `<h2>What you receive</h2>${list(service.deliverables)}` : ''}
    ${faqs}
    <p class="page-actions"><a class="btn" href="/#quote">Request this service</a>
      <a class="btn ghost" href="/#services">See all services</a></p>
  </article>`;

  return shell(req, pageHead(base, {
    // seo_title is an explicit, complete title when set — appending the brand
    // to it just repeats the name.
    title: service.seo_title || `${service.name} | ${ORG_NAME}`,
    description,
    urlPath: url,
    jsonLd,
  }), main);
}

// The admin shell. The session state is baked into the markup so the page paints
// the right panel immediately instead of flashing the sign-in form at staff who
// are already signed in.
export function renderAdmin(req) {
  const user = req.session?.user ?? null;
  const signedIn = ['super_admin', 'admin', 'staff'].includes(user?.role);
  return fill(template('admin.html'), {
    boot: jsonScript('adminBoot', { user: signedIn ? user : null }),
  }).replace('data-state="signed-out"', `data-state="${signedIn ? 'signed-in' : 'signed-out'}"`);
}

// The portal used to be served as a static file, so a signed-in visitor saw the
// sign-in card until the session lookup came back — a second of the wrong
// screen. Stamping the state server-side paints the right one on the first
// frame, exactly as renderAdmin does.
export function renderPortal(req) {
  const signedIn = Boolean(req.session?.user);
  return template('portal.html')
    .replace('data-portal="signed-out"', `data-portal="${signedIn ? 'signed-in' : 'signed-out'}"`);
}

export const renderReset = () => template('reset.html');

export function renderNotFound(req) {
  const main = `<article class="section text-page">
    <p class="eyebrow">Error 404</p>
    <h1>We could not find that page.</h1>
    <p class="lead">The link may be out of date, or the page may have moved. These are good places to pick up from.</p>
    <p class="page-actions"><a class="btn" href="/">Go to the homepage</a>
      <a class="btn ghost" href="/#services">Browse services</a>
      <a class="btn ghost" href="/#contact">Contact us</a></p>
  </article>`;
  return shell(req, pageHead(baseUrl(req), {
    title: `Page not found | ${ORG_NAME}`,
    description: 'The page you requested could not be found.',
    urlPath: req.originalUrl.split('?')[0],
    robots: 'noindex,follow',
  }), main);
}

// Kenya's Data Protection Act 2019 requires that people are told what is done
// with their data before they consent, and the quote form asks for consent
// against nothing they can read. The contact details come from the settings
// table rather than being written in here, so the notice cannot drift away from
// what the rest of the site says. The retention periods and the controller's
// identity are business decisions: review them, and take legal advice before
// relying on this as your published policy.
export function renderPrivacy(req) {
  const s = settings();
  const contact = [
    s.email && `<a href="mailto:${esc(s.email)}">${esc(s.email)}</a>`,
    s.phone && esc(s.phone),
    s.address && esc(s.address),
  ].filter(Boolean).join(' &middot; ');

  const main = `<div class="text-layout">
    <nav class="page-toc" aria-label="On this page">
      <h2>On this page</h2>
      <ol>
        <li><a href="#who-is-responsible">Who is responsible</a></li>
        <li><a href="#what-we-collect-and-why">What we collect, and why</a></li>
        <li><a href="#manuscripts-and-other-files">Manuscripts and other files</a></li>
        <li><a href="#who-else-sees-it">Who else sees it</a></li>
        <li><a href="#cookies">Cookies</a></li>
        <li><a href="#how-long-we-keep-it">How long we keep it</a></li>
        <li><a href="#your-rights">Your rights</a></li>
        <li><a href="#keeping-it-secure">Keeping it secure</a></li>
        <li><a href="#changes">Changes</a></li>
      </ol>
    </nav>
    <article class="section text-page">
    <p class="eyebrow">Privacy</p>
    <h1>How we handle your information</h1>
    <p class="lead">This notice explains what ${esc(s.company_name || ORG_NAME)} collects when you use this
      website, why we hold it, and what you can ask us to do with it. It is written to meet our obligations
      under Kenya's Data Protection Act, 2019.</p>

    <h2 id="who-is-responsible">Who is responsible</h2>
    <p>${esc(s.company_name || ORG_NAME)} is the data controller for the information described here.
      You can reach us at ${contact || 'the contact details published on this site'}.</p>

    <h2 id="what-we-collect-and-why">What we collect, and why</h2>
    <ul>
      <li><b>Project enquiries.</b> Your name, email address, telephone number, and optionally your
        organisation and location, together with the project details you describe and any manuscript or
        artwork you attach. We use these to assess the work, prepare a quotation and reply to you.</li>
      <li><b>Consultation bookings.</b> Your name, contact details, the type of consultation and your
        preferred date and time, so that we can arrange the appointment.</li>
      <li><b>Messages.</b> Anything you send through the contact form, so that we can answer it.</li>
      <li><b>Accounts.</b> If you create a client account, your name, email address, telephone number and a
        password we never store in readable form. Signed-in clients can also exchange messages with us about
        their project.</li>
      <li><b>Security records.</b> Sign-in times, the IP address a request came from, and the browser
        reported by your device. These let us detect unauthorised access to accounts and are kept separate
        from the project work itself.</li>
    </ul>
    <p>We ask for consent before you submit an enquiry. Where you are already a client, we also rely on the
      performance of our agreement with you, and on our own legal obligations for records such as invoices.</p>

    <h2 id="manuscripts-and-other-files">Manuscripts and other files</h2>
    <p>Work you upload stays private to you and the staff handling your project. Files are stored under
      names generated by our server, outside the publicly reachable part of the site, and are never listed or
      linked publicly. Downloading one requires signing in, and we record who downloaded what and when.</p>

    <h2 id="who-else-sees-it">Who else sees it</h2>
    <p>We do not sell your information, and we do not share it for advertising. This site runs no analytics
      or advertising trackers, and sets no third-party cookies. Information is disclosed only to the people
      working on your project, to service providers who host this site or carry our email, and where the law
      requires it. Typefaces are loaded from Google Fonts, which means your browser contacts Google's servers
      when a page loads.</p>

    <h2 id="cookies">Cookies</h2>
    <p>We use two, both strictly necessary and neither used for tracking: one keeps you signed in, and one
      protects forms against cross-site request forgery. Your choice of light or dark theme is remembered in
      your own browser and never reaches us.</p>

    <h2 id="how-long-we-keep-it">How long we keep it</h2>
    <p>Enquiries and their attachments are kept for as long as we are in discussion with you and for a
      reasonable period afterwards, in case the project resumes. Client project records, invoices and
      quotations are kept for as long as our business and tax obligations require. Security records are kept
      only as long as they are useful for investigating account misuse. You can ask us to delete anything we
      are not legally required to keep.</p>

    <h2 id="your-rights">Your rights</h2>
    <p>Under the Data Protection Act you may ask us for a copy of the information we hold about you, ask us
      to correct anything inaccurate, ask us to delete it, object to a particular use, or withdraw a consent
      you gave earlier. Withdrawing consent does not affect anything done before you withdrew it. Write to us
      using the details above and we will respond within the statutory period. If you are not satisfied with
      our answer, you may complain to the Office of the Data Protection Commissioner.</p>

    <h2 id="keeping-it-secure">Keeping it secure</h2>
    <p>The site is served over HTTPS. Passwords are stored only as irreversible hashes, staff accounts
      require a second factor in addition to a password, uploaded files are checked against their real format
      before being stored, and access to client records is restricted by role and recorded.</p>

    <h2 id="changes">Changes</h2>
    <p>If this notice changes materially we will say so on this page. Please check it when you submit
      something new.</p>

    <p class="page-actions"><a class="btn" href="/">Back to the homepage</a>
      <a class="btn ghost" href="/#contact">Contact us</a></p>
    </article>
  </div>`;

  return shell(req, pageHead(baseUrl(req), {
    title: `Privacy notice | ${ORG_NAME}`,
    description: `How ${ORG_NAME} collects, uses and protects the information you provide through this site.`,
    urlPath: '/privacy',
  }), main);
}

// Where a browser lands after posting a form without JavaScript.
export function renderThanks(req, { heading, message, reference }) {
  const main = `<article class="section text-page">
    <p class="eyebrow">Thank you</p>
    <h1>${esc(heading)}</h1>
    <p class="lead">${esc(message)}</p>
    ${reference ? `<p class="reference">Your reference is <b>${esc(reference)}</b>. Please keep it for follow-up.</p>` : ''}
    <p class="page-actions"><a class="btn" href="/">Back to the homepage</a>
      <a class="btn ghost" href="/portal">Client portal</a></p>
  </article>`;
  return shell(req, pageHead(baseUrl(req), {
    title: `${heading} | ${ORG_NAME}`,
    description: message,
    urlPath: '/thank-you',
    robots: 'noindex,nofollow',
  }), main);
}
