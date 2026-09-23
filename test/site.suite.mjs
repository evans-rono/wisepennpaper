import request from 'supertest';
import app from '../backend/server.js';
import db from '../backend/db.js';

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${extra ? ' :: ' + extra : ''}`); }
};

const agent = request.agent(app);

// ---------- homepage server rendering ----------
const home = await agent.get('/');
ok('GET / is 200', home.status === 200, String(home.status));
const h = home.text;
ok('services rendered server-side', h.includes('service-card') && !h.includes('<div class="skeleton">'));
ok('service options rendered into the quote select', /<option value="\d+">/.test(h));
ok('FAQs rendered server-side', h.includes('<details><summary>'));
ok('contact details rendered server-side', h.includes('mailto:') && !h.includes('Loading'));
ok('whatsapp link has a number', /wa\.me\/\d+/.test(h));
ok('canonical uses BASE_URL', h.includes('<link rel="canonical" href="http://localhost:3111/">'));
ok('og:image absolute', h.includes('og:image" content="http://localhost:3111/og-image.png"'));
ok('twitter card present', h.includes('name="twitter:card"'));
ok('JSON-LD has telephone + hours', h.includes('"telephone"') && h.includes('"openingHours"'));
ok('no meta keywords', !h.includes('name="keywords"'));
ok('favicon linked', h.includes('rel="icon" href="/favicon.svg"'));
ok('no statistics band', !h.includes('class="stats"'));
ok('bootstrap json present', h.includes('id="bootstrap"'));
ok('csrf hidden field in all 3 forms', (h.match(/name="_csrf"/g) || []).length === 3);
ok('all ssr slots filled', !h.includes('<!--ssr:'));
ok('noscript present', h.includes('<noscript>'));
// Search and service detail. Signing in lives on /portal only: a second copy
// in a dialog here would be a separate implementation of the same forms.
ok('dialogs are <dialog>', (h.match(/<dialog class="modal"/g) || []).length === 2);
ok('no duplicate auth dialog', !h.includes('id="signinModal"') && !h.includes('id="signupModal"'));
ok('sign in points at the portal', h.includes('id="authNav"'));
ok('no inline style attributes', !/ style="/.test(h));
ok('no selected-work section', !h.includes('id="portfolio"') && !h.includes('data-filter'));
ok('no client-voices section', !h.includes('id="testimonials"') && !h.includes('Client voices'));

ok('no public link to the staff entrance', !h.includes('href="/admin"'));
ok('the privacy notice is linked', h.includes('href="/privacy"'));
ok('the consent checkbox points at it', /name="consent"[\s\S]{0,220}href="\/privacy"/.test(h));
ok('every public form carries a honeypot', (h.match(/name="wpnp_check"/g) || []).length === 3);
// The honeypot alone must not be named anything a browser or password manager
// fills by itself — a filled one silently discards the enquiry. Visible fields
// like "organisation" are supposed to autofill, so only the trap is checked.
const honeypotNames = [...h.matchAll(/<div class="hp"[\s\S]*?name="([^"]+)"/g)].map((m) => m[1]);
ok('the honeypot name means nothing to autofill',
  honeypotNames.length === 3 && honeypotNames.every((n) =>
    !/^(website|url|company|organization|organisation|fax|nickname|username|name|email|tel|phone)$/.test(n)),
  honeypotNames.join(', '));

// ---------- privacy notice ----------
const privacy = await agent.get('/privacy');
ok('GET /privacy is 200', privacy.status === 200, String(privacy.status));
ok('privacy slots filled', !privacy.text.includes('<!--ssr:'));
ok('privacy names the Act', privacy.text.includes('Data Protection Act'));
ok('privacy carries the real contact address', privacy.text.includes('mailto:'));
ok('privacy is canonical and indexable',
  privacy.text.includes('/privacy"') && !privacy.text.includes('noindex'));
ok('sitemap lists the privacy notice', (await agent.get('/sitemap.xml')).text.includes('/privacy'));
// A nine-section notice is three screens long; the contents list uses the
// margin the reading measure deliberately leaves rather than widening the prose.
const headingIds = [...privacy.text.matchAll(/<h2 id="([a-z0-9-]+)"/g)].map((m) => m[1]);
const tocLinks = [...privacy.text.matchAll(/<li><a href="#([a-z0-9-]+)">/g)].map((m) => m[1]);
ok('every privacy section has an id', headingIds.length === 9, String(headingIds.length));
ok('the contents list covers all of them',
  tocLinks.length === headingIds.length && tocLinks.every((id, i) => id === headingIds[i]),
  `${tocLinks.length} links vs ${headingIds.length} headings`);
ok('the prose and the contents list are siblings, not nested',
  privacy.text.includes('<div class="text-layout">'));

// ---------- service pages ----------
const slug = (await agent.get('/api/services')).body[0].slug;
const svc = await agent.get('/services/' + slug);
ok('GET /services/:slug is 200', svc.status === 200, String(svc.status));
ok('service page has h1 + canonical', svc.text.includes('<h1>') && svc.text.includes('/services/' + slug + '"'));
ok('service page has Service JSON-LD', svc.text.includes('"@type":"Service"'));
ok('service page has breadcrumbs', svc.text.includes('BreadcrumbList'));
ok('service page slots filled', !svc.text.includes('<!--ssr:'));
ok('unknown service is 404', (await agent.get('/services/does-not-exist')).status === 404);

// ---------- 404 handling ----------
const notFound = await agent.get('/totally-made-up');
ok('unknown path is 404 not 200', notFound.status === 404, String(notFound.status));
ok('404 page is noindex', notFound.text.includes('noindex'));
ok('/index.html is not served raw', (await agent.get('/index.html')).status === 404);
ok('/page.html is not served raw', (await agent.get('/page.html')).status === 404);
ok('/api/nope is 404', (await agent.get('/api/nope')).status === 404);
ok('/favicon.ico redirects', (await agent.get('/favicon.ico')).status === 301);
ok('/favicon.svg served', (await agent.get('/favicon.svg')).status === 200);
ok('/og-image.png served', (await agent.get('/og-image.png')).status === 200);
ok('/apple-touch-icon.png served', (await agent.get('/apple-touch-icon.png')).status === 200);
ok('/dashboard.css served', (await agent.get('/dashboard.css')).status === 200);

// ---------- sitemap / robots ----------
const sm = await agent.get('/sitemap.xml');
ok('sitemap lists service URLs', sm.text.includes('/services/' + slug));
ok('sitemap has no hash fragments', !sm.text.includes('/#'));
ok('robots disallows thank-you', (await agent.get('/robots.txt')).text.includes('Disallow: /thank-you'));

// ---------- caching + CSP ----------
const css = await agent.get('/styles.css');
ok('css revalidates', css.headers['cache-control'] === 'no-cache', css.headers['cache-control']);
const png = await agent.get('/og-image.png');
ok('png immutable', (png.headers['cache-control'] || '').includes('immutable'), png.headers['cache-control']);
const csp = home.headers['content-security-policy'] || '';
ok('CSP has no unsafe-inline', !csp.includes('unsafe-inline'), csp);
ok('CSP img-src drops https:', /img-src 'self' data:/.test(csp), csp);
ok('CSP has frame-ancestors none', csp.includes("frame-ancestors 'none'"), csp);

// ---------- csrf + JSON forms ----------
const token = (await agent.get('/api/csrf')).body.csrfToken;
const contact = await agent.post('/api/contact').set('CSRF-Token', token).send({
  name: 'Test Person', email: 't@example.com', subject: 'Hello there', message: 'This is a test message body.',
});
ok('JSON contact post succeeds', contact.status === 201, JSON.stringify(contact.body));
const noToken = await request(app).post('/api/contact')
  .send({ name: 'xx', email: 'a@b.co', subject: 'yyy', message: 'zzzzzzzzzzzz' });
ok('contact without csrf is rejected', noToken.status === 403, String(noToken.status));
// Named so the browser can tell a stale token from "you may not do that", fetch
// a fresh one and retry — otherwise the first click of a long-open page fails
// and only the second works, which is what a sign-out button pressed twice is.
ok('a rejected token says why, in a form script can act on',
  noToken.body.code === 'EBADCSRFTOKEN', JSON.stringify(noToken.body));
const wrongToken = await agent.post('/api/contact').set('CSRF-Token', 'not-a-real-token')
  .send({ name: 'xx', email: 'a@b.co', subject: 'yyy', message: 'zzzzzzzzzzzz' });
ok('so does a malformed one', wrongToken.status === 403 && wrongToken.body.code === 'EBADCSRFTOKEN',
  `${wrongToken.status} ${JSON.stringify(wrongToken.body)}`);
ok('an ordinary refusal is not labelled as a token problem',
  !(await request(app).get('/api/admin/dashboard')).body.code);

// ---------- honeypot ----------
// A bot fills every field it finds, including the one placed off-screen. The
// response has to look like success, or whoever wrote the script simply learns
// which field to skip.
const before = db.prepare("SELECT COUNT(*) n FROM contact_messages").get().n;
const hpToken = (await agent.get('/api/csrf')).body.csrfToken;
const trap = await agent.post('/api/contact').set('CSRF-Token', hpToken).send({
  name: 'Spam Bot', email: 'bot@example.com', subject: 'Cheap offers',
  message: 'A message body long enough to pass validation.', wpnp_check: 'http://spam.example',
});
ok('a filled honeypot still answers as success', trap.status === 201, String(trap.status));
ok('but nothing was stored',
  db.prepare("SELECT COUNT(*) n FROM contact_messages").get().n === before);

// ---------- no-JS form post (browser Accept header) ----------
const htmlAgent = request.agent(app);
const formToken = /name="_csrf" value="([^"]+)"/.exec((await htmlAgent.get('/')).text)[1];
const nojs = await htmlAgent.post('/api/appointments')
  .set('Accept', 'text/html,application/xhtml+xml')
  .type('form')
  .send({
    _csrf: formToken, full_name: 'Test Person', email: 't@example.com', phone: '0700000000',
    consultation_type: 'Editorial consultation', preferred_date: '2030-01-01', preferred_time: '10:00',
  });
ok('no-JS appointment redirects to /thank-you',
  nojs.status === 303 && nojs.headers.location === '/thank-you', `${nojs.status} ${nojs.headers.location}`);
const thanks = await htmlAgent.get('/thank-you');
ok('thank-you shows the reference', thanks.status === 200 && /CONS-\d{4}-[0-9A-F]{6}/.test(thanks.text));
ok('thank-you is single-use', (await htmlAgent.get('/thank-you')).status === 303);

// ---------- no-JS multipart quote (csrf runs after multer) ----------
const qAgent = request.agent(app);
const qToken = /name="_csrf" value="([^"]+)"/.exec((await qAgent.get('/')).text)[1];
const quote = await qAgent.post('/api/quotes')
  .set('Accept', 'text/html')
  .field('_csrf', qToken)
  .field('full_name', 'Test Person').field('email', 't@example.com').field('phone', '0700000000')
  .field('project_type', 'Book').field('project_title', 'My Book')
  .field('description', 'A description comfortably over twenty characters long.');
ok('no-JS multipart quote redirects', quote.status === 303, `${quote.status} ${JSON.stringify(quote.body)}`);
ok('quote thank-you has WPNP reference', /WPNP-\d{4}-[0-9A-F]{6}/.test((await qAgent.get('/thank-you')).text));

// ---------- admin notes are no longer wiped ----------
const admin = request.agent(app);
const at = (await admin.get('/api/csrf')).body.csrfToken;
const login = await admin.post('/api/auth/login').set('CSRF-Token', at)
  .send({ email: 'admin@wisepennpaper.co.ke', password: process.env.ADMIN_PASSWORD });
ok('admin login', login.status === 200, JSON.stringify(login.body));
// Admin roles must complete two-step enrolment before the dashboard opens.
const enrolToken = (await admin.get('/api/csrf')).body.csrfToken;
const enrolSetup = await admin.post('/api/auth/2fa/setup').set('CSRF-Token', enrolToken).send({});
const enrolCode = (await import('../backend/totp.js')).generateCode(enrolSetup.body.secret.replace(/\s/g, ''));
await admin.post('/api/auth/2fa/enable').set('CSRF-Token', enrolToken).send({ code: enrolCode });

const at2 = (await admin.get('/api/csrf')).body.csrfToken;
const qid = (await admin.get('/api/admin/dashboard')).body.quotes[0].id;
await admin.patch('/api/admin/quotes/' + qid).set('CSRF-Token', at2)
  .send({ status: 'Contacted', admin_notes: 'Called the client on Tuesday.' });
await admin.patch('/api/admin/quotes/' + qid).set('CSRF-Token', at2).send({ status: 'Approved' });
const after = (await admin.get('/api/admin/dashboard')).body.quotes.find((q) => q.id === qid);
ok('status change preserves admin notes',
  after.admin_notes === 'Called the client on Tuesday.', String(after.admin_notes));
ok('status change applied', after.status === 'Approved', after.status);
ok('unknown quote id is 404',
  (await admin.patch('/api/admin/quotes/999999').set('CSRF-Token', at2).send({ status: 'New' })).status === 404);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
