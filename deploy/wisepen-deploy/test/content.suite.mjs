import request from 'supertest';
import app from '../backend/server.js';
import db from '../backend/db.js';
import { generateCode } from '../backend/totp.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => {
  if (c) { pass++; console.log('  PASS  ' + n); }
  else { fail++; console.log('  FAIL  ' + n + (e ? ' :: ' + e : '')); }
};
const agent = () => request.agent(app);
const post = async (a, u, b) => { const t = (await a.get('/api/csrf')).body.csrfToken; return a.post(u).set('CSRF-Token', t).send(b); };
const patch = async (a, u, b) => { const t = (await a.get('/api/csrf')).body.csrfToken; return a.patch(u).set('CSRF-Token', t).send(b); };
const del = async (a, u) => { const t = (await a.get('/api/csrf')).body.csrfToken; return a.delete(u).set('CSRF-Token', t); };

const su = agent();
await post(su, '/api/auth/login', { email: 'admin@wisepennpaper.co.ke', password: 'TestPass-12345!x' });
const setup = await post(su, '/api/auth/2fa/setup', {});
await post(su, '/api/auth/2fa/enable', { code: generateCode(setup.body.secret.replace(/\s/g, '')) });

/* ------------------------------------------------------------- settings */

const before = await su.get('/api/admin/settings');
ok('settings are readable', before.status === 200 && 'phone' in before.body.settings, String(before.status));
ok('settings update', (await patch(su, '/api/admin/settings', { phone: '+254 711 222 333' })).status === 200);
ok('the change is stored', db.prepare("SELECT value v FROM settings WHERE key='phone'").get().v === '+254 711 222 333');
const home1 = await su.get('/');
ok('the new phone number reaches the homepage', home1.text.includes('+254 711 222 333'));
ok('an unknown key is ignored', (await patch(su, '/api/admin/settings', { evil: 'x' })).status === 400);
// The homepage statistics band was removed, and with it these five keys.
ok('a retired statistics key is refused', (await patch(su, '/api/admin/settings', { books_published: '48' })).status === 400);

/* ------------------------------------------------------------ portfolio */
// The public "Selected work" section is gone; projects are still recorded and
// managed here, so the editor behind them is still worth testing.

const proj = await post(su, '/api/admin/content/portfolio', {
  title: 'Voices of the Rift', client: 'Rift Valley Trust', category: 'Books',
  description: 'A 240-page anthology taken from manuscript to print.', featured: true,
});
ok('a portfolio project can be created', proj.status === 201, JSON.stringify(proj.body));
ok('it gets a slug', !!proj.body.item.slug, proj.body.item.slug);

const dup = await post(su, '/api/admin/content/portfolio', {
  title: 'Voices of the Rift', category: 'Books', description: 'A different project that happens to share a name.',
});
ok('a duplicate title gets a distinct slug',
  dup.status === 201 && dup.body.item.slug !== proj.body.item.slug, `${dup.body.item?.slug} vs ${proj.body.item.slug}`);
ok('a project can be edited',
  (await patch(su, '/api/admin/content/portfolio/' + proj.body.item.id, { title: 'Voices of the Rift Valley' })).status === 200);
ok('a project can be deleted', (await del(su, '/api/admin/content/portfolio/' + dup.body.item.id)).status === 200);
ok('deleting an unknown id is a 404', (await del(su, '/api/admin/content/portfolio/999999')).status === 404);

/* --------------------------------------------------------- testimonials */
// The public "Client voices" section is gone; the editor behind it is kept,
// so what it stores and validates is still worth testing.

const t1 = await post(su, '/api/admin/content/testimonials', {
  client_name: 'Wanjiku Mureithi', organisation: 'Rift Valley Trust',
  testimonial: 'They took a rough manuscript and returned something we were proud to launch.',
  rating: 5, published: true,
});
ok('a testimonial can be published', t1.status === 201, JSON.stringify(t1.body));
ok('a testimonial can be unpublished',
  (await patch(su, '/api/admin/content/testimonials/' + t1.body.item.id, { published: false })).status === 200);
ok('an out-of-range rating is refused',
  (await post(su, '/api/admin/content/testimonials', { client_name: 'Someone Else', testimonial: 'A perfectly fine body.', rating: 9 })).status === 400);

/* ------------------------------------------------------------------ faqs */

const f1 = await post(su, '/api/admin/content/faqs', {
  question: 'Do you handle ISBN registration?',
  answer: 'Yes, we guide authors through the ISBN process as part of publishing support.',
  published: true,
});
ok('an FAQ can be added', f1.status === 201, JSON.stringify(f1.body));
ok('and appears on the homepage', (await su.get('/')).text.includes('ISBN registration'));

/* ------------------------------------------------------------------ blog */

const draft = await post(su, '/api/admin/content/blog', {
  title: 'Preparing a manuscript', excerpt: 'What to do before you submit.',
  content: 'A longer article body that comfortably exceeds the minimum length requirement.',
  status: 'draft',
});
ok('an article can be drafted', draft.status === 201, JSON.stringify(draft.body));
ok('a draft stays off the public site', !(await su.get('/')).text.includes('Preparing a manuscript'));
ok('publishing it works', (await patch(su, '/api/admin/content/blog/' + draft.body.item.id, { status: 'published' })).status === 200);
ok('and it now appears', (await su.get('/')).text.includes('Preparing a manuscript'));
ok('publishing stamps a date', !!db.prepare('SELECT published_at p FROM blog_posts WHERE id=?').get(draft.body.item.id).p);

/* ------------------------------------------------------------- authority */

ok('an unknown content type is a 404', (await su.get('/api/admin/content/nope')).status === 404);
const anon = agent();
ok('anonymous cannot read content', (await anon.get('/api/admin/content/portfolio')).status === 401);
ok('anonymous cannot write settings', (await patch(anon, '/api/admin/settings', { phone: 'x' })).status === 401);

const staffEmail = `st${Date.now()}@example.com`;
await post(su, '/api/admin/users', { name: 'Plain Staff', email: staffEmail, role: 'staff', password: 'Copper-Vessel-Morning-Ledger-7!' });
const st = agent();
await post(st, '/api/auth/login', { email: staffEmail, password: 'Copper-Vessel-Morning-Ledger-7!' });
ok('plain staff can read content', (await st.get('/api/admin/content/portfolio')).status === 200);
ok('plain staff cannot create content',
  (await post(st, '/api/admin/content/faqs', { question: 'Sneaky question here?', answer: 'Should not be allowed through.' })).status === 403);
ok('plain staff cannot change settings', (await patch(st, '/api/admin/settings', { phone: 'x' })).status === 403);
ok('plain staff cannot read the audit log', (await st.get('/api/admin/audit')).status === 403);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
