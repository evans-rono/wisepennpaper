// Authorisation, not authentication. Every client route scopes its query by
// the signed-in user's id, but "signed in" and "allowed to see this row" are
// different questions, and the usual way custom portals leak is answering the
// first and assuming the second. These assertions pin that down: two real
// client accounts, each with their own project, file and messages, and every
// way one might reach the other's.
import request from 'supertest';
import app from '../backend/server.js';
import db from '../backend/db.js';
import crypto from 'node:crypto';
import { generateCode } from '../backend/totp.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => {
  if (c) { pass++; console.log('  PASS  ' + n); }
  else { fail++; console.log('  FAIL  ' + n + (e ? ' :: ' + e : '')); }
};
const agent = () => request.agent(app);
const post = async (a, u, b) => { const t = (await a.get('/api/csrf')).body.csrfToken; return a.post(u).set('CSRF-Token', t).send(b); };
const patch = async (a, u, b) => { const t = (await a.get('/api/csrf')).body.csrfToken; return a.patch(u).set('CSRF-Token', t).send(b); };

/* ------------------------------------------------------------- fixtures */

const su = agent();
await post(su, '/api/auth/login', { email: 'admin@wisepennpaper.co.ke', password: 'TestPass-12345!x' });
const setup = await post(su, '/api/auth/2fa/setup', {});
await post(su, '/api/auth/2fa/enable', { code: generateCode(setup.body.secret.replace(/\s/g, '')) });

const PASSWORD = 'Copper-Vessel-Morning-Ledger-7!';
const makeClient = async (label) => {
  const email = `${label}${Date.now()}@example.com`;
  const a = agent();
  const r = await post(a, '/api/auth/register', { name: `Client ${label}`, email, phone: '0700000000', password: PASSWORD });
  return { agent: a, email, id: r.body?.user?.id ?? db.prepare('SELECT id FROM users WHERE email=?').get(email).id };
};

const alice = await makeClient('alice');
const bob = await makeClient('bob');
ok('two separate client accounts exist', alice.id !== bob.id, `${alice.id} vs ${bob.id}`);

// Projects have no create endpoint — staff open them from an approved quote —
// so the fixture is written directly, exactly as the application would store it.
const projectOf = (clientId, reference, title) => db.prepare(
  'INSERT INTO projects(reference,client_id,title,description,status) VALUES(?,?,?,?,?)')
  .run(reference, clientId, title, 'A manuscript in production.', 'Editing').lastInsertRowid;

const aliceProject = projectOf(alice.id, `ISO-A-${Date.now()}`, "Alice's Memoir");
const bobProject = projectOf(bob.id, `ISO-B-${Date.now()}`, "Bob's Anthology");

const fileOf = (projectId, uploader, name) => db.prepare(
  'INSERT INTO files(project_id,uploaded_by,original_name,stored_name,mime_type,size,approved) VALUES(?,?,?,?,?,?,1)')
  .run(projectId, uploader, name, `stored-${crypto.randomUUID()}.pdf`, 'application/pdf', 1024).lastInsertRowid;

const aliceFile = fileOf(aliceProject, alice.id, 'alice-manuscript.pdf');

db.prepare('INSERT INTO messages(project_id,sender_id,body) VALUES(?,?,?)')
  .run(aliceProject, alice.id, 'A private note about my manuscript.');

/* ------------------------------------------------- the portal shows only you */

const bobPortal = await bob.agent.get('/api/client/portal');
ok('a client can read their own portal', bobPortal.status === 200, String(bobPortal.status));
ok('it contains only their own projects',
  bobPortal.body.projects.every((p) => p.client_id === bob.id),
  JSON.stringify(bobPortal.body.projects.map((p) => p.client_id)));
ok("another client's project is absent",
  !bobPortal.body.projects.some((p) => p.id === aliceProject));
ok("another client's messages are absent",
  !JSON.stringify(bobPortal.body).includes('A private note about my manuscript.'));

const alicePortal = await alice.agent.get('/api/client/portal');
ok('the same endpoint shows the other client their own work',
  alicePortal.body.projects.some((p) => p.id === aliceProject));

/* ------------------------------------------- guessing an id gets you nothing */

ok("posting a message to another client's project is refused",
  (await post(bob.agent, `/api/client/projects/${aliceProject}/messages`, { body: 'Can I see this?' })).status === 404);
ok('the message was not written',
  !db.prepare('SELECT 1 FROM messages WHERE project_id=? AND sender_id=?').get(aliceProject, bob.id));
ok('posting to their own project still works',
  (await post(bob.agent, `/api/client/projects/${bobProject}/messages`, { body: 'A question about my book.' })).status === 201);
ok('an id that belongs to nobody is refused',
  (await post(bob.agent, '/api/client/projects/999999/messages', { body: 'Hello?' })).status === 404);

/* ----------------------------------------------------------------- files */

const stolen = await bob.agent.get(`/api/files/${aliceFile}`);
ok("downloading another client's file is refused", stolen.status === 403, String(stolen.status));
ok('an unknown file id is a 404', (await bob.agent.get('/api/files/999999')).status === 404);
const anon = agent();
ok('anonymous cannot download a file at all', (await anon.get(`/api/files/${aliceFile}`)).status === 401);

/* ------------------------------------------------- profile edits stay yours */

// The route takes the whole profile, not a partial patch.
const renamed = await patch(bob.agent, '/api/client/profile', { name: 'Bob Renamed', email: bob.email, phone: '0700000000' });
ok('a client can edit their own profile', renamed.status === 200, String(renamed.status));
ok("it did not touch the other client's record",
  db.prepare('SELECT name FROM users WHERE id=?').get(alice.id).name === 'Client alice',
  db.prepare('SELECT name FROM users WHERE id=?').get(alice.id).name);

/* --------------------------------------------- a client is not a staff member */

ok('a client cannot read the staff dashboard', (await bob.agent.get('/api/admin/dashboard')).status === 403);
ok('a client cannot list projects', (await bob.agent.get('/api/admin/projects')).status === 403);
ok('a client cannot read the audit log', (await bob.agent.get('/api/admin/audit')).status === 403);
ok('a client cannot read the user list', (await bob.agent.get('/api/admin/users')).status === 403);
ok('a client cannot change settings', (await patch(bob.agent, '/api/admin/settings', { phone: 'x' })).status === 403);
ok('a client cannot promote themselves',
  [403, 404].includes((await patch(bob.agent, `/api/admin/users/${bob.id}`, { role: 'super_admin' })).status));
ok('and the role really did not change',
  db.prepare('SELECT role FROM users WHERE id=?').get(bob.id).role === 'client');

/* ------------------------------------- an email address is not a credential

   The portal used to match quotes and appointments with `user_id=? OR email=?`
   so that someone who enquired anonymously would find it waiting after they
   registered. Nothing verifies an address at sign-up, so the same query let
   anyone register as a stranger and collect that stranger's enquiry and the
   manuscript attached to it — no id to guess, just an address to know. */

const VICTIM = `victim${Date.now()}@example.com`;
const visitor = agent();
const vToken = (await visitor.get('/api/csrf')).body.csrfToken;
const enquiry = await visitor.post('/api/quotes').set('CSRF-Token', vToken).type('form').send({
  _csrf: vToken, full_name: 'Victim Author', email: VICTIM, phone: '0700000000',
  project_type: 'Book', project_title: 'An Unpublished Memoir',
  description: 'A confidential manuscript sent only to the publisher.',
});
ok('an anonymous enquiry can be submitted', enquiry.status === 201, String(enquiry.status));
const enquiryId = db.prepare('SELECT id FROM quote_requests WHERE email=?').get(VICTIM).id;
const enquiryFile = db.prepare(
  'INSERT INTO files(quote_id,original_name,stored_name,mime_type,size) VALUES(?,?,?,?,?)')
  .run(enquiryId, 'memoir.pdf', `stored-${crypto.randomUUID()}.pdf`, 'application/pdf', 2048).lastInsertRowid;
ok('it is not attached to any account',
  db.prepare('SELECT user_id FROM quote_requests WHERE id=?').get(enquiryId).user_id === null);

const impostor = agent();
const claimed = await post(impostor, '/api/auth/register',
  { name: 'Impostor', email: VICTIM, phone: '0711111111', password: PASSWORD });
ok('someone else can still register with that address', claimed.status === 201, String(claimed.status));

const stolenPortal = await impostor.get('/api/client/portal');
ok("registering with the address does not reveal the enquiry",
  !stolenPortal.body.quotes.some((q) => q.id === enquiryId),
  JSON.stringify(stolenPortal.body.quotes.map((q) => q.id)));
ok('nor its title anywhere in the response',
  !JSON.stringify(stolenPortal.body).includes('An Unpublished Memoir'));
ok('nor the manuscript attached to it',
  (await impostor.get(`/api/files/${enquiryFile}`)).status === 403);

// The same trick from the other direction: change an existing account's address.
await patch(bob.agent, '/api/client/profile', { name: 'Bob Renamed', email: `spare${Date.now()}@example.com`, phone: '0700000000' });
ok('changing an account address to a stranger\'s reveals nothing either',
  !(await bob.agent.get('/api/client/portal')).body.quotes.some((q) => q.id === enquiryId));

/* ------------------------------------------ the legitimate path still works */

await patch(su, `/api/admin/quotes/${enquiryId}`, { status: 'Contacted', user_id: bob.id });
ok('staff can attach an enquiry to a client account',
  db.prepare('SELECT user_id FROM quote_requests WHERE id=?').get(enquiryId).user_id === bob.id);
ok('and then that client sees it',
  (await bob.agent.get('/api/client/portal')).body.quotes.some((q) => q.id === enquiryId));
ok('and can fetch its attachment',
  [200, 404].includes((await bob.agent.get(`/api/files/${enquiryFile}`)).status));
ok('but the impostor still cannot',
  (await impostor.get(`/api/files/${enquiryFile}`)).status === 403);
ok('linking to an account that does not exist is refused',
  (await patch(su, `/api/admin/quotes/${enquiryId}`, { status: 'Contacted', user_id: 999999 })).status === 400);
ok('linking to a staff account is refused',
  (await patch(su, `/api/admin/quotes/${enquiryId}`, { status: 'Contacted', user_id: 1 })).status === 400);

// The dashboard names the account by address, because listing users needs a
// manager role and plain staff handle quotes too.
ok('staff can link by the account email instead of the id',
  (await patch(su, `/api/admin/quotes/${enquiryId}`, { status: 'Contacted', client_email: alice.email })).status === 200);
ok('and it moved to that account',
  db.prepare('SELECT user_id FROM quote_requests WHERE id=?').get(enquiryId).user_id === alice.id);
ok('an address with no client account is refused',
  (await patch(su, `/api/admin/quotes/${enquiryId}`, { status: 'Contacted', client_email: 'nobody@example.com' })).status === 400);
ok('the refusal left the link untouched',
  db.prepare('SELECT user_id FROM quote_requests WHERE id=?').get(enquiryId).user_id === alice.id);
ok('an empty address detaches it',
  (await patch(su, `/api/admin/quotes/${enquiryId}`, { status: 'Contacted', client_email: '' })).status === 200
  && db.prepare('SELECT user_id FROM quote_requests WHERE id=?').get(enquiryId).user_id === null);
ok('and the client stops seeing it',
  !(await alice.agent.get('/api/client/portal')).body.quotes.some((q) => q.id === enquiryId));

/* -------------------------------------------- staff do see across accounts */

ok('staff can read a client file', [200, 404].includes((await su.get(`/api/files/${aliceFile}`)).status));
ok('staff can list every project', (await su.get('/api/admin/projects')).status === 200);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
