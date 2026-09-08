import request from 'supertest';
import app from '../backend/server.js';
import db from '../backend/db.js';

let pass = 0, fail = 0;
const ok = (name, condition, extra = '') => {
  if (condition) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${extra ? ' :: ' + extra : ''}`); }
};
const agent = () => request.agent(app);
const token = async (a) => (await a.get('/api/csrf')).body.csrfToken;
const post = async (a, path, body) => a.post(path).set('CSRF-Token', await token(a)).send(body);
const patch = async (a, path, body) => a.patch(path).set('CSRF-Token', await token(a)).send(body);
const password = 'quiet lantern harbour method';

const invalidEmail = await post(agent(), '/api/auth/register', {
  name: 'Invalid Email', email: 'not-an-email', phone: '0712345678', phone_country: 'KE', password,
});
ok('signup rejects invalid email with field', invalidEmail.status === 400 && invalidEmail.body.field === 'email');

const invalidPhone = await post(agent(), '/api/auth/register', {
  name: 'Invalid Phone', email: `invalid-phone-${Date.now()}@example.com`, phone: '123', phone_country: 'KE', password,
});
ok('signup rejects invalid phone with field', invalidPhone.status === 400 && invalidPhone.body.field === 'phone');

const client = agent();
const email = `  Client-${Date.now()}@Example.COM `;
const signup = await post(client, '/api/auth/register', {
  name: 'Test Client', email, phone: '0712345678', phone_country: 'KE', password,
});
ok('signup accepts valid Kenyan phone', signup.status === 201, JSON.stringify(signup.body));
const stored = db.prepare('SELECT email,phone FROM users WHERE id=?').get(signup.body.user.id);
ok('signup lowercases and trims email', stored.email === email.trim().toLowerCase());
ok('signup stores phone in E.164 format', stored.phone === '+254712345678', stored.phone);

const international = await post(agent(), '/api/auth/register', {
  name: 'International Client', email: `us-${Date.now()}@example.com`, phone: '4155552671', phone_country: 'US', password,
});
ok('signup accepts an international country code', international.status === 201 && international.body.user.phone === '+14155552671');

const updated = await patch(client, '/api/client/profile', {
  name: 'Updated Client', email: ' Updated@Example.COM ', phone: '769153821', phone_country: 'KE',
});
ok('client can edit information', updated.status === 200);
const afterEdit = db.prepare('SELECT name,email,phone FROM users WHERE id=?').get(signup.body.user.id);
ok('client edit stores normalized values', afterEdit.name === 'Updated Client' && afterEdit.email === 'updated@example.com' && afterEdit.phone === '+254769153821');

const badEdit = await patch(client, '/api/client/profile', { name: 'Updated Client', email: 'bad', phone: '769153821', phone_country: 'KE' });
ok('client edit rejects invalid email', badEdit.status === 400 && badEdit.body.field === 'email');

const past = await post(agent(), '/api/appointments', {
  full_name: 'Past Person', email: 'past@example.com', phone: '0712345678', phone_country: 'KE',
  consultation_type: 'Editorial consultation', preferred_date: '2000-01-01', preferred_time: '10:00', timezone_offset: '0',
});
ok('appointment rejects past date', past.status === 400 && past.body.field === 'preferred_date');

const future = await post(agent(), '/api/appointments', {
  full_name: 'Future Person', email: 'future@example.com', phone: '0712345678', phone_country: 'KE',
  consultation_type: 'Editorial consultation', preferred_date: '2099-01-01', preferred_time: '10:00', timezone_offset: '0',
});
ok('appointment accepts future date', future.status === 201, JSON.stringify(future.body));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
