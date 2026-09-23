import request from 'supertest';
import app from '../backend/server.js';
import db from '../backend/db.js';
import { generateCode } from '../backend/totp.js';
let pass=0, fail=0;
const ok=(n,c,e='')=>{ if(c){pass++;console.log('  PASS  '+n);} else {fail++;console.log('  FAIL  '+n+(e?' :: '+e:''));} };
const agent=()=>request.agent(app);
const post=async(a,u,b)=>{const t=(await a.get('/api/csrf')).body.csrfToken; return a.post(u).set('CSRF-Token',t).send(b);};
const patch=async(a,u,b)=>{const t=(await a.get('/api/csrf')).body.csrfToken; return a.patch(u).set('CSRF-Token',t).send(b);};
const del=async(a,u)=>{const t=(await a.get('/api/csrf')).body.csrfToken; return a.delete(u).set('CSRF-Token',t);};
const ADMIN={email:'admin@wisepennpaper.co.ke',password:'TestPass-12345!x'};
const PW='Copper-Vessel-Morning-Ledger-7!';

const su=agent();
const login=await post(su,'/api/auth/login',ADMIN);
ok('super admin signs in', login.status===200, JSON.stringify(login.body));
ok('session flags that enrolment is required', login.body.user.mustEnrol===true);
ok('dashboard is blocked until enrolled', (await su.get('/api/admin/dashboard')).status===403);
ok('the refusal carries a machine-readable code', (await su.get('/api/admin/dashboard')).body.code==='2FA_REQUIRED');
ok('file downloads are blocked too', (await su.get('/api/files/1')).status===403);
ok('enrolment endpoints stay reachable', (await su.get('/api/auth/2fa/status')).status===200);

const setup=await post(su,'/api/auth/2fa/setup',{});
const secret=setup.body.secret.replace(/\s/g,'');
ok('enrolment completes', (await post(su,'/api/auth/2fa/enable',{code:generateCode(secret)})).status===200);
ok('dashboard opens once enrolled', (await su.get('/api/admin/dashboard')).status===200);
ok('a required second factor cannot be switched off',
  (await post(su,'/api/auth/2fa/disable',{password:ADMIN.password,code:generateCode(secret)})).status===403);

const staffEmail=`staff${Date.now()}@example.com`;
const created=await post(su,'/api/admin/users',{name:'Jane Kamau',email:staffEmail,phone:'0700111222',role:'staff',password:PW});
ok('a staff account can be created', created.status===201, JSON.stringify(created.body));
ok('and appears in the team list', (await su.get('/api/admin/users')).body.items.some(u=>u.email===staffEmail));
ok('the list never leaks password hashes', !JSON.stringify((await su.get('/api/admin/users')).body).includes('sha256$'));
const dup=await post(su,'/api/admin/users',{name:'Duplicate Person',email:staffEmail,role:'staff',password:PW});
ok('a duplicate email is refused', dup.status===409, `${dup.status} ${JSON.stringify(dup.body)}`);
ok('a weak password is refused',
  (await post(su,'/api/admin/users',{name:'Weak Person',email:`w${Date.now()}@e.co`,role:'staff',password:'password1234'})).status===400);
ok('a one-character name is refused', (await post(su,'/api/admin/users',{name:'X',email:`x${Date.now()}@e.co`,role:'staff',password:PW})).status===400);

const staffId=created.body.user.id;
const staffAgent=agent();
ok('the new staff member can sign in', (await post(staffAgent,'/api/auth/login',{email:staffEmail,password:PW})).status===200);
ok('staff are not forced to enrol', (await staffAgent.get('/api/admin/dashboard')).status===200);
ok('staff cannot manage the team', (await staffAgent.get('/api/admin/users')).status===403);

ok('deactivation succeeds', (await patch(su,'/api/admin/users/'+staffId,{is_active:false})).status===200);
ok('the deactivated session dies on its next request', (await staffAgent.get('/api/admin/dashboard')).status===401);
const denied=await post(agent(),'/api/auth/login',{email:staffEmail,password:PW});
ok('and they can no longer sign in', denied.status===403, String(denied.status));
ok('the refusal explains why', /no longer active/i.test(denied.body.error||''), denied.body.error);
ok('reactivation restores access', (await patch(su,'/api/admin/users/'+staffId,{is_active:true})).status===200);
ok('and they can sign in again', (await post(agent(),'/api/auth/login',{email:staffEmail,password:PW})).status===200);

const meId=login.body.user.id;
ok('you cannot change your own role', (await patch(su,'/api/admin/users/'+meId,{role:'staff'})).status===403);
ok('you cannot deactivate yourself', (await patch(su,'/api/admin/users/'+meId,{is_active:false})).status===403);
await patch(su,'/api/admin/users/'+staffId,{role:'super_admin'});
ok('a super admin can promote to super admin', db.prepare('SELECT role FROM users WHERE id=?').get(staffId).role==='super_admin');
ok('promotion invalidates that person\'s sessions', !!db.prepare('SELECT sessions_valid_from s FROM users WHERE id=?').get(staffId).s);
await patch(su,'/api/admin/users/'+staffId,{role:'staff'});
ok('demoting back to staff leaves one super admin',
  db.prepare("SELECT COUNT(*) n FROM users WHERE role='super_admin' AND is_active=1").get().n===1);
ok('the last super admin cannot be demoted',
  (await patch(su,'/api/admin/users/'+meId,{role:'admin'})).status===403);

const adminEmail=`adm${Date.now()}@example.com`;
await post(su,'/api/admin/users',{name:'Plain Admin',email:adminEmail,role:'admin',password:'Brass-Compass-Evening-Tide-4!'});
const plain=agent();
await post(plain,'/api/auth/login',{email:adminEmail,password:'Brass-Compass-Evening-Tide-4!'});
const ps=await post(plain,'/api/auth/2fa/setup',{});
await post(plain,'/api/auth/2fa/enable',{code:generateCode(ps.body.secret.replace(/\s/g,''))});
const esc1=await post(plain,'/api/admin/users',{name:'Escalation Attempt',email:`y${Date.now()}@e.co`,role:'super_admin',password:PW});
ok('an admin cannot create a super admin', esc1.status===403, `${esc1.status} ${JSON.stringify(esc1.body)}`);
ok('an admin cannot promote anyone to super admin', (await patch(plain,'/api/admin/users/'+staffId,{role:'super_admin'})).status===403);
ok('an admin cannot demote a super admin', (await patch(plain,'/api/admin/users/'+meId,{role:'staff'})).status===403);

ok('a manager can clear a colleague\'s second factor', (await post(su,'/api/admin/users/'+staffId+'/reset-2fa',{})).status===200);
ok('it is recorded in the audit log', db.prepare("SELECT COUNT(*) n FROM audit_logs WHERE action='staff_2fa_reset'").get().n>0);
ok('an unknown account is a 404', (await patch(su,'/api/admin/users/999999',{is_active:false})).status===404);


/* ------------------------------------------------------ deleting accounts

   Deactivating keeps the records and blocks sign-in. Deleting is only for the
   accounts that should never have existed, so the route refuses any account
   that real work hangs off and names what is holding it. */

ok('nobody can delete their own account', (await del(su,'/api/admin/users/'+meId)).status===403);
ok('an admin cannot delete a super admin', (await del(plain,'/api/admin/users/'+meId)).status===403);
ok('deleting an unknown account is a 404', (await del(su,'/api/admin/users/999999')).status===404);
// A fresh session: staffAgent's was destroyed by the deactivation test above,
// and a dead session would answer 401, which proves something else.
const liveStaff=agent();
await post(liveStaff,'/api/auth/login',{email:staffEmail,password:PW});
ok('plain staff cannot delete anyone', (await del(liveStaff,'/api/admin/users/'+staffId)).status===403);

const spare=await post(su,'/api/admin/users',{name:'Wrong Address',email:`typo${Date.now()}@example.com`,phone:'0700333444',role:'staff',password:PW});
const spareId=spare.body.user?.id??spare.body.id;
ok('an account added by mistake can be created', spare.status===201, JSON.stringify(spare.body));
ok('and deleted', (await del(su,'/api/admin/users/'+spareId)).status===200);
ok('it is gone from the database', !db.prepare('SELECT 1 FROM users WHERE id=?').get(spareId));
ok('the audit log keeps the address, which the user row no longer holds',
  db.prepare("SELECT COUNT(*) n FROM audit_logs WHERE action='staff_deleted' AND entity_id LIKE ?").get(`%typo%`).n>0);

// An account with work attached is refused, and told why.
const busy=await post(su,'/api/admin/users',{name:'Has History',email:`busy${Date.now()}@example.com`,phone:'0700555666',role:'staff',password:PW});
const busyId=busy.body.user?.id??busy.body.id;
db.prepare('INSERT INTO projects(reference,client_id,title,status) VALUES(?,?,?,?)')
  .run(`DEL-${Date.now()}`,busyId,'A project they are attached to','Editing');
const refused=await del(su,'/api/admin/users/'+busyId);
ok('an account attached to work is refused', refused.status===409, String(refused.status));
ok('the refusal names what is holding it', /1 project/.test(refused.body.error||''), refused.body.error);
ok('it points at deactivation instead', /[Dd]eactivate/.test(refused.body.error||''));
ok('and the account still exists', !!db.prepare('SELECT 1 FROM users WHERE id=?').get(busyId));
ok('deactivating it works', (await patch(su,'/api/admin/users/'+busyId,{is_active:false})).status===200);

// The last super admin cannot be removed by either route.
ok('the last active super admin cannot be deleted',
  [403,409].includes((await del(plain,'/api/admin/users/'+meId)).status));

/* ------------------------------------------------- coming back afterwards

   The brute-force counters are keyed on the email address and the user id
   rather than by foreign key, so they outlive the account. Left behind, a
   lockout earned by an old account refuses whoever next registers that
   address — including the same person returning as a client, told "too many
   attempts" for a password they had just chosen. */

const lockOut=async(email)=>{for(let i=0;i<12;i++) await post(agent(),'/api/auth/login',{email,password:'wrong-password-here'});};
const REJOIN=`rejoin${Date.now()}@example.com`;
await post(agent(),'/api/auth/register',{name:'Returning Client',email:REJOIN,phone:'0700000000',password:PW});
const rejoinId=db.prepare('SELECT id FROM users WHERE email=?').get(REJOIN).id;
await lockOut(REJOIN);
ok('failed sign-ins lock an account out',
  db.prepare('SELECT locked_until l FROM login_attempts WHERE key=?').get(`user:${REJOIN}`)?.l>Date.now());
ok('the account can be deleted', (await del(su,'/api/admin/users/'+rejoinId)).status===200);
ok('deleting clears the lockout that was keyed to the address',
  db.prepare('SELECT COUNT(*) n FROM login_attempts WHERE key=?').get(`user:${REJOIN}`).n===0);
ok('the address can be registered again',
  (await post(agent(),'/api/auth/register',{name:'Returning Client',email:REJOIN,phone:'0700000000',password:PW})).status===201);
const rejoined=await post(agent(),'/api/auth/login',{email:REJOIN,password:PW});
ok('and they can sign straight in as a client',
  rejoined.status===200 && rejoined.body.user?.role==='client', `${rejoined.status} ${JSON.stringify(rejoined.body)}`);

// Reactivating has the same trap: access is restored while a stale lockout
// still refuses them.
const REVIVE=`revive${Date.now()}@example.com`;
await post(agent(),'/api/auth/register',{name:'Revived Client',email:REVIVE,phone:'0700000000',password:PW});
const reviveId=db.prepare('SELECT id FROM users WHERE email=?').get(REVIVE).id;
await patch(su,'/api/admin/users/'+reviveId,{is_active:false});
await lockOut(REVIVE);
ok('reactivating succeeds', (await patch(su,'/api/admin/users/'+reviveId,{is_active:true})).status===200);
const revived=await post(agent(),'/api/auth/login',{email:REVIVE,password:PW});
ok('and they can sign in immediately, not after the lockout expires',
  revived.status===200, `${revived.status} ${JSON.stringify(revived.body)}`);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
