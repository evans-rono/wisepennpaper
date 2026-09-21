import request from 'supertest';
import app from '../backend/server.js';
import db from '../backend/db.js';
import { generateCode } from '../backend/totp.js';
let pass=0, fail=0;
const ok=(n,c,e='')=>{ if(c){pass++;console.log('  PASS  '+n);} else {fail++;console.log('  FAIL  '+n+(e?' :: '+e:''));} };
const agent=()=>request.agent(app);
const post=async(a,u,b)=>{const t=(await a.get('/api/csrf')).body.csrfToken; return a.post(u).set('CSRF-Token',t).send(b);};
const patch=async(a,u,b)=>{const t=(await a.get('/api/csrf')).body.csrfToken; return a.patch(u).set('CSRF-Token',t).send(b);};
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

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
