// Answers "why will the admin password not work" without revealing anything
// secret: npm run admin:check
//
// "Invalid email or password" is deliberately the same message whether the
// account is missing, the address is different, or the password is wrong —
// telling a stranger which one it is would let them enumerate accounts. That
// silence is right for the sign-in page and useless for the person who owns the
// server, so this reports the parts an owner is entitled to know. It prints no
// password and no hash: for the configured ADMIN_PASSWORD it prints only
// whether it verifies, which is what you already learn by trying to sign in.
import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';

const dbFile = path.resolve(process.env.DB_PATH || 'wise-pen.db');
console.log(`Database    ${dbFile}`);
if (!fs.existsSync(dbFile)) {
  console.log('\nThere is no database at that path.');
  console.log('If the site is running, DB_PATH here does not match the one the app uses.');
  process.exit(1);
}

const { default: db } = await import('./db.js');
const { verifyPassword, minLengthFor } = await import('./password.js');

const email = (process.env.ADMIN_EMAIL || 'admin@wisepennpaper.co.ke').toLowerCase().trim();
const configured = process.env.ADMIN_PASSWORD;
console.log(`ADMIN_EMAIL ${email}${process.env.ADMIN_EMAIL ? '' : '  (default — ADMIN_EMAIL is not set)'}`);
console.log(`ADMIN_PASSWORD ${configured ? `set, ${configured.length} characters` : 'not set — the seed would have used its built-in default'}`);

const users = db.prepare('SELECT COUNT(*) n FROM users').get().n;
const staff = db.prepare("SELECT id,name,email,role,is_active,totp_enabled,last_login_at,sessions_valid_from FROM users WHERE role<>'client' ORDER BY id").all();
console.log(`\nAccounts    ${users} in total, ${staff.length} with staff access`);

if (!staff.length) {
  console.log('\nThere is no staff account at all, so no password can work.');
  console.log('The tables are created when the app boots, but the administrator is created by the seed.');
  console.log('Run the seed once (Setup Node.js App > Run JS script > seed), then sign in.');
  process.exit(1);
}

for (const u of staff) {
  console.log(`\n  ${u.email}`);
  console.log(`    id ${u.id}, role ${u.role}${u.is_active === 0 ? ', DEACTIVATED — sign-in is refused whatever the password' : ''}`);
  console.log(`    two-step verification ${u.totp_enabled ? 'enrolled' : 'not yet enrolled'}`);
  console.log(`    last signed in ${u.last_login_at || 'never'}`);
  if (u.sessions_valid_from) console.log(`    sessions invalidated at ${u.sessions_valid_from}`);
}

const target = db.prepare('SELECT id,email,role,is_active,password_hash FROM users WHERE email=?').get(email);
console.log('');
if (!target) {
  console.log(`No account uses ${email}.`);
  const near = staff.map((u) => u.email).join(', ');
  if (near) console.log(`Staff addresses that do exist: ${near}`);
  console.log('ADMIN_EMAIL probably differs from the address the account was created with.');
} else if (!configured) {
  console.log('ADMIN_PASSWORD is not set here, so there is nothing to test against.');
} else if (await verifyPassword(configured, target.password_hash)) {
  console.log('The configured ADMIN_PASSWORD DOES match this account.');
  console.log('So a failed sign-in is not the password. Check for a lockout below, that the');
  console.log('account is active, and that you are entering the two-step code correctly.');
} else {
  console.log('The configured ADMIN_PASSWORD does NOT match the stored hash.');
  console.log('The password was changed after the seed ran. Reset it: set ADMIN_PASSWORD and');
  console.log('ADMIN_PASSWORD_ROTATE=on, run the seed, then set ADMIN_PASSWORD_ROTATE back to off.');
  console.log(`Admin passwords need at least ${minLengthFor(target.role)} characters.`);
}

// Repeated failures lock the account for a while, and the sign-in page reports
// that plainly — but only once you get the password right, so it is worth
// saying here too.
const now = Date.now();
const locks = db.prepare('SELECT key,count,locked_until FROM login_attempts WHERE locked_until>?').all(now);
console.log('');
if (!locks.length) console.log('No account is currently locked out by failed attempts.');
else for (const l of locks) {
  console.log(`Locked: ${l.key} — ${l.count} failed attempts, clears in ${Math.ceil((l.locked_until - now) / 60000)} minute(s).`);
}

console.log('\nNothing here changes anything. To set a new password without email, see');
console.log('npm run reset:test -- <address> --issue (or RESET_TEST_EMAIL + RESET_TEST_ISSUE=on).');
db.close();
