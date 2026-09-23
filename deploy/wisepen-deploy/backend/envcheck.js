// Reports which settings the running process can actually see, without
// printing their values: npm run env:check
import 'dotenv/config';

const REQUIRED = ['NODE_ENV', 'BASE_URL', 'SESSION_SECRET', 'DB_PATH'];
const OPTIONAL = ['PORT', 'ADMIN_EMAIL', 'SMTP_HOST', 'SMTP_USER', 'MAIL_FROM', 'TRUST_PROXY',
  'REQUIRE_ADMIN_2FA', 'STORAGE_DRIVER', 'UPLOAD_DIR', 'GOOGLE_CLIENT_ID'];

const show = (name, required) => {
  const v = process.env[name];
  const state = v ? `set (${v.length} chars)` : required ? 'MISSING' : 'not set';
  console.log(`  ${name.padEnd(20)} ${state}`);
};
console.log('Required:');
REQUIRED.forEach((n) => show(n, true));
console.log('Optional:');
OPTIONAL.forEach((n) => show(n, false));

const missing = REQUIRED.filter((n) => !process.env[n]);
if (missing.length) {
  console.log(`\n${missing.length} required setting(s) missing: ${missing.join(', ')}`);
  console.log('In cPanel these come from Setup Node.js App > Environment variables; restart the app after changing them.');
  process.exit(1);
}
console.log('\nAll required settings are visible to this process.');
