// Takes a consistent copy of the database and the uploaded files:
//   npm run backup
//
// It exists because the obvious approach is wrong. The database runs in WAL
// mode, so copying wise-pen.db in File Manager while the site is live captures
// the main file without the write-ahead log beside it — a backup that restores
// to some arbitrary older state, silently. SQLite's online backup API walks the
// database under a read lock instead, so the copy is a real point in time even
// while quotes are being submitted.
//
// Runs with no arguments so it works from cPanel's "Run JS script" button and
// from a cron job.
import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';

// db.js creates the database when the file is missing, which is right for the
// server and dangerous here. A cron job does not inherit the environment the
// Node.js app runs with, so a wrong or unset DB_PATH would quietly open a new
// empty database, back that up, and in time rotate the real backups away.
// Checked before the import, because importing is what would create it.
const dbFile = path.resolve(process.env.DB_PATH || 'wise-pen.db');
if (!fs.existsSync(dbFile)) {
  console.error(`No database at ${dbFile}.`);
  console.error('Set DB_PATH, or run this from the application root. Nothing was backed up.');
  process.exit(1);
}
const { default: db } = await import('./db.js');

const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
const dir = path.resolve(process.env.BACKUP_DIR || 'backups');
const keep = Math.max(Number(process.env.BACKUP_KEEP) || 7, 1);
const uploadDir = path.resolve(process.env.UPLOAD_DIR || 'uploads');

fs.mkdirSync(dir, { recursive: true });

const target = path.join(dir, `wise-pen-${stamp}.db`);
await db.backup(target);
const size = fs.statSync(target).size;
console.log(`Database    ${target} (${(size / 1048576).toFixed(1)} MB)`);

// Uploaded manuscripts are the part that cannot be regenerated from anywhere.
// They are copied rather than archived: no tar or zip binary is guaranteed on
// shared hosting, and a plain directory restores by dragging it back.
let copied = 0;
if (fs.existsSync(uploadDir)) {
  const dest = path.join(dir, `uploads-${stamp}`);
  fs.mkdirSync(dest, { recursive: true });
  for (const name of fs.readdirSync(uploadDir)) {
    const from = path.join(uploadDir, name);
    if (!fs.statSync(from).isFile()) continue;
    fs.copyFileSync(from, path.join(dest, name));
    copied += 1;
  }
  console.log(`Uploads     ${dest} (${copied} files)`);
} else {
  console.log('Uploads     none on disk (object storage, or nothing uploaded yet)');
}

// Keeping every copy forever fills the same disk the database sits on, which is
// the failure this script is supposed to prevent.
const older = (prefix) => fs.readdirSync(dir).filter((n) => n.startsWith(prefix)).sort().slice(0, -keep);
for (const name of [...older('wise-pen-'), ...older('uploads-')]) {
  fs.rmSync(path.join(dir, name), { recursive: true, force: true });
  console.log(`Removed     ${name} (keeping the newest ${keep})`);
}

console.log('\nBackups on the same server survive a mistake, not a host failure.');
console.log(`Download ${path.relative(process.cwd(), dir)} periodically, or point BACKUP_DIR somewhere replicated.`);
db.close();
