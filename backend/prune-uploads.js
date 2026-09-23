// Reports files on disk that no database row refers to, and deletes them with
// --delete (or PRUNE_CONFIRM=on for cPanel's argument-less script runner):
//   npm run prune:uploads
//   npm run prune:uploads -- --delete
//
// Orphans accumulate from quote submissions that failed validation after the
// file was written, and from rows deleted in the dashboard. They are invisible
// in the UI and count against the same disk allocation as the database.
import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';

// This decides what to delete by asking the database what it knows about, so
// pointing it at the wrong database is the worst thing that could happen: an
// empty one lists nothing, and every manuscript on disk becomes an "orphan".
// db.js creates a missing database on import, so the check comes first.
const dbFile = path.resolve(process.env.DB_PATH || 'wise-pen.db');
if (!fs.existsSync(dbFile)) {
  console.error(`No database at ${dbFile}.`);
  console.error('Set DB_PATH, or run this from the application root. Nothing was examined.');
  process.exit(1);
}
const { default: db } = await import('./db.js');

const remove = process.argv.includes('--delete') || process.env.PRUNE_CONFIRM === 'on';
const uploadDir = path.resolve(process.env.UPLOAD_DIR || 'uploads');
const GRACE_MS = 60 * 60 * 1000;

if (!fs.existsSync(uploadDir)) { console.log(`No upload directory at ${uploadDir}.`); process.exit(0); }

const known = new Set(db.prepare('SELECT stored_name FROM files').all().map((r) => r.stored_name));
// The database opened, but is it the right one? A correct database with no file
// rows and a directory full of files is not a tidy-up job, it is a mismatch.
const onDisk = fs.readdirSync(uploadDir).filter((n) => fs.statSync(path.join(uploadDir, n)).isFile()).length;
if (remove && known.size === 0 && onDisk > 0) {
  console.error(`${dbFile} records no uploaded files at all, yet ${onDisk} file(s) sit in ${uploadDir}.`);
  console.error('That looks like the wrong database rather than a directory of rubbish. Nothing was deleted.');
  process.exit(1);
}
const now = Date.now();
let orphans = 0, bytes = 0, young = 0;

for (const name of fs.readdirSync(uploadDir)) {
  const full = path.join(uploadDir, name);
  const stat = fs.statSync(full);
  if (!stat.isFile() || known.has(name)) continue;
  // A file being written by a request in flight has no row yet. Anything from
  // the last hour is left alone so a busy moment is never mistaken for rubbish.
  if (now - stat.mtimeMs < GRACE_MS) { young += 1; continue; }
  orphans += 1; bytes += stat.size;
  if (remove) { fs.rmSync(full, { force: true }); console.log(`Deleted  ${name} (${(stat.size / 1024).toFixed(0)} KB)`); }
  else console.log(`Orphan   ${name} (${(stat.size / 1024).toFixed(0)} KB, ${stat.mtime.toISOString().slice(0, 10)})`);
}

console.log(`\n${known.size} files tracked in the database, ${orphans} orphaned on disk (${(bytes / 1048576).toFixed(1)} MB).`);
if (young) console.log(`${young} recent file(s) skipped — too new to be sure they are not mid-upload.`);
if (orphans && !remove) console.log('Nothing was deleted. Re-run with --delete, or PRUNE_CONFIRM=on, to remove them.');
db.close();
