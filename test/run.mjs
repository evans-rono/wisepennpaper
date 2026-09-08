// Runs every suite, each in its own process against its own freshly seeded
// database. Isolation matters here: several suites enrol two-factor, lock
// accounts and deactivate users, so sharing one database would make results
// depend on the order they happened to run in.
//
//   npm test

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const workDir = path.join(root, '.test-databases');

const ADMIN_PASSWORD = 'TestPass-12345!';
const baseEnv = {
  ...process.env,
  NODE_ENV: 'test',
  BASE_URL: 'http://localhost:3111',
  SESSION_SECRET: 'test-session-secret-at-least-32-characters-long',
  ADMIN_PASSWORD,
  // The limiters are exercised by their own assertions; everywhere else they
  // would only throttle the suite itself.
  AUTH_RATE_LIMIT: '100000',
  API_RATE_LIMIT: '100000',
};

const suites = fs.readdirSync(here).filter((f) => f.endsWith('.suite.mjs')).sort();
if (!suites.length) {
  console.error('No suites found in test/.');
  process.exit(1);
}

fs.rmSync(workDir, { recursive: true, force: true });
fs.mkdirSync(workDir, { recursive: true });

let failed = 0;
for (const suite of suites) {
  const name = suite.replace('.suite.mjs', '');
  const dbPath = path.join(workDir, `${name}.db`);
  const env = { ...baseEnv, DB_PATH: dbPath };

  const seeded = spawnSync(process.execPath, ['backend/seed.js'], { cwd: root, env, encoding: 'utf8' });
  if (seeded.status !== 0) {
    console.error(`\n${name}: seeding failed\n${seeded.stderr}`);
    failed++;
    continue;
  }

  console.log(`\n── ${name} ${'─'.repeat(Math.max(0, 56 - name.length))}`);
  const run = spawnSync(process.execPath, [path.join('test', suite)], {
    cwd: root, env, encoding: 'utf8',
  });
  // Node prints an experimental-feature notice for some built-ins; it is noise.
  const output = (run.stdout || '') + (run.stderr || '');
  console.log(output.split('\n')
    .filter((line) => !/ExperimentalWarning|trace-warnings|^(GET|POST|PATCH|DELETE|PUT) /.test(line))
    .join('\n').trim());
  if (run.status !== 0) failed++;
}

fs.rmSync(workDir, { recursive: true, force: true });
console.log(failed ? `\n${failed} suite(s) failed.` : '\nAll suites passed.');
process.exit(failed ? 1 : 0);
