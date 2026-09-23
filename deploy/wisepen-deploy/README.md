# The Wise Pen N’ Paper Business Platform

A full-stack publishing website, lead-management system, secure client portal and admin dashboard. The visual design is original and uses an editorial green, gold and paper-toned identity.

## Included

- Responsive public website with services, process, client categories, resources, FAQs, contact and CTAs
- Server-rendered public pages: services, FAQs, articles and contact details are in the delivered HTML, so they are crawlable and readable before any script runs
- Indexable service pages at `/services/<slug>`, listed in the sitemap, with per-service metadata and `Service` + `BreadcrumbList` structured data
- Progressive enhancement: the quote, contact and consultation forms post natively and confirm on a server-rendered page when JavaScript is unavailable
- Database-backed service catalogue and site-wide search
- Three-step quote request workflow with reference generation and secure multi-file upload
- Contact and consultation booking workflows
- Client registration, login, project progress, milestones, quote, appointment and invoice views
- Staff dashboard: business metrics, quote requests with full detail and downloadable attachments, internal notes, appointment and enquiry status management, an activity log for administrators, and paging throughout
- Content management for everything the public site shows: services, FAQs and articles, plus a Site details screen for contact information. Projects and testimonials are still recorded under their own tabs, though the site no longer has a Selected work or Client voices section to show them in. Nothing on the public site now requires hand-written SQL to change
- Team management: add colleagues, set roles, deactivate someone who leaves, and clear a lost second factor. Guarded against self-demotion, self-deactivation, privilege escalation by an admin, and removing the last super admin
- Two-step verification for staff sign-in (TOTP, RFC 6238) with QR enrolment, single-use recovery codes, replay protection, and "sign out everywhere else". Required for `admin` and `super_admin`: those accounts cannot reach any data until enrolled, and cannot switch it back off
- Optional Sign in with Google (OpenID Connect authorisation-code flow with PKCE, server-side so no third-party script is loaded). Verified email required, optional Workspace domain restriction, and it never creates a staff account
- Relational data model for users, clients, services, quotes, projects, milestones, files, appointments, portfolio, testimonials, blog, FAQs, messages, notifications, quotations, invoices, settings and audit logs
- Role-aware API protection, signed double-submit CSRF tokens, security headers (CSP without `unsafe-inline`, Permissions-Policy, COOP/CORP, HSTS, strict referrer policy), validation, sanitisation, upload size limits and audit logging
- Uploads are accepted on their contents, not their claimed type: every file is checked against its format signature after it lands, stored under a server-generated name with the verified extension, and deleted if it is not a genuine PDF, Word, JPG or PNG
- Rate limiting sized to stop automated abuse without touching ordinary use: signed-in users are exempt from the general limiter, only failed sign-ins count towards the credential limiter, and both ceilings are env-overridable
- Password handling built to NIST SP 800-63B: bcrypt over a SHA-256 pre-hash (so passphrases are not silently truncated at bcrypt's 72-byte limit), a 12-character minimum with screening against common passwords, keyboard runs and the user's own name, email and the site's name, constant-cost verification that does not reveal whether an account exists, per-account backoff on repeated failures, session regeneration on sign-in, registration and password change, and an authenticated change-password flow
- Optional Have I Been Pwned breach screening (`PWNED_CHECK=on`), using the k-anonymity range API so the password never leaves the server
- Sessions and brute-force counters are stored in SQLite, so a restart or deploy no longer signs everyone out — and no longer clears an attacker's lockout
- No third-party runtime dependencies for CSRF, TOTP or QR generation; each is implemented against its specification in `backend/`
- SEO metadata, Open Graph and Twitter cards, JSON-LD, sitemap, robots rules and real 404 responses for unknown paths
- Accessibility work: native `<dialog>` modals with focus trapping, AA-conformant text contrast in both themes, keyboard-only focus rings, reduced-motion support and a print stylesheet
- Light and dark themes: follows the operating system by default, with a toggle that overrides it and is remembered per browser
- Password fields with a reveal toggle, a live strength meter and confirmation matching
- SMTP email notifications when configured

## Tests

```bash
npm test
```

Runs every suite in `test/`, each in its own process against its own freshly
seeded database — several of them enrol two-factor, lock accounts and deactivate
users, so a shared database would make results depend on ordering.

## Project layout

- `frontend/` contains browser-facing HTML, CSS, JavaScript and image assets.
- `backend/` contains the Express server, database layer, authentication and other server-only modules.
- `test/` contains the integration and unit suites.

The backend serves the frontend at `/`, while JSON endpoints remain under `/api/`.

## Run locally

```bash
cp .env.example .env
# Replace SESSION_SECRET and ADMIN_PASSWORD in .env
npm install
npm run seed
npm start
```

Open `http://localhost:3000`.

- Admin: `http://localhost:3000/admin`
- Client portal: `http://localhost:3000/portal`

The seed command prints the configured admin account. Change the temporary password before any public deployment.

## Production checklist

1. Replace the sample contact details from the dashboard's **Site details** tab.
2. Replace `frontend/og-image.png` (1200×630), `frontend/favicon.svg` and `frontend/apple-touch-icon.png` with final brand artwork. The supplied files are built from the site's own palette and wordmark, not from a brand guideline.
3. Add original articles from the dashboard. The build intentionally does not invent customer claims; `npm run seed:samples` adds clearly-labelled placeholders for review, and `-- --remove` takes them out again.
4. Configure SMTP variables for live email notifications.
5. Set a strong `ADMIN_PASSWORD` and re-run the seed; the seed prints a warning if the configured one would fail the policy applied to client accounts.
6. Consider enabling `PWNED_CHECK=on` so new passwords are screened against known breaches. Review the outbound call to api.pwnedpasswords.com against your own data-handling policy first.
7. Set `TRUST_PROXY` to the number of reverse proxies actually in front of the app. It defaults to 1; too high and a caller can spoof their address via `X-Forwarded-For`, which is what rate limiting and audit logs key on.
8. Tune `API_RATE_LIMIT` and `AUTH_RATE_LIMIT` for your traffic. The defaults are deliberately far above human usage and exist only to blunt automated abuse.
9. Use HTTPS and a reverse proxy. Set `NODE_ENV=production`, `BASE_URL`, and a long random `SESSION_SECRET`.
10. Sessions are stored in SQLite and survive restarts. For several instances, point `DB_PATH` at shared storage or move the store to Redis.
11. Configure `MALWARE_SCAN=clamav` (the production Docker image includes ClamAV) and keep its signature database current. Uploads are scanned after signature verification and before they are moved to permanent local or object storage.
12. For object storage, set `STORAGE_DRIVER=s3` plus `S3_BUCKET`, credentials, and an optional `S3_ENDPOINT` for R2 or another S3-compatible provider. Buckets must be private; downloads remain authorized by the application.
13. Configure SMTP for password recovery and new-device/IP sign-in alerts. Reset tokens are random, stored only as SHA-256 hashes, single-use, and expire after `PASSWORD_RESET_TTL_MINUTES`.
14. Move SQLite to PostgreSQL for high concurrency or multi-instance hosting. New persistence code uses `backend/repository.js`; keep parameterised queries and add PostgreSQL migrations before switching `DB_DIALECT`.
15. Add backups, uptime monitoring, central logs and dependency vulnerability scanning. CI runs `npm audit --audit-level=critical` and fails on critical advisories.
14. Verify company address, telephone, email, hours, legal pages, privacy notice, cookie requirements and Google Maps consent before launch.
15. Run accessibility, browser, responsive, Core Web Vitals and penetration testing against the deployed environment.

## Important implementation notes

- No third-party benchmark copy, images or text are included.
- The empty resources state is deliberate. Publish verified business content through the dashboard rather than fabricating it.
- The core flows are implemented. Extended back-office screens for every database entity can be added without changing the underlying model.
- For production, pin reviewed dependency versions in a generated lockfile and run `npm audit` in CI.
- CSRF is implemented in `backend/security.js` rather than with `csurf`, which is archived upstream and no longer receives fixes. It is the signed double-submit cookie pattern: an httpOnly, HMAC-signed cookie plus the same token echoed in a header or form field, so a party who can only write cookies for the domain still cannot mint a valid pair.
- Two-step verification is optional per staff account and set up from the dashboard's Security tab. Enabling it for every account with `admin` or `super_admin` rights is worth doing before launch — those accounts can read every client record.
- Recovery codes are shown once and stored only as hashes. If a member of staff loses both their authenticator and their codes, an administrator has to clear `totp_enabled` and `totp_secret` for that row directly; there is no self-service reset.
- `backend/qr.js` is a byte-mode, error-correction-level-M QR encoder covering versions 1-10. It was checked module-for-module against the `qrcode` package across 660 generated matrices before that package was removed.
- Signature checking is not malware scanning. It establishes that a file is the format it claims to be; it does not establish that the file is safe. Scanning on ingest is still required before these documents are opened by staff.
- Password recovery is available at `/api/auth/forgot-password` and `/reset-password`; configure SMTP so the reset link and six-digit verification code can be delivered. The code is generated securely, stored only as a hash, expires with the reset link, and is single-use.
- Upload storage is selected through `STORAGE_DRIVER`. Local storage keeps the existing single-server behavior; the S3-compatible implementation works with AWS S3, Cloudflare R2 and compatible gateways. ClamAV is fail-closed when enabled.
- `backend/repository.js` is the portability boundary for new database work. The current application schema and session store remain SQLite-backed until a PostgreSQL migration is introduced.
- `seed.js` sets up structure — an administrator account, categories, the service catalogue — not content. Everything the public site shows is editable from the dashboard, and editing `seed.js` after the first run has no effect, because it inserts only what is missing.
- Password hashes written before the pre-hash change still verify, and are upgraded to the current scheme the next time that user signs in successfully.

## Suggested deployment

Use a Node.js host or container platform with persistent storage, HTTPS and environment secrets. Run `npm run seed` once, then `npm start`. For a scaled deployment, migrate the database and uploads as described above.

## Deploying on cPanel

cPanel runs Node applications under Passenger, which supplies `PORT` and fronts
the app with Apache. `app.listen(process.env.PORT)` and `TRUST_PROXY=1` already
match that, so no code changes are needed.

1. Upload the project outside `public_html` (for example `/home/<user>/wisepen`).
   Passenger serves the app itself; `public_html` is not used for its files.
2. cPanel > **Setup Node.js App** > Create Application:
   - Node.js version: 22 (the version in `.nvmrc`; ask the host to enable it if
     the list stops earlier — `better-sqlite3` needs a prebuilt binary or a
     compiler for the exact version chosen).
   - Application root: the upload folder. Application URL: the domain.
   - Application startup file: `backend/server.js`.
3. Add the environment variables from `.env.example` in that same screen, with
   `NODE_ENV=production`, the real `BASE_URL`, and a fresh `SESSION_SECRET`.
4. Run **NPM Install** from the app's page, or over SSH activate the virtualenv
   the page shows (`source /home/<user>/nodevenv/.../bin/activate`) and run
   `npm ci --omit=dev`.
5. Point `DB_PATH` and `UPLOAD_DIR` at writable paths outside `public_html`, and
   back both up — they hold every account, quote and uploaded file.
6. Run `npm run seed` once from the activated virtualenv, then **Restart** the
   app and change the seeded administrator password.
7. Issue SSL for the domain (cPanel > SSL/TLS Status, AutoSSL). Session and CSRF
   cookies are secure-only in production, so sign-in fails over plain HTTP.

Redeploying is: upload changed files, run NPM Install if dependencies moved,
then Restart. Shared hosts often block outbound SMTP to other providers; see the
mail notes in `.env.example` if Gmail times out.

### Without SSH or a terminal

Every step above has a button equivalent, so a plan with no shell can still run
the whole deployment. Nothing here is a workaround; these are the same commands,
started from the panel instead of a prompt.

**Uploading.** Build a zip of the project without `node_modules`, `.env`, the
database files or `.git`, then cPanel > **File Manager** > Upload, and
**Extract** it into the application root. `node_modules` is excluded on purpose:
`better-sqlite3` is a compiled binary and the copy built on your machine will
not necessarily match the host's Node build. The server installs its own.

The alternative is cPanel > **Git Version Control**: give it the repository URL,
set the checkout path to the application root, and afterwards each deploy is the
**Update from Remote** button. Worth the setup if this will be deployed often.

**Installing.** Setup Node.js App > your app > **Run NPM Install**. It reads
`package.json` from the application root and builds `better-sqlite3` against the
Node version the app is configured for.

**Running the one-off commands.** Setup Node.js App > your app > **Run JS
script** runs any script named in `package.json`, printing the output in the
panel. That covers all four that matter:

| Script | What it does |
| --- | --- |
| `env:check` | Names which settings the app can actually see. Run it first. |
| `seed` | Creates the tables and the administrator account. Run once. |
| `mail:test` | Sends one message, to prove SMTP works. |
| `reset:test` | Exercises the real forgot-password endpoint end to end. |

That button cannot pass arguments, so `mail:test` and `reset:test` also read
their target address from the environment — `MAIL_TEST_TO` and
`RESET_TEST_EMAIL`. Set the variable, Restart, run the script.

If your cPanel build has no **Run JS script** button, cPanel > **Cron Jobs**
does the same work: add a job set to run once, with the command that the Node.js
app page displays for entering the virtualenv, followed by the script — for
example `cd /home/<user>/wisepen && /home/<user>/nodevenv/wisepen/22/bin/npm run
seed`. Tick the option to email the output to yourself so you can read it, then
delete the job once it has run.

**Reading errors.** Setup Node.js App > your app > **Log**. Everything the
process writes to stdout and stderr lands there, including failed sends.

### Password reset email on cPanel

Nothing in the reset flow needs configuring; it needs a working mailbox. The
server generates a single-use link and a six-digit code, sends both to the
address held on the account, and never reveals whether an address is registered.

1. cPanel > **Email Accounts** > Create, e.g. `no-reply@<yourdomain>`.
2. Add to the application environment, then Restart:
   `SMTP_HOST=mail.<yourdomain>`, `SMTP_PORT=465`, `SMTP_SECURE=on`,
   `SMTP_USER` and `MAIL_FROM` set to that mailbox, `SMTP_PASS` its password.
   `BASE_URL` must be the live site — the reset link is built from it, so a
   stale value emails a link to localhost.
3. Prove the mailbox works at all:
   `npm run mail:test -- you@example.com`
   With no terminal: set `MAIL_TEST_TO` to that address alongside the SMTP
   settings, Restart, then Run JS script > `mail:test`. Failures print the
   likely cause, not just nodemailer's wording.
4. Prove the reset path works end to end:
   `npm run reset:test -- a.real.client@example.com`
   With no terminal: set `RESET_TEST_EMAIL`, Restart, then Run JS script >
   `reset:test`. It calls the live endpoint exactly as the browser does and
   reports whether a token row was created and whether mail is configured to
   carry it. Then check the inbox, open the link, and set a new password.
5. Remove `MAIL_TEST_TO` and `RESET_TEST_EMAIL` once both pass. They are
   test scaffolding and nothing should read them in normal operation.

If no email arrives, the send failure is logged by the application (cPanel >
Setup Node.js App > Log). Common causes: SMTP credentials wrong, the host
blocking the port, or the message sitting in spam because `MAIL_FROM` is not a
mailbox on your own domain.

`npm run reset:test -- someone@example.com --issue` prints a working reset link
and code without sending mail — or, with no terminal, `RESET_TEST_EMAIL` plus
`RESET_TEST_ISSUE=on` and Run JS script. Use it to get into an account while
SMTP is still being sorted out. It grants nothing new: whoever can run it
already holds the panel or the shell, and so could rewrite a password hash
directly. Clear `RESET_TEST_ISSUE` afterwards, so that a stray restart cannot
mint another link.
