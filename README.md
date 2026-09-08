# The Wise Pen N’ Paper Business Platform

A full-stack publishing website, lead-management system, secure client portal and admin dashboard. The visual design is original and uses an editorial green, gold and paper-toned identity.

## Included

- Responsive public website with services, process, project portfolio, testimonials, client categories, resources, FAQs, contact and CTAs
- Server-rendered public pages: services, portfolio, testimonials, FAQs, articles, statistics and contact details are in the delivered HTML, so they are crawlable and readable before any script runs
- Indexable service pages at `/services/<slug>`, listed in the sitemap, with per-service metadata and `Service` + `BreadcrumbList` structured data
- Progressive enhancement: the quote, contact and consultation forms post natively and confirm on a server-rendered page when JavaScript is unavailable
- Database-backed service catalogue and site-wide search
- Three-step quote request workflow with reference generation and secure multi-file upload
- Contact and consultation booking workflows
- Client registration, login, project progress, milestones, quote, appointment and invoice views
- Staff dashboard: business metrics, quote requests with full detail and downloadable attachments, internal notes, appointment and enquiry status management, an activity log for administrators, and paging throughout
- Content management for everything the public site shows: services, portfolio, testimonials, FAQs and articles, plus a Site details screen for contact information and the homepage statistics. Nothing on the public site now requires hand-written SQL to change
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

1. Replace the sample contact details and add real statistics from the dashboard's **Site details** tab.
2. Replace `frontend/og-image.png` (1200×630), `frontend/favicon.svg` and `frontend/apple-touch-icon.png` with final brand artwork. The supplied files are built from the site's own palette and wordmark, not from a brand guideline.
3. Add verified portfolio projects, testimonials and original articles from the dashboard. The build intentionally does not invent customer claims.
4. Configure SMTP variables for live email notifications.
5. Set a strong `ADMIN_PASSWORD` and re-run the seed; the seed prints a warning if the configured one would fail the policy applied to client accounts.
6. Consider enabling `PWNED_CHECK=on` so new passwords are screened against known breaches. Review the outbound call to api.pwnedpasswords.com against your own data-handling policy first.
7. Set `TRUST_PROXY` to the number of reverse proxies actually in front of the app. It defaults to 1; too high and a caller can spoof their address via `X-Forwarded-For`, which is what rate limiting and audit logs key on.
8. Tune `API_RATE_LIMIT` and `AUTH_RATE_LIMIT` for your traffic. The defaults are deliberately far above human usage and exist only to blunt automated abuse.
9. Use HTTPS and a reverse proxy. Set `NODE_ENV=production`, `BASE_URL`, and a long random `SESSION_SECRET`.
10. Sessions are stored in SQLite and survive restarts. For several instances, point `DB_PATH` at shared storage or move the store to Redis.
11. Store uploads in private object storage with signed downloads and malware scanning. The local disk implementation is intended for a single-server deployment.
12. Move SQLite to PostgreSQL for high concurrency or multi-instance hosting. Keep parameterised queries and migrations.
13. Add a transactional email provider, backups, uptime monitoring, central logs and dependency vulnerability scanning.
14. Verify company address, telephone, email, hours, real statistics, legal pages, privacy notice, cookie requirements and Google Maps consent before launch.
15. Run accessibility, browser, responsive, Core Web Vitals and penetration testing against the deployed environment.

## Important implementation notes

- No third-party benchmark copy, images or text are included.
- Empty portfolio, testimonial and blog states are deliberate. Publish verified business content through the dashboard rather than fabricating it.
- The core flows are implemented. Extended back-office screens for every database entity can be added without changing the underlying model.
- For production, pin reviewed dependency versions in a generated lockfile and run `npm audit` in CI.
- CSRF is implemented in `backend/security.js` rather than with `csurf`, which is archived upstream and no longer receives fixes. It is the signed double-submit cookie pattern: an httpOnly, HMAC-signed cookie plus the same token echoed in a header or form field, so a party who can only write cookies for the domain still cannot mint a valid pair.
- Two-step verification is optional per staff account and set up from the dashboard's Security tab. Enabling it for every account with `admin` or `super_admin` rights is worth doing before launch — those accounts can read every client record.
- Recovery codes are shown once and stored only as hashes. If a member of staff loses both their authenticator and their codes, an administrator has to clear `totp_enabled` and `totp_secret` for that row directly; there is no self-service reset.
- `backend/qr.js` is a byte-mode, error-correction-level-M QR encoder covering versions 1-10. It was checked module-for-module against the `qrcode` package across 660 generated matrices before that package was removed.
- Signature checking is not malware scanning. It establishes that a file is the format it claims to be; it does not establish that the file is safe. Scanning on ingest is still required before these documents are opened by staff.
- There is no forgot-password flow, and no sign-in alert email. Both need working SMTP, which is not configured; they were left out rather than half-built. An administrator can clear a colleague's second factor from the Team screen, but cannot reset a password from the interface.
- `seed.js` sets up structure — an administrator account, categories, the service catalogue — not content. Everything the public site shows is editable from the dashboard, and editing `seed.js` after the first run has no effect, because it inserts only what is missing.
- Password hashes written before the pre-hash change still verify, and are upgraded to the current scheme the next time that user signs in successfully.

## Suggested deployment

Use a Node.js host or container platform with persistent storage, HTTPS and environment secrets. Run `npm run seed` once, then `npm start`. For a scaled deployment, migrate the database and uploads as described above.
