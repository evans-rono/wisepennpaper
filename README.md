# The Wise Pen N’ Paper Business Platform

A full-stack publishing website, lead-management system, secure client portal and admin dashboard. The visual design is original and uses an editorial green, gold and paper-toned identity.

## Included

- Responsive public website with services, process, project portfolio, testimonials, client categories, resources, FAQs, contact and CTAs
- Database-backed service catalogue and site-wide search
- Three-step quote request workflow with reference generation and secure multi-file upload
- Contact and consultation booking workflows
- Client registration, login, project progress, milestones, quote, appointment and invoice views
- Admin authentication, business metrics, quote status management, appointment/contact views, and service creation
- Relational data model for users, clients, services, quotes, projects, milestones, files, appointments, portfolio, testimonials, blog, FAQs, messages, notifications, quotations, invoices, settings and audit logs
- Role-aware API protection, password hashing, CSRF tokens, rate limiting, security headers, validation, sanitisation, file allow-listing, upload size limits and audit logging
- SEO metadata, JSON-LD, sitemap and robots rules
- SMTP email notifications when configured

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

1. Replace all sample contact details and editable statistics in the `settings` table.
2. Add verified portfolio projects, testimonials and original blog content. The build intentionally does not invent customer claims.
3. Configure SMTP variables for live email notifications.
4. Use HTTPS and a reverse proxy. Set `NODE_ENV=production`, `BASE_URL`, and a long random `SESSION_SECRET`.
5. Replace the in-memory session store with Redis or another durable session store for multi-instance deployment.
6. Store uploads in private object storage with signed downloads and malware scanning. The local disk implementation is intended for a single-server deployment.
7. Move SQLite to PostgreSQL for high concurrency or multi-instance hosting. Keep parameterised queries and migrations.
8. Add a transactional email provider, backups, uptime monitoring, central logs and dependency vulnerability scanning.
9. Verify company address, telephone, email, hours, real statistics, legal pages, privacy notice, cookie requirements and Google Maps consent before launch.
10. Run accessibility, browser, responsive, Core Web Vitals and penetration testing against the deployed environment.

## Important implementation notes

- No third-party benchmark copy, images or text are included.
- Empty portfolio, testimonial and blog states are deliberate. Publish verified business content through the database/admin modules rather than fabricating it.
- The core flows are implemented. Extended back-office screens for every database entity can be added without changing the underlying model.
- For production, pin reviewed dependency versions in a generated lockfile and run `npm audit` in CI.

## Suggested deployment

Use a Node.js host or container platform with persistent storage, HTTPS and environment secrets. Run `npm run seed` once, then `npm start`. For a scaled deployment, migrate the database and uploads as described above.
