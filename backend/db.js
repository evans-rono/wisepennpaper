import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
const file = process.env.DB_PATH || 'wise-pen.db';
fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
const db = new Database(file);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN('super_admin','admin','staff','client')), created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS services(id INTEGER PRIMARY KEY, name TEXT NOT NULL, slug TEXT UNIQUE NOT NULL, summary TEXT NOT NULL, description TEXT NOT NULL, benefits TEXT DEFAULT '[]', process TEXT DEFAULT '[]', deliverables TEXT DEFAULT '[]', faqs TEXT DEFAULT '[]', turnaround TEXT, image TEXT, featured INTEGER DEFAULT 0, sort_order INTEGER DEFAULT 0, seo_title TEXT, meta_description TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS quote_requests(id INTEGER PRIMARY KEY, reference TEXT UNIQUE NOT NULL, user_id INTEGER, full_name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT NOT NULL, organisation TEXT, location TEXT, project_type TEXT NOT NULL, service_id INTEGER, project_title TEXT NOT NULL, description TEXT NOT NULL, target_audience TEXT, page_word_estimate TEXT, quantity INTEGER, expected_date TEXT, budget TEXT, status TEXT DEFAULT 'New', assigned_to INTEGER, admin_notes TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(service_id) REFERENCES services(id));
CREATE TABLE IF NOT EXISTS projects(id INTEGER PRIMARY KEY, reference TEXT UNIQUE NOT NULL, client_id INTEGER NOT NULL, title TEXT NOT NULL, description TEXT, status TEXT DEFAULT 'Assessment', progress INTEGER DEFAULT 10, assigned_to INTEGER, start_date TEXT, due_date TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(client_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS milestones(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, title TEXT NOT NULL, status TEXT DEFAULT 'pending', due_date TEXT, sort_order INTEGER DEFAULT 0, FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY, project_id INTEGER, quote_id INTEGER, uploaded_by INTEGER, original_name TEXT NOT NULL, stored_name TEXT NOT NULL, mime_type TEXT NOT NULL, size INTEGER NOT NULL, approved INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS appointments(id INTEGER PRIMARY KEY, reference TEXT UNIQUE NOT NULL, user_id INTEGER, full_name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT NOT NULL, consultation_type TEXT NOT NULL, preferred_date TEXT NOT NULL, preferred_time TEXT NOT NULL, project_info TEXT, status TEXT DEFAULT 'Pending', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS portfolio(id INTEGER PRIMARY KEY, title TEXT NOT NULL, slug TEXT UNIQUE NOT NULL, client TEXT, category TEXT NOT NULL, description TEXT NOT NULL, services_delivered TEXT DEFAULT '[]', completion_date TEXT, image TEXT, gallery TEXT DEFAULT '[]', outcome TEXT, featured INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS testimonials(id INTEGER PRIMARY KEY, client_name TEXT NOT NULL, organisation TEXT, testimonial TEXT NOT NULL, photo TEXT, rating INTEGER DEFAULT 5 CHECK(rating BETWEEN 1 AND 5), published INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, slug TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS blog_posts(id INTEGER PRIMARY KEY, title TEXT NOT NULL, slug TEXT UNIQUE NOT NULL, excerpt TEXT NOT NULL, content TEXT NOT NULL, featured_image TEXT, author_id INTEGER, category_id INTEGER, published_at TEXT, status TEXT DEFAULT 'draft', seo_title TEXT, meta_description TEXT, og_image TEXT, canonical_url TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS faqs(id INTEGER PRIMARY KEY, question TEXT NOT NULL, answer TEXT NOT NULL, category TEXT DEFAULT 'General', sort_order INTEGER DEFAULT 0, published INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS contact_messages(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT, subject TEXT NOT NULL, message TEXT NOT NULL, status TEXT DEFAULT 'Unread', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, user_id INTEGER, type TEXT NOT NULL, title TEXT NOT NULL, body TEXT, read_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS invoices(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, number TEXT UNIQUE NOT NULL, amount REAL NOT NULL, currency TEXT DEFAULT 'KES', status TEXT DEFAULT 'Draft', due_date TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS quotations(id INTEGER PRIMARY KEY, quote_request_id INTEGER NOT NULL, number TEXT UNIQUE NOT NULL, amount REAL NOT NULL, currency TEXT DEFAULT 'KES', status TEXT DEFAULT 'Sent', valid_until TEXT, notes TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, sender_id INTEGER NOT NULL, body TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT NOT NULL, entity TEXT NOT NULL, entity_id TEXT, ip TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS password_reset_tokens(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, token_hash TEXT UNIQUE NOT NULL, expires_at TEXT NOT NULL, used_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS login_devices(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, fingerprint TEXT NOT NULL, ip TEXT NOT NULL, user_agent TEXT, last_seen_at TEXT DEFAULT CURRENT_TIMESTAMP, created_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id,fingerprint), FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
`);
// Columns added after the initial schema. CREATE TABLE IF NOT EXISTS leaves an
// existing table untouched, so each one is added explicitly and only if absent.
const ADDED_COLUMNS = [
  ['users', 'totp_secret', 'TEXT'],
  ['users', 'totp_enabled', 'INTEGER DEFAULT 0'],
  ['users', 'totp_confirmed_at', 'TEXT'],
  ['users', 'recovery_codes', "TEXT DEFAULT '[]'"],
  ['users', 'last_totp_step', 'INTEGER'],
  ['users', 'last_login_at', 'TEXT'],
  ['users', 'sessions_valid_from', 'TEXT'],
  ['users', 'is_active', 'INTEGER DEFAULT 1'],
  ['users', 'created_by', 'INTEGER'],
  ['files', 'scan_status', "TEXT DEFAULT 'clean'"],
  ['files', 'storage_driver', "TEXT DEFAULT 'local'"],
  ['password_reset_tokens', 'code_hash', 'TEXT'],
];
for (const [table, column, definition] of ADDED_COLUMNS) {
  const present = db.prepare(`PRAGMA table_info(${table})`).all().some((c) => c.name === column);
  if (!present) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}

export default db;
