// Sample articles for the resources block, which is empty on a fresh install.
//
//   npm run seed:samples            add it
//   npm run seed:samples -- --remove   take it back out
//
// This is placeholder material so the sections can be seen, styled and reviewed
// before there is real work to show. None of it is true of the business, so it
// is kept out of the main seed and refuses to touch a production database
// without --force. Replace every entry through the admin dashboard before the
// site goes live.

import 'dotenv/config';
import slugify from 'slugify';
import db from './db.js';

const args = new Set(process.argv.slice(2));
const remove = args.has('--remove');

if (process.env.NODE_ENV === 'production' && !args.has('--force')) {
  console.error('Refusing to run against a production database. Re-run with --force if that is really what you want.');
  process.exit(1);
}

const POSTS = [
  ['What a developmental edit actually changes', 'Editing',
   'A developmental edit works on structure, argument and pacing — not commas. Here is what to expect from one, and when your manuscript is ready for it.',
   'A developmental edit is the first real read your manuscript gets as a book rather than as a draft.\n\nIt looks at whether the structure carries the argument, whether the opening earns the reader’s attention, whether chapters end where they should, and whether the voice holds across the whole work. None of that is about grammar; line editing and proofreading come later, and doing them first means paying to polish sentences that may not survive.\n\nYour manuscript is ready for a developmental edit when it is complete enough to be read end to end, even if parts are rough. What you receive back is an editorial report setting out what is working, what is not, and a recommended order for fixing it.'],
  ['Budgeting a self-funded book in Kenya', 'Publishing Tips',
   'Editorial, design, proofing and printing each carry their own costs. A realistic breakdown of where the money goes, and which stages repay the spend.',
   'The commonest mistake a first-time author makes is budgeting for printing and treating everything before it as optional.\n\nPrinting is the one cost that is easy to quote and easy to understand, so it anchors the whole budget. But a clean print run of a book that was never edited simply produces a thousand tidy copies of the same problems.\n\nPlan in stages: an editorial assessment first, so you know what the book needs; then editing; then design and layout; then a proofread of the laid-out pages, which catches what no one can see in a manuscript; then production. Each stage should close with something you can look at before the next begins. That way the budget follows decisions you have already made rather than guesses.'],
  ['Preparing files a printer will accept', 'Book Design',
   'Bleed, trim, margins, embedded fonts and colour space. The handful of specifications that decide whether a print run goes smoothly.',
   'Most print delays are not design problems. They are file problems, and they are the same few every time.\n\nBleed: any element meant to reach the edge of the page must extend past the trim line, usually by 3mm. Margins: text set too close to the spine disappears into the binding, and the wider the book, the worse it gets. Fonts: embed them, or the printer’s machine substitutes something else and the pages reflow. Colour: print is CMYK, and a cover designed in RGB will not look on paper the way it looked on screen.\n\nAsk your printer for their specification sheet before the layout starts rather than after it finishes. Ten minutes at the beginning saves a re-export, a re-proof and a week.'],
];

const postSlugs = POSTS.map(([title]) => slugify(title, { lower: true, strict: true }));

if (remove) {
  const gone = (label, info) => console.log(`  removed ${info.changes} ${label}`);
  const holes = (n) => Array(n).fill('?').join(',');
  gone('articles', db.prepare(`DELETE FROM blog_posts WHERE slug IN (${holes(postSlugs.length)})`).run(...postSlugs));
  db.close();
  console.log('\nSample content removed. The resources block is empty again.');
  process.exit(0);
}

const author = db.prepare("SELECT id FROM users WHERE role='super_admin' ORDER BY id LIMIT 1").get();
if (!author) {
  console.error('No administrator account found. Run `npm run seed` first.');
  process.exit(1);
}

const categoryId = db.prepare('SELECT id FROM categories WHERE name=?');
const addPost = db.prepare(`INSERT OR IGNORE INTO blog_posts
  (title,slug,excerpt,content,author_id,category_id,published_at,status,seo_title,meta_description)
  VALUES(?,?,?,?,?,?,?,'published',?,?)`);
POSTS.forEach(([title, category, excerpt, content], i) =>
  addPost.run(title, postSlugs[i], excerpt, content, author.id, categoryId.get(category)?.id ?? null,
    new Date(Date.now() - i * 86_400_000 * 9).toISOString().slice(0, 10),
    `${title} | Wise Pen N’ Paper`, excerpt.slice(0, 155)));

const count = (t) => db.prepare(`SELECT COUNT(*) n FROM ${t}`).get().n;
console.log(`Sample content added. Articles: ${count('blog_posts')}.`);
console.log(`
  These are placeholders, not records of work done. Before this site goes live,
  replace them in the admin dashboard:

    Articles  — replace these with your own writing

  \`npm run seed:samples -- --remove\` takes all of it back out.`);

db.close();
