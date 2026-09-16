// Sends one test message so SMTP settings can be verified without signing up a
// user: npm run mail:test you@example.com
import 'dotenv/config';
import { sendMail } from './mailer.js';

const to = process.argv[2];
if (!to) { console.error('Usage: npm run mail:test -- you@example.com'); process.exit(1); }
if (!process.env.SMTP_HOST) { console.error('SMTP_HOST is not set: nothing would be sent.'); process.exit(1); }

try {
  await sendMail({
    to,
    subject: 'Wise Pen N’ Paper SMTP test',
    text: `Sent from ${process.env.SMTP_HOST} as ${process.env.MAIL_FROM || process.env.SMTP_USER}.`,
  });
  console.log(`Sent to ${to}. Check the inbox, and the spam folder if it is not there.`);
} catch (error) {
  console.error('Send failed:', error.message);
  process.exit(1);
}
