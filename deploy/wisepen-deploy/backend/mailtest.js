// Sends one test message so SMTP settings can be verified without signing up a
// user: npm run mail:test you@example.com
//
// cPanel's "Run JS script" button cannot pass arguments, and shared plans often
// have no terminal at all, so the address may also arrive as MAIL_TEST_TO in
// the application's environment variables.
import 'dotenv/config';
import { sendMail } from './mailer.js';

const to = process.argv[2] || process.env.MAIL_TEST_TO;
if (!to) {
  console.error('No address given. Pass one (npm run mail:test -- you@example.com),');
  console.error('or set MAIL_TEST_TO in the environment and run the script with no arguments.');
  process.exit(1);
}
if (!process.env.SMTP_HOST) { console.error('SMTP_HOST is not set: nothing would be sent.'); process.exit(1); }

console.log(`Host        ${process.env.SMTP_HOST}:${process.env.SMTP_PORT || 587} (secure ${process.env.SMTP_SECURE === 'on' ? 'on' : 'off'})`);
console.log(`From        ${process.env.MAIL_FROM || process.env.SMTP_USER}`);
console.log(`To          ${to}\n`);

try {
  await sendMail({
    to,
    subject: 'Wise Pen N’ Paper SMTP test',
    text: `Sent from ${process.env.SMTP_HOST} as ${process.env.MAIL_FROM || process.env.SMTP_USER}.`,
  });
  console.log(`Sent to ${to}. Check the inbox, and the spam folder if it is not there.`);
} catch (error) {
  console.error('Send failed:', error.message);
  // The three failures that actually happen on shared hosting, in the order
  // they bite. Nodemailer's own message names the symptom, not the cause.
  if (/ETIMEDOUT|ECONNREFUSED|EHOSTUNREACH/.test(error.message)) {
    console.error('\nThe host is blocking this port outbound, or nothing is listening on it.');
    console.error('Shared cPanel plans routinely block SMTP to outside providers: create a');
    console.error('mailbox under cPanel > Email Accounts and point SMTP_HOST at mail.<yourdomain>.');
  }
  if (/Invalid login|535|534|Username and Password not accepted/i.test(error.message)) {
    console.error('\nCredentials refused. For Gmail this must be a 16-character App Password');
    console.error('with the spaces removed, never the account password.');
  }
  if (/self.signed|certificate|wrong version number/i.test(error.message)) {
    console.error('\nTLS mismatch. SMTP_SECURE must match the port: on for 465, off for 587.');
  }
  process.exit(1);
}
