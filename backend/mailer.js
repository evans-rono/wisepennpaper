import nodemailer from 'nodemailer';

let transport;
const getTransport = () => {
  if (!process.env.SMTP_HOST) return null;
  transport ??= nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === 'on',
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
  });
  return transport;
};

export async function sendMail({ to, subject, text }) {
  const smtp = getTransport();
  if (!smtp) {
    if (process.env.NODE_ENV === 'production') throw new Error('SMTP is not configured');
    return false;
  }
  // Gmail rewrites From to the authenticated mailbox unless the address is a
  // verified "Send mail as" alias, so fall back to the SMTP account itself.
  const from = process.env.MAIL_FROM || process.env.SMTP_USER;
  await smtp.sendMail({ from, to, subject, text });
  return true;
}

export async function sendPasswordReset({ to, name, url, code, ttlMinutes = 30 }) {
  return sendMail({
    to,
    subject: 'Reset your Wise Pen N’ Paper password',
    text: `Hello ${name || 'there'},\n\nYour password reset verification code is: ${code}\n\nUse this link to reset your password:\n${url}\n\nThe code and link expire in ${ttlMinutes} minutes and can only be used once. If you did not request this, you can ignore this email.`,
  });
}

export async function sendSignInAlert({ to, name, ip, userAgent, time }) {
  return sendMail({
    to,
    subject: 'New sign-in to your Wise Pen N’ Paper account',
    text: `Hello ${name || 'there'},\n\nYour account was signed in from a new device or network.\n\nTime: ${time}\nIP: ${ip}\nBrowser: ${userAgent || 'Unknown'}\n\nIf this was not you, change your password immediately.`,
  });
}

export const resetTransportForTests = () => { transport = undefined; };
