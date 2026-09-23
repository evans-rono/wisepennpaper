import { parsePhoneNumberFromString } from 'libphonenumber-js/max';

export const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

export function normaliseEmail(value) {
  const email = String(value ?? '').trim().toLowerCase();
  return EMAIL_RE.test(email) ? email : null;
}

export function normalisePhone(value, country = 'KE') {
  const raw = String(value ?? '').trim();
  const phone = parsePhoneNumberFromString(raw, String(country || 'KE').toUpperCase());
  if (!phone || !phone.isValid()) return null;
  return phone.number;
}

export function timezoneOffset(value) {
  const minutes = Number(value);
  return Number.isInteger(minutes) && minutes >= -840 && minutes <= 840 ? minutes : null;
}

export function parseClientDateTime(date, time, offsetMinutes) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(date ?? '')) || !/^\d{2}:\d{2}$/.test(String(time ?? ''))) return null;
  const offset = timezoneOffset(offsetMinutes);
  const suffix = offset === null ? '' : (() => {
    const absolute = Math.abs(offset);
    const hours = Math.floor(absolute / 60);
    const minutes = absolute % 60;
    return `${offset <= 0 ? '+' : '-'}${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}`;
  })();
  const parsed = new Date(`${date}T${time}:00${suffix}`);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export function currentDateInputValue() {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
}

export function isPastCalendarDate(value) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(value ?? '')) && String(value) < currentDateInputValue();
}
