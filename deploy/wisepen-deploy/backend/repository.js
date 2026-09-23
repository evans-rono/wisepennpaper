import db from './db.js';

// New persistence code goes through this adapter so the rest of the app does
// not depend on a driver-specific connection or placeholder convention.
export const sql = (text, ...params) => db.prepare(text).all(...params);
export const one = (text, ...params) => db.prepare(text).get(...params);
export const run = (text, ...params) => db.prepare(text).run(...params);
export const transaction = (work) => db.transaction(work)();
export const dialect = process.env.DB_DIALECT || 'sqlite';
export default { sql, one, run, transaction, dialect };
