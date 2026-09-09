import 'dotenv/config'; import path from 'node:path'; import fs from 'node:fs'; import crypto from 'node:crypto'; import express from 'express'; import helmet from 'helmet'; import rateLimit from 'express-rate-limit'; import session from 'express-session'; import cookieParser from 'cookie-parser'; import multer from 'multer'; import sanitizeHtml from 'sanitize-html'; import slugify from 'slugify'; import { z } from 'zod'; import db from './db.js'; import { renderHome, renderService, renderNotFound, renderThanks, renderAdmin, serviceBySlug, serviceSlugs, baseUrl } from './render.js'; import { hashPassword, verifyPassword, needsRehash, assessPassword, isBreached, MIN_LENGTH, MAX_LENGTH } from './password.js'; import { SqliteSessionStore, lockedFor, recordFailure, clearFailures, retryMessage } from './store.js'; import { createCsrf, verifyUploads, safeFileName } from './security.js'; import { scanAndRemove } from './malware.js'; import { downloadUpload } from './storage.js'; import { sendMail, sendPasswordReset, sendSignInAlert } from './mailer.js'; import { generateSecret, generateCode, verifyCode, otpauthUri, formatSecret, generateRecoveryCodes, hashRecoveryCode, consumeRecoveryCode } from './totp.js'; import { toSvg } from './qr.js'; import { googleEnabled, authorisationUrl, exchangeCode, verifyIdToken, refuseReason } from './google.js'; import { normaliseEmail, normalisePhone, parseClientDateTime, isPastCalendarDate } from './validation.js';
const app=express(), root=path.resolve('.'), uploads=path.join(root,'uploads'); fs.mkdirSync(uploads,{recursive:true});
if(process.env.NODE_ENV==='production'){const missing=['SESSION_SECRET'].filter(k=>!process.env[k]||process.env[k].length<32); if(process.env.MALWARE_SCAN==='off')missing.push('MALWARE_SCAN'); if(process.env.STORAGE_DRIVER&&process.env.STORAGE_DRIVER!=='local')missing.push(...['S3_BUCKET','S3_ACCESS_KEY_ID','S3_SECRET_ACCESS_KEY'].filter(k=>!process.env[k])); if(missing.length){console.error(`Refusing to start: ${missing.join(', ')} must be configured in production.`); process.exit(1);}}
const sessionSecret=process.env.SESSION_SECRET||crypto.randomBytes(32).toString('hex'); if(!process.env.SESSION_SECRET)console.warn('SESSION_SECRET is not set. Using a random development secret; sessions will not survive a restart.');
app.disable('x-powered-by');
// Number of proxies in front of the app. req.ip (and therefore rate limiting
// and audit logs) is read from X-Forwarded-For, so this must match the real
// deployment: too high and a caller can spoof their address by sending the
// header themselves. Set TRUST_PROXY=0 when the app is exposed directly.
if(process.env.NODE_ENV==='production') app.set('trust proxy',Number(process.env.TRUST_PROXY??1));
// No 'unsafe-inline' for styles: the admin and portal pages moved their inline
// <style> blocks into dashboard.css, and the one dynamic style (the portal
// progress bar) is set through the CSSOM, which the policy does not restrict.
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],styleSrc:["'self'",'https://fonts.googleapis.com'],fontSrc:["'self'",'https://fonts.gstatic.com'],imgSrc:["'self'",'data:'],scriptSrc:["'self'"],connectSrc:["'self'"],formAction:["'self'"],frameAncestors:["'none'"],objectSrc:["'none'"],baseUri:["'self'"],frameSrc:["'none'"],workerSrc:["'self'"],manifestSrc:["'self'"],upgradeInsecureRequests:process.env.NODE_ENV==='production'?[]:null}},referrerPolicy:{policy:'strict-origin-when-cross-origin'},hsts:{maxAge:31536000,includeSubDomains:true,preload:false},crossOriginOpenerPolicy:{policy:'same-origin'},crossOriginResourcePolicy:{policy:'same-origin'}}));
// Helmet does not set this one. The site uses none of these capabilities, so
// deny them outright rather than leaving them available to injected content.
app.use((req,res,next)=>{res.setHeader('Permissions-Policy','accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), usb=(), interest-cohort=()'); next();});
app.use(express.json({limit:'200kb'})); app.use(express.urlencoded({extended:false,limit:'200kb'})); app.use(cookieParser());
// Normalize contact data once, before route schemas and database writes see it.
const normalizeFormContact=(req,res,next)=>{
  const target=req.path==='/api/auth/register'||req.path==='/api/contact'||req.path==='/api/appointments'||req.path==='/api/client/profile'||req.path.startsWith('/api/admin/users');
  if(!target||!['POST','PATCH'].includes(req.method)||!req.body||typeof req.body!=='object')return next();
  if('email' in req.body){const email=normaliseEmail(req.body.email); if(!email)return res.status(400).json({error:'Enter a valid email address.',field:'email'}); req.body.email=email;}
  if('phone' in req.body&&String(req.body.phone).trim()){
    const phone=normalisePhone(req.body.phone,req.body.phone_country||'KE');
    if(!phone)return res.status(400).json({error:'Enter a valid phone number for the selected country.',field:'phone'});
    req.body.phone=phone;
  }
  if(req.path==='/api/appointments'){
    if(isPastCalendarDate(req.body.preferred_date))return res.status(400).json({error:'Choose today or a future date.',field:'preferred_date'});
    const selected=parseClientDateTime(req.body.preferred_date,req.body.preferred_time,req.body.timezone_offset);
    if(!selected)return res.status(400).json({error:'Choose a valid consultation date and time.',field:'preferred_date'});
    if(selected.getTime()<=Date.now())return res.status(400).json({error:'Choose a future consultation time.',field:'preferred_date'});
  }
  if(req.path==='/api/quotes'&&isPastCalendarDate(req.body.expected_date))
    return res.status(400).json({error:'Expected completion date cannot be in the past.',field:'expected_date'});
  next();
};
app.use(normalizeFormContact);
// Sessions live in SQLite, not process memory: a restart or deploy no longer
// signs everybody out, and more than one instance can share them.
const SESSION_TTL_MS=8*60*60*1000;
app.use(session({name:'wpnp.sid',secret:sessionSecret,resave:false,saveUninitialized:false,store:new SqliteSessionStore({ttlMs:SESSION_TTL_MS}),cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:SESSION_TTL_MS}}));
// The limiters exist to stop automated abuse, not to ration ordinary use, so
// the thresholds sit far above anything a person generates: signed-in staff are
// skipped entirely, and only *failed* credential attempts count. Both ceilings
// are env-overridable. The per-account backoff in store.js is what actually
// stops targeted brute-force; these are the blunt outer guard.
const signedIn=req=>!!req.session?.user;
app.use('/api',rateLimit({windowMs:60_000,limit:Number(process.env.API_RATE_LIMIT)||600,skip:signedIn,standardHeaders:'draft-7',legacyHeaders:false}));
const CREDENTIAL_ROUTES=new Set(['/api/auth/login','/api/auth/register','/api/auth/password','/api/auth/forgot-password','/api/auth/reset-password']);
const credentialLimiter=rateLimit({windowMs:15*60_000,limit:Number(process.env.AUTH_RATE_LIMIT)||50,skipSuccessfulRequests:true,standardHeaders:'draft-7',legacyHeaders:false});
app.use((req,res,next)=>CREDENTIAL_ROUTES.has(req.path)?credentialLimiter(req,res,next):next());
// Credentials and session state must never sit in a shared or browser cache.
const NO_STORE=/^\/api\/(auth|session|csrf|admin|client)(\/|$)/;
app.use((req,res,next)=>{if(NO_STORE.test(req.path))res.setHeader('Cache-Control','no-store'); next();});
const csrf=createCsrf({secret:sessionSecret,secure:process.env.NODE_ENV==='production'});
// The bare templates are not pages; only their rendered form is. Must sit ahead
// of the static handler, which would otherwise serve them unfilled.
const TEMPLATES=new Set(['/index.html','/page.html','/admin.html']);
app.use((req,res,next)=>TEMPLATES.has(req.path)?res.status(404).type('html').send(renderNotFound(req)):next());
// Long-lived caching for content-addressed assets only. Scripts, styles and
// markup revalidate, so a deploy reaches returning visitors immediately instead
// of leaving them on a day-old bundle.
app.use(express.static(path.join(root,'frontend'),{index:false,setHeaders(res,p){res.setHeader('Cache-Control',/\.(?:js|css|html)$/i.test(p)?'no-cache':'public, max-age=31536000, immutable');}}));
// Static assets are served above this line so they never pick up a CSRF cookie:
// a Set-Cookie header on an immutable asset stops shared caches storing it.
// Rendered pages need a token so their forms can carry a hidden _csrf field and
// keep working without JavaScript, so every remaining request gets one issued.
app.use(csrf.issue);
// The multipart quote POST is the one route that cannot verify here: the token
// travels in the form body, which multer has not parsed yet. It runs csrf.verify
// itself, after the upload middleware.
app.use((req,res,next)=>(req.method==='POST'&&req.path==='/api/quotes')?next():csrf.verify(req,res,next));
const clean=v=>sanitizeHtml(String(v??''),{allowedTags:[],allowedAttributes:{}}).trim(); const ref=p=>`${p}-${new Date().getFullYear()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`; const audit=(req,a,e,id)=>db.prepare('INSERT INTO audit_logs(user_id,action,entity,entity_id,ip) VALUES(?,?,?,?,?)').run(req.session.user?.id||null,a,e,String(id||''),req.ip);
const notify=async(subject,text)=>{if(!process.env.ALERT_EMAIL)return; await sendMail({to:process.env.ALERT_EMAIL,subject,text});};
const hashResetToken=token=>crypto.createHash('sha256').update(token).digest('hex');
const hashResetCode=code=>crypto.createHash('sha256').update(String(code)).digest('hex');
const loginFingerprint=req=>crypto.createHash('sha256').update(`${req.get('user-agent')||''}|${req.ip}`).digest('hex');
const notifyLogin=async(req,user)=>{
  const fingerprint=loginFingerprint(req); const existing=db.prepare('SELECT * FROM login_devices WHERE user_id=? AND fingerprint=?').get(user.id,fingerprint);
  const priorIp=db.prepare('SELECT ip FROM login_devices WHERE user_id=? ORDER BY last_seen_at DESC LIMIT 1').get(user.id)?.ip;
  db.prepare('INSERT INTO login_devices(user_id,fingerprint,ip,user_agent) VALUES(?,?,?,?) ON CONFLICT(user_id,fingerprint) DO UPDATE SET ip=excluded.ip,user_agent=excluded.user_agent,last_seen_at=CURRENT_TIMESTAMP').run(user.id,fingerprint,req.ip,req.get('user-agent')||'');
  if(!existing||priorIp!==req.ip) await sendSignInAlert({to:user.email,name:user.name,ip:req.ip,userAgent:req.get('user-agent'),time:new Date().toISOString()});
};
const STAFF_ROLES=['super_admin','admin','staff'];
// Roles that may not operate without a second factor. These accounts can read
// every client record, so the requirement is not optional for them.
const REQUIRE_2FA_ROLES=process.env.REQUIRE_ADMIN_2FA==='off'?[]:['super_admin','admin'];
const mustEnrol=u=>REQUIRE_2FA_ROLES.includes(u.role)&&!u.totp_enabled;
const ENROLMENT_PATHS=new Set(['/api/auth/2fa/status','/api/auth/2fa/setup','/api/auth/2fa/enable','/api/auth/logout']);
const auth=(...roles)=>{const allowed=roles.flat(); return (req,res,next)=>{const u=req.session.user;
  if(!u)return res.status(401).json({error:'Authentication required'});
  if(allowed.length&&!allowed.includes(u.role))return res.status(403).json({error:'Not authorised'});
  // "Sign out everywhere" moves this cutoff forward; any session opened before
  // it is no longer trusted, on this device or any other.
  const row=db.prepare('SELECT sessions_valid_from,is_active,totp_enabled FROM users WHERE id=?').get(u.id);
  // A deactivated account stops working on its very next request, without
  // waiting for the session to expire.
  if(!row||row.is_active===0)return req.session.destroy(()=>res.status(401).json({error:'This account is no longer active.'}));
  if(row.sessions_valid_from&&(!u.startedAt||u.startedAt<row.sessions_valid_from))return req.session.destroy(()=>res.status(401).json({error:'You were signed out. Please sign in again.'}));
  // An admin who has not set up a second factor can reach the enrolment
  // endpoints and sign out. Nothing else. Allowlisted here rather than in a
  // wrapper, so a route added later cannot forget the check.
  if(mustEnrol({role:u.role,totp_enabled:row.totp_enabled})&&!ENROLMENT_PATHS.has(req.path))
    return res.status(403).json({error:'Set up two-step verification before using the dashboard.',code:'2FA_REQUIRED'});
  next();};};
// No part of the stored name comes from the uploader; verifyUploads appends the
// extension for the type the bytes actually turn out to be.
const storage=multer.diskStorage({destination:uploads,filename:(req,file,cb)=>cb(null,`${Date.now()}-${crypto.randomBytes(12).toString('hex')}`)}); const allowed=new Set(['application/pdf','application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document','image/jpeg','image/png']); // This filter only screens the declared type to avoid writing obvious junk to
// disk. It is not the security boundary -- verifyUploads is, because a client
// can put any Content-Type it likes on any bytes.
const upload=multer({storage,limits:{fileSize:15*1024*1024,files:5,fields:40},fileFilter:(r,f,cb)=>cb(null,allowed.has(f.mimetype))});
const scanUploads=(req,res,next)=>Promise.all((req.files||[]).map(scanAndRemove)).then(()=>next(),next);
app.use((req,res,next)=>{
  if(req.method!=='POST'||req.path!=='/api/quotes'||!req.is('multipart/form-data'))return next();
  upload.array('files',5)(req,res,(err)=>{
    if(err)return next(err);
    const email=normaliseEmail(req.body.email); const phone=normalisePhone(req.body.phone,req.body.phone_country||'KE');
    if(!email)return res.status(400).json({error:'Enter a valid email address.',field:'email'});
    if(!phone)return res.status(400).json({error:'Enter a valid phone number for the selected country.',field:'phone'});
    req.body.email=email; req.body.phone=phone; req.quoteMultipartParsed=true; req.headers['content-type']='application/json'; next();
  });
});
app.get('/api/csrf',(req,res)=>res.json({csrfToken:req.csrfToken()})); app.get('/api/session',(req,res)=>res.json({user:req.session.user||null}));
// fetch() sends "Accept: */*", a browser form post sends text/html. That is how
// we tell a scripted submission from a no-JavaScript one.
const wantsHtml=req=>req.accepts(['json','html'])==='html';
// Carries the confirmation across the redirect that follows a native form post,
// so the reference never has to travel in a query string.
const thank=(req,res,payload)=>{req.session.flash=payload; req.session.save(()=>res.redirect(303,'/thank-you'));};
const failHtml=(req,res,message)=>{req.session.flash={heading:'We could not send that',message,error:true}; req.session.save(()=>res.redirect(303,'/thank-you'));};
// Starts a clean session and attaches the user, so a session id an attacker
// planted before sign-in cannot be reused afterwards.
const publicUser=(u,startedAt=new Date().toISOString())=>({id:u.id,name:u.name,email:u.email,phone:u.phone,role:u.role,startedAt,
  twoFactor:!!u.totp_enabled,mustEnrol:mustEnrol(u)});
const startSession=(req,res,user,status=200,startedAt)=>req.session.regenerate(err=>{if(err)return res.status(500).json({error:'Could not start session'}); req.session.user=publicUser(user,startedAt); db.prepare('UPDATE users SET last_login_at=CURRENT_TIMESTAMP WHERE id=?').run(user.id); notifyLogin(req,user).catch(e=>console.error('sign-in alert failed',e)); res.status(status).json({ok:true,user:req.session.user});});
// Length, screening and the optional breach lookup, in that order.
const checkPassword=async(password,context)=>{const verdict=assessPassword(password,context); if(!verdict.ok)return verdict.problem; if(await isBreached(password))return 'This password has appeared in a known data breach. Please choose a different one.'; return null;};
const requestEmail=(value)=>normaliseEmail(value);
const requestPhone=(value,country)=>{const raw=String(value??''); const [embeddedCountry,number]=raw.includes(':')?raw.split(/:(.*)/s):[country,raw]; return normalisePhone(number,embeddedCountry||'KE');};

app.post('/api/auth/register',async(req,res)=>{try{const d=z.object({name:z.string().trim().min(2),email:z.string(),phone:z.string().min(1),password:z.string().min(MIN_LENGTH).max(MAX_LENGTH)}).parse(req.body); const email=requestEmail(d.email); if(!email)return res.status(400).json({error:'Enter a valid email address.',field:'email'}); const phone=requestPhone(d.phone,req.body.phone_country); if(!phone)return res.status(400).json({error:'Enter a valid phone number for the selected country.',field:'phone'}); const problem=await checkPassword(d.password,{email,name:d.name}); if(problem)return res.status(400).json({error:problem,field:'password'}); const info=db.prepare('INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?,?)').run(clean(d.name),email,phone,await hashPassword(d.password),'client'); audit(req,'register','user',info.lastInsertRowid); startSession(req,res,{id:info.lastInsertRowid,name:clean(d.name),email,phone,role:'client'},201);}catch(e){if(e.code==='SQLITE_CONSTRAINT_UNIQUE')return res.status(409).json({error:'Email is already registered',field:'email'}); res.status(400).json({error:`Check the registration details. Passwords need at least ${MIN_LENGTH} characters.`});}});

app.post('/api/auth/forgot-password',async(req,res)=>{
  const email=requestEmail(req.body.email); const user=email?db.prepare('SELECT id,name,email,is_active FROM users WHERE email=?').get(email):null;
  if(user?.is_active!==0){
    const token=crypto.randomBytes(32).toString('base64url');
    const code=String(crypto.randomInt(0,1_000_000)).padStart(6,'0');
    const ttl=Math.max(Number(process.env.PASSWORD_RESET_TTL_MINUTES)||30,5);
    db.prepare('DELETE FROM password_reset_tokens WHERE user_id=? OR expires_at<?').run(user?.id||0,new Date().toISOString());
    if(user){
      db.prepare('INSERT INTO password_reset_tokens(user_id,token_hash,code_hash,expires_at) VALUES(?,?,?,?)').run(user.id,hashResetToken(token),hashResetCode(code),new Date(Date.now()+ttl*60_000).toISOString());
      const url=`${baseUrl(req)}/reset-password?token=${encodeURIComponent(token)}`;
      sendPasswordReset({to:user.email,name:user.name,url,code,ttlMinutes:ttl}).catch(e=>console.error('password reset email failed',e));
      audit(req,'password_reset_requested','user',user.id);
    }
  }
  res.json({ok:true,message:'If that email is registered, a password reset link will arrive shortly.'});
});

app.post('/api/auth/reset-password',async(req,res)=>{
  const token=String(req.body.token||''); const row=token?db.prepare('SELECT t.*,u.email,u.name,u.is_active FROM password_reset_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=? AND t.used_at IS NULL').get(hashResetToken(token)):null;
  if(!row||row.is_active===0||new Date(row.expires_at).getTime()<=Date.now())return res.status(400).json({error:'That reset link is invalid or has expired.'});
  const code=String(req.body.code||'');
  const expectedCodeHash=Buffer.from(row.code_hash||'');
  const suppliedCodeHash=Buffer.from(hashResetCode(code));
  if(!/^\d{6}$/.test(code)||expectedCodeHash.length!==suppliedCodeHash.length||!crypto.timingSafeEqual(suppliedCodeHash,expectedCodeHash))return res.status(400).json({error:'Enter the six-digit verification code sent to your email.',field:'code'});
  const next=String(req.body.new_password||'');
  if(next.length<MIN_LENGTH||next.length>MAX_LENGTH)return res.status(400).json({error:`Use between ${MIN_LENGTH} and ${MAX_LENGTH} characters.`,field:'new_password'});
  const problem=await checkPassword(next,{email:row.email,name:row.name}); if(problem)return res.status(400).json({error:problem,field:'new_password'});
  const cutoff=new Date().toISOString(); const passwordHash=await hashPassword(next);
  db.transaction(()=>{
    db.prepare('UPDATE users SET password_hash=?,sessions_valid_from=? WHERE id=?').run(passwordHash,cutoff,row.user_id);
    db.prepare('UPDATE password_reset_tokens SET used_at=CURRENT_TIMESTAMP WHERE id=?').run(row.id);
    db.prepare('DELETE FROM password_reset_tokens WHERE user_id=? AND id<>?').run(row.user_id,row.id);
  })();
  audit(req,'password_reset_completed','user',row.user_id);
  res.json({ok:true});
});

app.post('/api/auth/login',async(req,res)=>{const email=String(req.body.email||'').toLowerCase().trim();
// Escalating backoff is keyed to the account, not the address: the IP limiter
// above already covers one address spraying many accounts, while this covers
// many addresses grinding on one account. Keying it to the IP as well would
// punish a whole office behind one NAT for a single colleague's typos.
const key=`user:${email}`; const waiting=lockedFor(key); if(waiting>0)return res.status(429).json({error:retryMessage(waiting)});
const u=db.prepare('SELECT * FROM users WHERE email=?').get(email);
// verifyPassword always runs bcrypt, comparing against a placeholder hash when
// the account does not exist, so a missing email costs the same as a wrong
// password and cannot be told apart by response time.
const okPassword=await verifyPassword(req.body.password,u?.password_hash);
if(!u||!okPassword){recordFailure(key); audit(req,'login_failed','user',u?.id||email); return res.status(401).json({error:'Invalid email or password'});}
// Checked after the password so a deactivated account is indistinguishable
// from a wrong password until the caller has already proved the credential.
if(u.is_active===0){audit(req,'login_deactivated','user',u.id); return res.status(403).json({error:'This account is no longer active. Contact an administrator.'});}
clearFailures(key);
// Quietly move pre-existing hashes onto the current scheme now that we hold
// the plaintext and know it is correct.
if(needsRehash(u.password_hash)){try{db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(await hashPassword(req.body.password),u.id);}catch(e){console.error('rehash failed',e);}}
// With two-factor on, the password alone buys nothing but a short-lived ticket
// to the second step. No user is put on the session until that step passes.
if(u.totp_enabled){req.session.pending={id:u.id,at:Date.now()}; audit(req,'login_2fa_pending','user',u.id); return req.session.save(()=>res.json({ok:true,twoFactorRequired:true}));}
audit(req,'login','user',u.id); startSession(req,res,u);});

const PENDING_MS=5*60_000;
const pendingUser=req=>{const p=req.session.pending; if(!p||Date.now()-p.at>PENDING_MS)return null; return db.prepare('SELECT * FROM users WHERE id=?').get(p.id)||null;};

app.post('/api/auth/2fa/verify',async(req,res)=>{const u=pendingUser(req);
  if(!u){delete req.session.pending; return res.status(401).json({error:'That sign-in attempt expired. Please start again.'});}
  const key=`2fa:${u.id}`; const waiting=lockedFor(key); if(waiting>0)return res.status(429).json({error:retryMessage(waiting)});
  const submitted=String(req.body.code??'');
  const step=verifyCode(u.totp_secret,submitted);
  if(step!==null){
    // A code is good for one use: reusing it inside its 30-second window, or
    // replaying one captured moments ago, is refused.
    if(u.last_totp_step!==null&&step<=u.last_totp_step){recordFailure(key); return res.status(401).json({error:'That code has already been used. Wait for the next one.',field:'code'});}
    db.prepare('UPDATE users SET last_totp_step=? WHERE id=?').run(step,u.id);
    clearFailures(key); delete req.session.pending; audit(req,'login','user',u.id); return startSession(req,res,u);
  }
  const remaining=consumeRecoveryCode(JSON.parse(u.recovery_codes||'[]'),submitted);
  if(remaining){
    db.prepare('UPDATE users SET recovery_codes=? WHERE id=?').run(JSON.stringify(remaining),u.id);
    clearFailures(key); delete req.session.pending; audit(req,'login_recovery_code','user',u.id);
    return startSession(req,res,u);
  }
  recordFailure(key); audit(req,'login_2fa_failed','user',u.id);
  res.status(401).json({error:'That code is not correct.',field:'code'});});

/* ------------------------------------------------------------ google sign-in */

// Whether the button should be offered at all, so the sign-in pages can hide it
// when no credentials are configured.
app.get('/api/auth/google/available',(req,res)=>res.json({available:googleEnabled()}));

app.get('/api/auth/google',async(req,res)=>{
  if(!googleEnabled())return res.status(404).type('html').send(renderNotFound(req));
  try{
    const {url,state,nonce,verifier}=await authorisationUrl(baseUrl(req));
    // Held in the session, never in the URL: these are what prove the callback
    // belongs to a sign-in this browser actually started.
    req.session.google={state,nonce,verifier,at:Date.now(),returnTo:req.query.next==='portal'?'/portal':'/admin'};
    req.session.save(()=>res.redirect(url));
  }catch(e){console.error('google authorisation failed',e); failHtml(req,res,'Google sign-in is unavailable right now.');}});

const GOOGLE_WINDOW_MS=10*60_000;

app.get('/api/auth/google/callback',async(req,res)=>{
  const pending=req.session.google;
  delete req.session.google;
  const fail=(message)=>{req.session.flash={heading:'Sign-in failed',message,error:true}; req.session.save(()=>res.redirect(303,'/thank-you'));};

  if(!googleEnabled())return res.status(404).type('html').send(renderNotFound(req));
  if(req.query.error)return fail('Google reported: '+clean(req.query.error));
  if(!pending||Date.now()-pending.at>GOOGLE_WINDOW_MS)return fail('That sign-in attempt expired. Please try again.');
  // Guards against a callback the user never initiated.
  if(!req.query.state||req.query.state!==pending.state)return fail('That sign-in request could not be verified. Please try again.');
  if(!req.query.code)return fail('Google did not return a sign-in code.');

  let claims;
  try{
    const tokens=await exchangeCode({code:String(req.query.code),verifier:pending.verifier,baseUrl:baseUrl(req)});
    claims=await verifyIdToken(tokens.id_token,{nonce:pending.nonce});
  }catch(e){console.error('google sign-in failed',e); return fail('We could not verify that Google account.');}

  const refusal=refuseReason(claims);
  if(refusal){audit(req,'google_refused','user',claims.email||''); return fail(refusal);}

  const email=String(claims.email).toLowerCase();
  let user=db.prepare('SELECT * FROM users WHERE email=?').get(email);

  if(!user){
    // Never creates staff. An unknown Google account becomes a client and
    // nothing more; staff access is granted deliberately from the Team screen.
    // A real hash of a value nobody holds, rather than a sentinel string: this
    // account has no password, and no password can ever match it.
    const unusable=await hashPassword(crypto.randomBytes(32).toString('hex'));
    const info=db.prepare('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)')
      .run(clean(claims.name||email.split('@')[0]),email,unusable,'client');
    user=db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
    audit(req,'google_registered','user',user.id);
  }
  if(user.is_active===0){audit(req,'login_deactivated','user',user.id); return fail('This account is no longer active. Contact an administrator.');}

  // Google having authenticated the person says nothing about this site's own
  // second factor, so an account with TOTP on still has to complete it.
  if(user.totp_enabled){
    req.session.pending={id:user.id,at:Date.now()};
    audit(req,'login_2fa_pending','user',user.id);
    return req.session.save(()=>res.redirect(pending.returnTo));
  }
  audit(req,'login_google','user',user.id);
  req.session.regenerate(err=>{
    if(err)return fail('Could not start a session.');
    req.session.user=publicUser(user);
    notifyLogin(req,user).catch(e=>console.error('sign-in alert failed',e));
    req.session.save(()=>res.redirect(pending.returnTo));
  });});

app.get('/api/auth/2fa/status',auth(),(req,res)=>{const u=db.prepare('SELECT totp_enabled,totp_confirmed_at,recovery_codes FROM users WHERE id=?').get(req.session.user.id);
  res.json({enabled:!!u.totp_enabled,confirmedAt:u.totp_confirmed_at,recoveryCodesLeft:JSON.parse(u.recovery_codes||'[]').length});});

// Generates a candidate secret. It is stored but stays inactive until a code
// from it is proved, so an abandoned setup cannot lock anyone out.
app.post('/api/auth/2fa/setup',auth(),(req,res)=>{const u=db.prepare('SELECT * FROM users WHERE id=?').get(req.session.user.id);
  if(u.totp_enabled)return res.status(409).json({error:'Two-factor authentication is already switched on.'});
  const secret=generateSecret();
  db.prepare('UPDATE users SET totp_secret=?,totp_enabled=0 WHERE id=?').run(secret,u.id);
  const uri=otpauthUri({secret,account:u.email,issuer:'The Wise Pen N’ Paper'});
  res.json({secret:formatSecret(secret),uri,qr:toSvg(uri,{margin:2})});});

app.post('/api/auth/2fa/enable',auth(),(req,res)=>{const u=db.prepare('SELECT * FROM users WHERE id=?').get(req.session.user.id);
  if(u.totp_enabled)return res.status(409).json({error:'Two-factor authentication is already switched on.'});
  if(!u.totp_secret)return res.status(400).json({error:'Start the setup again to get a fresh key.'});
  const step=verifyCode(u.totp_secret,req.body.code);
  if(step===null)return res.status(400).json({error:'That code is not correct. Check your authenticator app and try again.',field:'code'});
  const codes=generateRecoveryCodes();
  db.prepare('UPDATE users SET totp_enabled=1,totp_confirmed_at=CURRENT_TIMESTAMP,last_totp_step=?,recovery_codes=? WHERE id=?')
    .run(step,JSON.stringify(codes.map(hashRecoveryCode)),u.id);
  req.session.user.twoFactor=true; req.session.user.mustEnrol=false; audit(req,'2fa_enabled','user',u.id);
  // The only time the plain recovery codes exist outside the user's hands.
  res.json({ok:true,recoveryCodes:codes});});

app.post('/api/auth/2fa/disable',auth(),async(req,res)=>{const u=db.prepare('SELECT * FROM users WHERE id=?').get(req.session.user.id);
  if(!u.totp_enabled)return res.status(409).json({error:'Two-factor authentication is not switched on.'});
  if(REQUIRE_2FA_ROLES.includes(u.role))return res.status(403).json({error:'Two-step verification is required for your role and cannot be switched off.'});
  // Turning it off is a credential change, so it needs the password again.
  if(!await verifyPassword(req.body.password,u.password_hash))return res.status(401).json({error:'Your password is not correct',field:'password'});
  if(verifyCode(u.totp_secret,req.body.code)===null)return res.status(401).json({error:'That code is not correct.',field:'code'});
  db.prepare("UPDATE users SET totp_enabled=0,totp_secret=NULL,totp_confirmed_at=NULL,last_totp_step=NULL,recovery_codes='[]' WHERE id=?").run(u.id);
  req.session.user.twoFactor=false; req.session.user.mustEnrol=mustEnrol({...u,totp_enabled:0}); audit(req,'2fa_disabled','user',u.id);
  res.json({ok:true});});

app.post('/api/auth/2fa/recovery-codes',auth(),async(req,res)=>{const u=db.prepare('SELECT * FROM users WHERE id=?').get(req.session.user.id);
  if(!u.totp_enabled)return res.status(409).json({error:'Two-factor authentication is not switched on.'});
  if(!await verifyPassword(req.body.password,u.password_hash))return res.status(401).json({error:'Your password is not correct',field:'password'});
  const codes=generateRecoveryCodes();
  db.prepare('UPDATE users SET recovery_codes=? WHERE id=?').run(JSON.stringify(codes.map(hashRecoveryCode)),u.id);
  audit(req,'2fa_recovery_regenerated','user',u.id);
  res.json({ok:true,recoveryCodes:codes});});

// Moves the cutoff forward so every other session is dropped, then rebuilds
// this one so the person doing it stays signed in.
app.post('/api/auth/sign-out-everywhere',auth(),(req,res)=>{const u=db.prepare('SELECT * FROM users WHERE id=?').get(req.session.user.id);
  const cutoff=new Date().toISOString();
  db.prepare('UPDATE users SET sessions_valid_from=? WHERE id=?').run(cutoff,u.id);
  audit(req,'sign_out_everywhere','user',u.id);
  // Rebuilt with a start time explicitly after the cutoff it just wrote, so the
  // person doing this stays signed in while every other session is dropped.
  startSession(req,res,u,200,new Date(Date.parse(cutoff)+1).toISOString());});

app.post('/api/auth/logout',auth(),(req,res)=>{audit(req,'logout','user',req.session.user?.id); req.session.destroy(()=>{res.clearCookie('wpnp.sid'); res.setHeader('Clear-Site-Data','"cache"'); res.json({ok:true});});});

app.post('/api/auth/password',auth(),async(req,res)=>{const u=db.prepare('SELECT * FROM users WHERE id=?').get(req.session.user.id); if(!u)return res.status(401).json({error:'Authentication required'});
const key=`chpw:${u.id}`; const waiting=lockedFor(key); if(waiting>0)return res.status(429).json({error:retryMessage(waiting)});
if(!await verifyPassword(req.body.current_password,u.password_hash)){recordFailure(key); return res.status(401).json({error:'Your current password is not correct',field:'current_password'});}
clearFailures(key);
const next=String(req.body.new_password??''); if(next.length<MIN_LENGTH||next.length>MAX_LENGTH)return res.status(400).json({error:`Use between ${MIN_LENGTH} and ${MAX_LENGTH} characters.`,field:'new_password'});
if(await verifyPassword(next,u.password_hash))return res.status(400).json({error:'Choose a password you have not used here before',field:'new_password'});
const problem=await checkPassword(next,{email:u.email,name:u.name}); if(problem)return res.status(400).json({error:problem,field:'new_password'});
db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(await hashPassword(next),u.id); audit(req,'password_change','user',u.id);
// A password change should invalidate whatever else was signed in, so the
// session is rebuilt rather than carried over.
startSession(req,res,u);});
app.get('/api/settings',(req,res)=>res.json(Object.fromEntries(db.prepare('SELECT key,value FROM settings').all().map(x=>[x.key,x.value]))));
app.get('/api/services',(req,res)=>res.json(db.prepare('SELECT * FROM services ORDER BY sort_order,name').all().map(x=>({...x,benefits:JSON.parse(x.benefits),process:JSON.parse(x.process),deliverables:JSON.parse(x.deliverables),faqs:JSON.parse(x.faqs)}))));
app.get('/api/portfolio',(req,res)=>res.json(db.prepare('SELECT * FROM portfolio ORDER BY featured DESC,completion_date DESC').all())); app.get('/api/testimonials',(req,res)=>res.json(db.prepare('SELECT * FROM testimonials WHERE published=1 ORDER BY id DESC').all())); app.get('/api/faqs',(req,res)=>res.json(db.prepare('SELECT * FROM faqs WHERE published=1 ORDER BY sort_order').all())); app.get('/api/blog',(req,res)=>res.json(db.prepare("SELECT b.*,c.name category,u.name author FROM blog_posts b LEFT JOIN categories c ON c.id=b.category_id LEFT JOIN users u ON u.id=b.author_id WHERE b.status='published' ORDER BY b.published_at DESC").all()));
app.get('/api/search',(req,res)=>{const term=clean(req.query.q).slice(0,80); const q=`%${term}%`; if(q==='%%')return res.json({services:[],portfolio:[],faqs:[],posts:[]}); res.json({services:db.prepare('SELECT id,name,summary,slug FROM services WHERE name LIKE ? OR description LIKE ? LIMIT 12').all(q,q),portfolio:db.prepare('SELECT id,title,description,slug,category FROM portfolio WHERE title LIKE ? OR description LIKE ? LIMIT 12').all(q,q),faqs:db.prepare('SELECT id,question,answer FROM faqs WHERE question LIKE ? OR answer LIKE ? LIMIT 12').all(q,q),posts:db.prepare("SELECT id,title,excerpt,slug FROM blog_posts WHERE status='published' AND (title LIKE ? OR content LIKE ?) LIMIT 12").all(q,q)});});
app.post('/api/quotes',upload.array('files',5),csrf.verify,verifyUploads,(req,res)=>{try{const d=z.object({full_name:z.string().min(2),email:z.email(),phone:z.string().min(7),organisation:z.string().optional(),location:z.string().optional(),project_type:z.string().min(2),service_id:z.coerce.number().optional(),project_title:z.string().min(2),description:z.string().min(20),target_audience:z.string().optional(),page_word_estimate:z.string().optional(),quantity:z.coerce.number().optional(),expected_date:z.string().optional(),budget:z.string().optional()}).parse(req.body); const r=ref('WPNP'); const info=db.prepare('INSERT INTO quote_requests(reference,user_id,full_name,email,phone,organisation,location,project_type,service_id,project_title,description,target_audience,page_word_estimate,quantity,expected_date,budget) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(r,req.session.user?.id||null,...['full_name','email','phone','organisation','location','project_type'].map(k=>clean(d[k])),d.service_id||null,clean(d.project_title),clean(d.description),clean(d.target_audience),clean(d.page_word_estimate),d.quantity||null,d.expected_date||null,clean(d.budget)); for(const f of req.files||[])db.prepare('INSERT INTO files(quote_id,uploaded_by,original_name,stored_name,mime_type,size) VALUES(?,?,?,?,?,?)').run(info.lastInsertRowid,req.session.user?.id||null,safeFileName(clean(f.originalname)),f.filename,f.mimetype,f.size); db.prepare('INSERT INTO notifications(type,title,body) VALUES(?,?,?)').run('quote','New quote request',`${r}: ${clean(d.project_title)}`); notify(`New quote request ${r}`,`From ${d.full_name}: ${d.project_title}`).catch(console.error); if(wantsHtml(req))return thank(req,res,{heading:'Your project request is in.',message:'We will review the brief and come back to you with next steps.',reference:r}); res.status(201).json({ok:true,reference:r});}catch(e){for(const f of req.files||[])fs.rmSync(f.path,{force:true}); if(!e.expose)console.error('quote submission failed',e); const m=e.expose?e.message:'Please check the form and try again.'; if(wantsHtml(req))return failHtml(req,res,m); res.status(e.status||400).json({error:m});}});
app.post('/api/contact',(req,res)=>{try{const d=z.object({name:z.string().trim().min(2),email:z.string(),phone:z.string().optional(),subject:z.string().trim().min(3),message:z.string().trim().min(10)}).parse(req.body); const email=requestEmail(d.email); if(!email)throw Object.assign(new Error('Enter a valid email address.'),{field:'email'}); const phone=d.phone?requestPhone(d.phone,req.body.phone_country):''; if(d.phone&&!phone)throw Object.assign(new Error('Enter a valid phone number for the selected country.'),{field:'phone'}); const x=db.prepare('INSERT INTO contact_messages(name,email,phone,subject,message) VALUES(?,?,?,?,?)').run(clean(d.name),email,phone,clean(d.subject),clean(d.message)); notify('New website enquiry',`${d.name}: ${d.subject}`).catch(console.error); if(wantsHtml(req))return thank(req,res,{heading:'Message received.',message:'Our team will respond using the contact details you supplied.'}); res.status(201).json({ok:true,id:x.lastInsertRowid});}catch(e){const m=e.field?e.message:'Please complete all required fields correctly'; if(wantsHtml(req))return failHtml(req,res,m); res.status(400).json({error:m,field:e.field});}});
app.post('/api/appointments',(req,res)=>{try{const d=z.object({full_name:z.string().min(2),email:z.email(),phone:z.string().min(7),consultation_type:z.string().min(2),preferred_date:z.string().min(8),preferred_time:z.string().min(3),project_info:z.string().optional()}).parse(req.body); if(new Date(`${d.preferred_date}T${d.preferred_time}`)<new Date())throw Error('Choose a future time'); const r=ref('CONS'); db.prepare('INSERT INTO appointments(reference,user_id,full_name,email,phone,consultation_type,preferred_date,preferred_time,project_info) VALUES(?,?,?,?,?,?,?,?,?)').run(r,req.session.user?.id||null,...['full_name','email','phone','consultation_type','preferred_date','preferred_time','project_info'].map(k=>clean(d[k]))); notify(`New consultation ${r}`,`${d.full_name} requested ${d.preferred_date} ${d.preferred_time}`).catch(console.error); if(wantsHtml(req))return thank(req,res,{heading:'Consultation requested.',message:'We will confirm the slot with you shortly.',reference:r}); res.status(201).json({ok:true,reference:r});}catch(e){const m=e.message||'Invalid appointment'; if(wantsHtml(req))return failHtml(req,res,m); res.status(400).json({error:m});}});
app.get('/api/admin/dashboard',auth('super_admin','admin','staff'),(req,res)=>{const c=t=>db.prepare(`SELECT COUNT(*) n FROM ${t}`).get().n; res.json({metrics:{enquiries:c('quote_requests'),newQuotes:db.prepare("SELECT COUNT(*) n FROM quote_requests WHERE status='New'").get().n,activeProjects:db.prepare("SELECT COUNT(*) n FROM projects WHERE status NOT IN('Completed','Cancelled')").get().n,completedProjects:db.prepare("SELECT COUNT(*) n FROM projects WHERE status='Completed'").get().n,clients:db.prepare("SELECT COUNT(*) n FROM users WHERE role='client'").get().n,unread:db.prepare("SELECT COUNT(*) n FROM contact_messages WHERE status='Unread'").get().n},quotes:db.prepare('SELECT q.*,s.name service FROM quote_requests q LEFT JOIN services s ON s.id=q.service_id ORDER BY q.created_at DESC LIMIT 30').all(),appointments:db.prepare('SELECT * FROM appointments ORDER BY created_at DESC LIMIT 20').all(),messages:db.prepare('SELECT * FROM contact_messages ORDER BY created_at DESC LIMIT 20').all()});});
const QUOTE_STATUSES=['New','Under Review','Contacted','Quotation Sent','Approved','In Progress','Completed','Cancelled'];
const APPOINTMENT_STATUSES=['Pending','Confirmed','Completed','Cancelled'];
const MESSAGE_STATUSES=['Unread','Read','Replied','Archived'];
const page=(req,fallback=25)=>{const limit=Math.min(Math.max(Number(req.query.limit)||fallback,1),100); const offset=Math.max(Number(req.query.offset)||0,0); return {limit,offset};};

// The full record behind a dashboard row, including the files the client
// attached -- which the dashboard previously had no way to reach at all.
/* ---------------------------------------------------------------- settings */

// Company details and the homepage statistics. These previously had no write
// path at all: changing the phone number meant hand-writing SQL.
const SETTING_KEYS=['company_name','tagline','email','phone','address','hours','whatsapp',
  'books_published','authors_supported','projects_completed','years_experience','organisations_served'];

app.get('/api/admin/settings',auth('super_admin','admin'),(req,res)=>{
  const stored=Object.fromEntries(db.prepare('SELECT key,value FROM settings').all().map(x=>[x.key,x.value]));
  res.json({settings:Object.fromEntries(SETTING_KEYS.map(k=>[k,stored[k]??'']))});});

app.patch('/api/admin/settings',auth('super_admin','admin'),(req,res)=>{
  const write=db.prepare('INSERT INTO settings(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP');
  const remove=db.prepare('DELETE FROM settings WHERE key=?');
  let changed=0;
  for(const key of SETTING_KEYS){
    if(!(key in req.body))continue;
    const value=clean(req.body[key]);
    // An empty statistic is removed rather than stored blank, because the
    // homepage band hides any figure that is absent.
    if(value==='')remove.run(key); else write.run(key,value);
    changed++;
  }
  if(!changed)return res.status(400).json({error:'No changes supplied'});
  audit(req,'settings_updated','settings',changed);
  res.json({ok:true});});

/* ----------------------------------------------------------------- content */

// portfolio, testimonials, FAQs and blog posts all needed the same four
// operations, so they share one implementation rather than four near-copies.
const uniqueSlug=(table,text,id)=>{
  const base=slugify(String(text||'item'),{lower:true,strict:true})||'item';
  const taken=db.prepare(`SELECT slug FROM ${table} WHERE slug LIKE ? AND id IS NOT ?`).all(base+'%',id??null).map(r=>r.slug);
  if(!taken.includes(base))return base;
  for(let n=2;;n++) if(!taken.includes(`${base}-${n}`))return `${base}-${n}`;
};

const CONTENT={
  portfolio:{
    table:'portfolio', order:'featured DESC, completion_date DESC, id DESC', slugFrom:'title',
    schema:z.object({title:z.string().min(2),client:z.string().optional(),category:z.string().min(2),
      description:z.string().min(10),completion_date:z.string().optional(),outcome:z.string().optional(),
      featured:z.boolean().optional()}),
    columns:['title','client','category','description','completion_date','outcome','featured'],
  },
  testimonials:{
    table:'testimonials', order:'id DESC',
    schema:z.object({client_name:z.string().min(2),organisation:z.string().optional(),
      testimonial:z.string().min(10),rating:z.coerce.number().int().min(1).max(5).optional(),
      published:z.boolean().optional()}),
    columns:['client_name','organisation','testimonial','rating','published'],
  },
  faqs:{
    table:'faqs', order:'sort_order, id',
    schema:z.object({question:z.string().min(5),answer:z.string().min(5),category:z.string().optional(),
      sort_order:z.coerce.number().int().optional(),published:z.boolean().optional()}),
    columns:['question','answer','category','sort_order','published'],
  },
  blog:{
    table:'blog_posts', order:'COALESCE(published_at, created_at) DESC', slugFrom:'title',
    schema:z.object({title:z.string().min(2),excerpt:z.string().min(10),content:z.string().min(20),
      category_id:z.coerce.number().int().optional(),status:z.enum(['draft','published']).optional()}),
    columns:['title','excerpt','content','category_id','status'],
  },
};

const BOOLEAN_COLUMNS=new Set(['featured','published']);
const contentType=req=>CONTENT[req.params.type]||null;

const contentValues=(type,data)=>{
  const out={};
  for(const col of type.columns){
    if(!(col in data))continue;
    const value=data[col];
    out[col]=BOOLEAN_COLUMNS.has(col)?(value?1:0)
      :typeof value==='number'?value
      :clean(value);
  }
  return out;
};

app.get('/api/admin/content/:type',auth(STAFF_ROLES),(req,res)=>{
  const type=contentType(req); if(!type)return res.status(404).json({error:'Unknown content type'});
  const {limit,offset}=page(req);
  res.json({total:db.prepare(`SELECT COUNT(*) n FROM ${type.table}`).get().n,
    items:db.prepare(`SELECT * FROM ${type.table} ORDER BY ${type.order} LIMIT ? OFFSET ?`).all(limit,offset)});});

app.post('/api/admin/content/:type',auth('super_admin','admin'),(req,res)=>{
  const type=contentType(req); if(!type)return res.status(404).json({error:'Unknown content type'});
  try{
    const data=type.schema.parse(req.body);
    const values=contentValues(type,data);
    if(type.slugFrom)values.slug=uniqueSlug(type.table,data[type.slugFrom]);
    // A post is only dated once it is actually published.
    if(type.table==='blog_posts'){values.author_id=req.session.user.id;
      if(values.status==='published')values.published_at=new Date().toISOString();}
    const cols=Object.keys(values);
    const info=db.prepare(`INSERT INTO ${type.table}(${cols.join(',')}) VALUES(${cols.map(()=>'?').join(',')})`).run(...Object.values(values));
    audit(req,'content_created',type.table,info.lastInsertRowid);
    res.status(201).json({ok:true,item:db.prepare(`SELECT * FROM ${type.table} WHERE id=?`).get(info.lastInsertRowid)});
  }catch(e){ if(e.code==='SQLITE_CONSTRAINT_UNIQUE')return res.status(409).json({error:'Something with that name already exists.'});
    res.status(400).json({error:'Check the fields and try again.'});}});

app.patch('/api/admin/content/:type/:id',auth('super_admin','admin'),(req,res)=>{
  const type=contentType(req); if(!type)return res.status(404).json({error:'Unknown content type'});
  const existing=db.prepare(`SELECT * FROM ${type.table} WHERE id=?`).get(req.params.id);
  if(!existing)return res.status(404).json({error:'Not found'});
  try{
    const data=type.schema.partial().parse(req.body);
    const values=contentValues(type,data);
    if(type.slugFrom&&data[type.slugFrom])values.slug=uniqueSlug(type.table,data[type.slugFrom],existing.id);
    if(type.table==='blog_posts'&&values.status==='published'&&!existing.published_at)
      values.published_at=new Date().toISOString();
    if(!Object.keys(values).length)return res.status(400).json({error:'No changes supplied'});
    db.prepare(`UPDATE ${type.table} SET ${Object.keys(values).map(k=>`${k}=?`).join(',')} WHERE id=?`)
      .run(...Object.values(values),existing.id);
    audit(req,'content_updated',type.table,existing.id);
    res.json({ok:true,item:db.prepare(`SELECT * FROM ${type.table} WHERE id=?`).get(existing.id)});
  }catch(e){ if(e.code==='SQLITE_CONSTRAINT_UNIQUE')return res.status(409).json({error:'Something with that name already exists.'});
    res.status(400).json({error:'Check the fields and try again.'});}});

app.delete('/api/admin/content/:type/:id',auth('super_admin','admin'),(req,res)=>{
  const type=contentType(req); if(!type)return res.status(404).json({error:'Unknown content type'});
  const info=db.prepare(`DELETE FROM ${type.table} WHERE id=?`).run(req.params.id);
  if(!info.changes)return res.status(404).json({error:'Not found'});
  audit(req,'content_deleted',type.table,req.params.id);
  res.json({ok:true});});

app.get('/api/admin/categories',auth(STAFF_ROLES),(req,res)=>
  res.json({items:db.prepare('SELECT id,name,slug FROM categories ORDER BY name').all()}));

/* ------------------------------------------------------ staff management */

const MANAGER_ROLES=['super_admin','admin'];
const ASSIGNABLE_ROLES=['staff','admin','super_admin','client'];
const publicStaff=u=>({id:u.id,name:u.name,email:u.email,phone:u.phone,role:u.role,is_active:!!u.is_active,
  two_factor:!!u.totp_enabled,last_login_at:u.last_login_at,created_at:u.created_at});
const countActiveSuperAdmins=()=>db.prepare("SELECT COUNT(*) n FROM users WHERE role='super_admin' AND is_active=1").get().n;

app.get('/api/admin/users',auth(MANAGER_ROLES),(req,res)=>{
  res.json({items:db.prepare("SELECT * FROM users WHERE role<>'client' ORDER BY CASE role WHEN 'super_admin' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, name").all().map(publicStaff)});});

app.post('/api/admin/users',auth(MANAGER_ROLES),async(req,res)=>{try{
  const d=z.object({name:z.string().min(2),email:z.email(),phone:z.string().min(7).optional(),
    role:z.enum(['staff','admin','super_admin']),password:z.string().min(MIN_LENGTH).max(MAX_LENGTH)}).parse(req.body);
  // Only a super_admin can mint another one; an admin promoting itself sideways
  // would otherwise be a free privilege escalation.
  if(d.role==='super_admin'&&req.session.user.role!=='super_admin')
    return res.status(403).json({error:'Only a super admin can create another super admin.',field:'role'});
  const email=d.email.toLowerCase();
  const problem=await checkPassword(d.password,{email,name:d.name});
  if(problem)return res.status(400).json({error:problem,field:'password'});
  const info=db.prepare('INSERT INTO users(name,email,phone,password_hash,role,created_by) VALUES(?,?,?,?,?,?)')
    .run(clean(d.name),email,clean(d.phone||''),await hashPassword(d.password),d.role,req.session.user.id);
  audit(req,'staff_created','user',info.lastInsertRowid);
  res.status(201).json({ok:true,user:publicStaff(db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid))});
}catch(e){if(e.code==='SQLITE_CONSTRAINT_UNIQUE')return res.status(409).json({error:'That email already has an account.',field:'email'});
  res.status(400).json({error:`Check the details. Passwords need at least ${MIN_LENGTH} characters.`});}});

app.patch('/api/admin/users/:id',auth(MANAGER_ROLES),(req,res)=>{
  const target=db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if(!target)return res.status(404).json({error:'Account not found'});
  const me=req.session.user;
  const self=String(target.id)===String(me.id);

  const updates={};
  if('role' in req.body){
    if(!ASSIGNABLE_ROLES.includes(req.body.role))return res.status(400).json({error:'Invalid role',field:'role'});
    // Nobody edits their own role: it is the shortest path to privilege
    // escalation, and to accidentally locking yourself out of your own tools.
    if(self)return res.status(403).json({error:'You cannot change your own role.',field:'role'});
    if((req.body.role==='super_admin'||target.role==='super_admin')&&me.role!=='super_admin')
      return res.status(403).json({error:'Only a super admin can grant or remove super admin.',field:'role'});
    if(target.role==='super_admin'&&req.body.role!=='super_admin'&&countActiveSuperAdmins()<=1)
      return res.status(409).json({error:'This is the last active super admin. Promote someone else first.',field:'role'});
    updates.role=req.body.role;
  }
  if('is_active' in req.body){
    const active=req.body.is_active?1:0;
    if(self&&!active)return res.status(403).json({error:'You cannot deactivate your own account.',field:'is_active'});
    if(!active&&target.role==='super_admin'&&countActiveSuperAdmins()<=1)
      return res.status(409).json({error:'This is the last active super admin. Promote someone else first.',field:'is_active'});
    if(!active&&target.role==='super_admin'&&me.role!=='super_admin')
      return res.status(403).json({error:'Only a super admin can deactivate a super admin.',field:'is_active'});
    updates.is_active=active;
  }
  for(const field of ['name','phone']) if(field in req.body) updates[field]=clean(req.body[field]);
  if(!Object.keys(updates).length)return res.status(400).json({error:'No changes supplied'});

  db.prepare(`UPDATE users SET ${Object.keys(updates).map(k=>`${k}=?`).join(',')} WHERE id=?`)
    .run(...Object.values(updates),target.id);
  // Deactivating or demoting must take effect everywhere at once, not whenever
  // that person's session happens to expire.
  if('is_active' in updates||'role' in updates)
    db.prepare('UPDATE users SET sessions_valid_from=? WHERE id=?').run(new Date().toISOString(),target.id);
  audit(req,'staff_updated','user',target.id);
  res.json({ok:true,user:publicStaff(db.prepare('SELECT * FROM users WHERE id=?').get(target.id))});});

// Clears a colleague's second factor when they have lost both their phone and
// their recovery codes. It cannot reveal or set one, only remove.
app.post('/api/admin/users/:id/reset-2fa',auth(MANAGER_ROLES),(req,res)=>{
  const target=db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if(!target)return res.status(404).json({error:'Account not found'});
  if(target.role==='super_admin'&&req.session.user.role!=='super_admin')
    return res.status(403).json({error:'Only a super admin can reset a super admin.'});
  db.prepare("UPDATE users SET totp_enabled=0,totp_secret=NULL,totp_confirmed_at=NULL,last_totp_step=NULL,recovery_codes='[]' WHERE id=?").run(target.id);
  audit(req,'staff_2fa_reset','user',target.id);
  res.json({ok:true});});

app.get('/api/admin/quotes/:id',auth(STAFF_ROLES),(req,res)=>{
  const q=db.prepare('SELECT q.*,s.name service,u.name assigned_name FROM quote_requests q LEFT JOIN services s ON s.id=q.service_id LEFT JOIN users u ON u.id=q.assigned_to WHERE q.id=?').get(req.params.id);
  if(!q)return res.status(404).json({error:'Quote request not found'});
  q.files=db.prepare('SELECT id,original_name,mime_type,size,created_at FROM files WHERE quote_id=? ORDER BY id').all(q.id);
  res.json(q);});

app.patch('/api/admin/appointments/:id',auth(STAFF_ROLES),(req,res)=>{
  if(!APPOINTMENT_STATUSES.includes(req.body.status))return res.status(400).json({error:'Invalid status'});
  const info=db.prepare('UPDATE appointments SET status=? WHERE id=?').run(req.body.status,req.params.id);
  if(!info.changes)return res.status(404).json({error:'Appointment not found'});
  audit(req,'update','appointment',req.params.id); res.json({ok:true});});

app.patch('/api/admin/messages/:id',auth(STAFF_ROLES),(req,res)=>{
  if(!MESSAGE_STATUSES.includes(req.body.status))return res.status(400).json({error:'Invalid status'});
  const info=db.prepare('UPDATE contact_messages SET status=? WHERE id=?').run(req.body.status,req.params.id);
  if(!info.changes)return res.status(404).json({error:'Message not found'});
  audit(req,'update','contact_message',req.params.id); res.json({ok:true});});

// Paged listings so the dashboard is not capped at the first 20-30 rows.
app.get('/api/admin/quotes',auth(STAFF_ROLES),(req,res)=>{const {limit,offset}=page(req);
  const where=QUOTE_STATUSES.includes(req.query.status)?' WHERE q.status=?':''; const args=where?[req.query.status]:[];
  res.json({total:db.prepare(`SELECT COUNT(*) n FROM quote_requests q${where}`).get(...args).n,
    items:db.prepare(`SELECT q.*,s.name service FROM quote_requests q LEFT JOIN services s ON s.id=q.service_id${where} ORDER BY q.created_at DESC LIMIT ? OFFSET ?`).all(...args,limit,offset)});});

app.get('/api/admin/appointments',auth(STAFF_ROLES),(req,res)=>{const {limit,offset}=page(req);
  res.json({total:db.prepare('SELECT COUNT(*) n FROM appointments').get().n,
    items:db.prepare('SELECT * FROM appointments ORDER BY created_at DESC LIMIT ? OFFSET ?').all(limit,offset)});});

app.get('/api/admin/messages',auth(STAFF_ROLES),(req,res)=>{const {limit,offset}=page(req);
  res.json({total:db.prepare('SELECT COUNT(*) n FROM contact_messages').get().n,
    items:db.prepare('SELECT * FROM contact_messages ORDER BY created_at DESC LIMIT ? OFFSET ?').all(limit,offset)});});

app.get('/api/admin/audit',auth('super_admin','admin'),(req,res)=>{const {limit,offset}=page(req,50);
  res.json({total:db.prepare('SELECT COUNT(*) n FROM audit_logs').get().n,
    items:db.prepare('SELECT a.*,u.name user_name,u.email user_email FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT ? OFFSET ?').all(limit,offset)});});

app.patch('/api/admin/quotes/:id',auth(STAFF_ROLES),(req,res)=>{if(!QUOTE_STATUSES.includes(req.body.status))return res.status(400).json({error:'Invalid status'}); // admin_notes is only written when the field is actually supplied. It used to
// be assigned unconditionally, so changing a quote's status through the
// dashboard dropdown silently erased whatever notes were already there.
const notes='admin_notes' in req.body?clean(req.body.admin_notes):null; const info=db.prepare('UPDATE quote_requests SET status=?,assigned_to=COALESCE(?,assigned_to),admin_notes=COALESCE(?,admin_notes) WHERE id=?').run(req.body.status,req.body.assigned_to||null,notes,req.params.id); if(!info.changes)return res.status(404).json({error:'Quote request not found'}); audit(req,'update','quote_request',req.params.id); res.json({ok:true});});
app.post('/api/admin/services',auth('super_admin','admin'),(req,res)=>{try{const d=z.object({name:z.string().min(2),summary:z.string().min(10),description:z.string().min(20),featured:z.boolean().optional()}).parse(req.body); const x=db.prepare('INSERT INTO services(name,slug,summary,description,featured,sort_order) VALUES(?,?,?,?,?,?)').run(clean(d.name),slugify(d.name,{lower:true,strict:true}),clean(d.summary),clean(d.description),d.featured?1:0,99); audit(req,'create','service',x.lastInsertRowid); res.status(201).json({ok:true,id:x.lastInsertRowid});}catch(e){res.status(400).json({error:'Invalid or duplicate service'});}});
app.patch('/api/admin/services/:id',auth('super_admin','admin'),(req,res)=>{const f=['name','summary','description','featured','sort_order']; const data=Object.fromEntries(f.filter(k=>k in req.body).map(k=>[k,k==='featured'?(req.body[k]?1:0):clean(req.body[k])])); if(!Object.keys(data).length)return res.status(400).json({error:'No changes supplied'}); const sets=Object.keys(data).map(k=>`${k}=?`).join(','); db.prepare(`UPDATE services SET ${sets} WHERE id=?`).run(...Object.values(data),req.params.id); audit(req,'update','service',req.params.id); res.json({ok:true});});
app.delete('/api/admin/services/:id',auth('super_admin','admin'),(req,res)=>{db.prepare('DELETE FROM services WHERE id=?').run(req.params.id); audit(req,'delete','service',req.params.id); res.json({ok:true});});
app.get('/api/admin/projects',auth(STAFF_ROLES),(req,res)=>res.json({items:db.prepare('SELECT p.*,u.name client_name,u.email client_email FROM projects p JOIN users u ON u.id=p.client_id ORDER BY p.created_at DESC').all().map(p=>({...p,messages:db.prepare('SELECT m.*,u.name sender FROM messages m JOIN users u ON u.id=m.sender_id WHERE project_id=? ORDER BY m.created_at').all(p.id)}))}));
app.post('/api/admin/projects/:id/messages',auth(STAFF_ROLES),(req,res)=>{
  const body=z.object({body:z.string().trim().min(1).max(2000)}).parse(req.body).body;
  const project=db.prepare('SELECT id FROM projects WHERE id=?').get(req.params.id);
  if(!project)return res.status(404).json({error:'Project not found'});
  const info=db.prepare('INSERT INTO messages(project_id,sender_id,body) VALUES(?,?,?)').run(project.id,req.session.user.id,clean(body));
  audit(req,'message_sent','project',project.id);
  res.status(201).json({ok:true,message:db.prepare('SELECT m.*,u.name sender FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?').get(info.lastInsertRowid)});
});
app.get('/api/client/portal',auth('client'),(req,res)=>res.json({projects:db.prepare('SELECT * FROM projects WHERE client_id=? ORDER BY created_at DESC').all(req.session.user.id).map(p=>({...p,milestones:db.prepare('SELECT * FROM milestones WHERE project_id=? ORDER BY sort_order').all(p.id),files:db.prepare('SELECT id,original_name,mime_type,size,approved,created_at FROM files WHERE project_id=?').all(p.id),messages:db.prepare('SELECT m.*,u.name sender FROM messages m JOIN users u ON u.id=m.sender_id WHERE project_id=? ORDER BY m.created_at').all(p.id)})),quotes:db.prepare('SELECT * FROM quote_requests WHERE user_id=? OR email=? ORDER BY created_at DESC').all(req.session.user.id,req.session.user.email),appointments:db.prepare('SELECT * FROM appointments WHERE user_id=? OR email=? ORDER BY created_at DESC').all(req.session.user.id,req.session.user.email),invoices:db.prepare('SELECT i.* FROM invoices i JOIN projects p ON p.id=i.project_id WHERE p.client_id=?').all(req.session.user.id)}));
app.patch('/api/client/profile',auth('client'),(req,res)=>{try{
  const d=z.object({name:z.string().trim().min(2),email:z.string(),phone:z.string().min(1)}).parse(req.body);
  const email=requestEmail(d.email); const phone=requestPhone(d.phone,req.body.phone_country);
  if(!email)return res.status(400).json({error:'Enter a valid email address.',field:'email'});
  if(!phone)return res.status(400).json({error:'Enter a valid phone number for the selected country.',field:'phone'});
  db.prepare('UPDATE users SET name=?,email=?,phone=? WHERE id=?').run(clean(d.name),email,phone,req.session.user.id);
  req.session.user={...req.session.user,name:clean(d.name),email,phone};
  audit(req,'client_profile_updated','user',req.session.user.id);
  res.json({ok:true,user:req.session.user});
}catch(e){if(e.code==='SQLITE_CONSTRAINT_UNIQUE')return res.status(409).json({error:'That email is already registered.',field:'email'}); res.status(400).json({error:'Check your client information and try again.'});}});
app.post('/api/client/projects/:id/messages',auth('client'),(req,res)=>{
  const body=z.object({body:z.string().trim().min(1).max(2000)}).parse(req.body).body;
  const project=db.prepare('SELECT id FROM projects WHERE id=? AND client_id=?').get(req.params.id,req.session.user.id);
  if(!project)return res.status(404).json({error:'Project not found'});
  const info=db.prepare('INSERT INTO messages(project_id,sender_id,body) VALUES(?,?,?)').run(project.id,req.session.user.id,clean(body));
  audit(req,'message_sent','project',project.id);
  res.status(201).json({ok:true,message:db.prepare('SELECT m.*,u.name sender FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?').get(info.lastInsertRowid)});
});
app.get('/api/files/:id',auth(),async(req,res)=>{const f=db.prepare('SELECT f.*,p.client_id,q.user_id quote_user,q.email quote_email FROM files f LEFT JOIN projects p ON p.id=f.project_id LEFT JOIN quote_requests q ON q.id=f.quote_id WHERE f.id=?').get(req.params.id); if(!f)return res.status(404).json({error:'File not found'}); const u=req.session.user, staff=['super_admin','admin','staff'].includes(u.role), mine=f.uploaded_by===u.id, owns=mine||f.client_id===u.id||f.quote_user===u.id||f.quote_email===u.email; const gate=f.project_id?(mine||!!f.approved):true; if(!staff&&!(owns&&gate))return res.status(403).json({error:'Not authorised'}); try{const file=await downloadUpload(f.stored_name); audit(req,'download','file',f.id); res.setHeader('Content-Disposition',`attachment; filename="${safeFileName(f.original_name)}"`); if(file.contentType)res.type(file.contentType); if(file.type==='path'){if(!fs.existsSync(file.value))return res.status(404).json({error:'File not found'}); return res.sendFile(path.resolve(file.value));} file.value.pipe(res);}catch(e){res.status(404).json({error:'File not found'});}});
app.get('/robots.txt',(req,res)=>res.type('text').send(`User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /portal\nDisallow: /thank-you\nSitemap: ${baseUrl(req)}/sitemap.xml`));
// Fragments like /#services are not separate URLs to a crawler; the service
// pages below are, so those are what the sitemap now lists.
app.get('/sitemap.xml',(req,res)=>{const b=baseUrl(req); const paths=['/',...serviceSlugs().map(s=>`/services/${s.slug}`)]; res.type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${paths.map(p=>`<url><loc>${b}${p}</loc><changefreq>${p==='/'?'weekly':'monthly'}</changefreq><priority>${p==='/'?'1.0':'0.8'}</priority></url>`).join('')}</urlset>`)});
app.get('/favicon.ico',(req,res)=>res.redirect(301,'/favicon.svg'));
app.get('/',(req,res)=>res.type('html').send(renderHome(req)));
app.get('/services/:slug',(req,res)=>{const s=serviceBySlug(req.params.slug); if(!s)return res.status(404).type('html').send(renderNotFound(req)); res.type('html').send(renderService(req,s));});
app.get('/thank-you',(req,res)=>{const flash=req.session.flash; delete req.session.flash; if(!flash)return res.redirect(303,'/'); res.type('html').send(renderThanks(req,flash));});
app.get('/admin',(req,res)=>res.type('html').send(renderAdmin(req))); app.get('/portal',(req,res)=>res.sendFile(path.join(root,'frontend','portal.html'))); app.get('/reset-password',(req,res)=>res.sendFile(path.join(root,'frontend','reset.html')));
// Anything unmatched is genuinely missing. This used to return the homepage
// with a 200, which makes every typo a soft 404 that crawlers happily index.
app.use((req,res)=>req.path.startsWith('/api/')?res.status(404).json({error:'Not found'}):res.status(404).type('html').send(renderNotFound(req)));
app.use((err,req,res,next)=>{
  const csrfFailure=err.code==='EBADCSRFTOKEN';
  const multerFailure=err instanceof multer.MulterError;
  const status=csrfFailure?403:(multerFailure||err.expose)?(err.status||400):500;
  if(status>=500)console.error(err); else console.warn(`${req.method} ${req.originalUrl} -> ${status}: ${err.message}`);
  const message=csrfFailure?'Security token expired. Refresh and try again.'
    :multerFailure?(err.code==='LIMIT_FILE_SIZE'?'Each file must be 15 MB or smaller':'That upload could not be accepted.')
    :err.expose?err.message
    :'Something went wrong. Please try again.';
  // A browser posting a form should land on a page, not on raw JSON.
  if(status<500&&typeof wantsHtml==='function'&&wantsHtml(req)&&req.method==='POST')return failHtml(req,res,message);
  res.status(status).json({error:message});
});
const port=process.env.PORT||3000; if(process.env.NODE_ENV!=='test')app.listen(port,()=>console.log(`Wise Pen platform running on http://localhost:${port}`)); export default app;
