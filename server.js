'use strict';
// RafixWindows server: Neon = accounts/passwords/devices/apps/promo codes/entitlements.
// ENV: DATABASE_URL, ADMIN_SECRET, TOKEN_PRIVATE_KEY, APP_MASTER_KEY
const crypto = require('crypto');
const express = require('express');

const FOREVER = 8640000000000000;
const DUR = { HOUR: 3600e3, DAY: 864e5, WEEK: 6048e5, MONTH: 2592e6, YEAR: 31536e6, FOREVER: null };
const NICK = /^[a-z0-9_]{3,16}$/;
const CODE_RE = /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/;
const TOKEN_TTL = 7 * 864e5;
const MAX_DEVICES = parseInt(process.env.MAX_DEVICES || '2', 10);

function b64u(buf) { return Buffer.from(buf).toString('base64url'); }
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function safeEq(a, b) { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); }

function createApp(pool, env) {
  env = env || process.env;
  const privKey = crypto.createPrivateKey({ key: Buffer.from(env.TOKEN_PRIVATE_KEY, 'base64'), format: 'der', type: 'pkcs8' });
  const pubKey = crypto.createPublicKey(privKey);
  const master = Buffer.from(env.APP_MASTER_KEY, 'base64');
  if (master.length !== 32) throw new Error('APP_MASTER_KEY must be 32 bytes (base64)');
  const adminSecret = env.ADMIN_SECRET || '';

  async function redeemPromo(codeHash, nick) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const code = await client.query('SELECT code_hash,tier,duration,redeemed_by,redeemed_at FROM promo_codes WHERE code_hash=$1 FOR UPDATE', [codeHash]);
      if (!code.rows.length) { await client.query('ROLLBACK'); return { ok:false, error:'Промокод не найден' }; }
      const c = code.rows[0];
      if (c.redeemed_by || c.redeemed_at) { await client.query('ROLLBACK'); return { ok:false, error:'Промокод уже использован' }; }
      const now = Date.now();
      const e = await client.query('SELECT premium_exp,plus_exp FROM entitlements WHERE nick=$1 FOR UPDATE', [nick]);
      if (!e.rows.length) { await client.query('ROLLBACK'); return { ok:false, error:'Аккаунт не найден' }; }
      const col = c.tier === 'PLUS' ? 'plus_exp' : 'premium_exp';
      const cur = Number(e.rows[0][col] || 0);
      const duration = String(c.duration).toUpperCase();
      let next;
      if (duration === 'FOREVER') next = FOREVER;
      else if (duration === 'NONE') next = 0;
      else if (!(duration in DUR)) { await client.query('ROLLBACK'); return { ok:false, error:'Недопустимая длительность промокода' }; }
      else next = Math.max(cur, now) + DUR[duration];
      await client.query(`UPDATE entitlements SET ${col}=$1,updated_at=$2 WHERE nick=$3`, [next, new Date().toISOString(), nick]);
      await client.query('UPDATE promo_codes SET redeemed_by=$1,redeemed_at=$2 WHERE code_hash=$3', [nick, now, codeHash]);
      await client.query('COMMIT');
      return { ok:true, tier:c.tier, duration };
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch (_) {}
      throw e;
    } finally { client.release(); }
  }

  const app = express();
  app.disable('x-powered-by'); app.set('trust proxy', 1);
  app.use((req, res, next) => { res.set({ 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'" }); next(); });

  const hits = new Map();
  function limited(key, max, windowMs) { const now = Date.now(); const arr = (hits.get(key) || []).filter(t => now - t < windowMs); arr.push(now); hits.set(key, arr); if (hits.size > 50000) for (const [k,v] of hits) if (!v.length || now-v[v.length-1]>windowMs) hits.delete(k); return arr.length > max; }
  function rl(name, max, windowMs, withNick) { return (req,res,next) => { const nick = withNick ? String((req.body&&req.body.nick)||'').toLowerCase().slice(0,32) : ''; if (limited(name+'|ip|'+req.ip,max*3,windowMs) || (nick&&limited(name+'|n|'+nick,max,windowMs))) return res.status(429).json({ok:false,error:'Слишком много попыток, подождите немного'}); next(); }; }

  // A rejected login or duplicate registration starts a server-side 10s cooldown.
  const authCool=new Map();
  function authDelay(req,res,next){
    const key=String(req.body?.nick||'').trim().toLowerCase()+'|'+req.ip;
    const until=authCool.get(key)||0;
    if(until>Date.now())return res.status(429).json({ok:false,error:'Повторите через '+Math.ceil((until-Date.now())/1000)+' сек.'});
    req.authCoolKey=key;next();
  }
  function failedAuth(req){
    if(req.authCoolKey)authCool.set(req.authCoolKey,Date.now()+10000);
    if(authCool.size>10000)for(const [k,v] of authCool)if(v<Date.now())authCool.delete(k);
  }

  function signToken(u, device) { const now=Date.now(); const payload={n:u.nick,p:Number(u.premium_exp),x:Number(u.plus_exp),d:device,i:now,e:now+TOKEN_TTL}; const body=b64u(JSON.stringify(payload)); return body+'.'+b64u(crypto.sign(null,Buffer.from(body),privKey)); }
  function verifyToken(tok) { try { const [body,sig]=String(tok).split('.'); if(!body||!sig)return null; if(!crypto.verify(null,Buffer.from(body),pubKey,Buffer.from(sig,'base64url')))return null; const p=JSON.parse(Buffer.from(body,'base64url').toString('utf8')); return p.e>Date.now()?p:null; } catch(e){return null;} }
  function deviceOk(d){return typeof d==='string'&&/^[a-f0-9]{64}$/.test(d);}
  let scryptBusy=0;
  function hashPw(pw,saltHex){return new Promise((resolve,reject)=>{if(scryptBusy>=16)return reject(Object.assign(new Error('busy'),{busy:true}));scryptBusy++;crypto.scrypt(pw,Buffer.from(saltHex,'hex'),32,{N:16384,r:8,p:1,maxmem:64*1024*1024},(err,key)=>{scryptBusy--;err?reject(err):resolve(key.toString('hex'));});});}
  function encGcm(key,plain){const iv=crypto.randomBytes(12);const c=crypto.createCipheriv('aes-256-gcm',key,iv);const ct=Buffer.concat([c.update(plain),c.final()]);return Buffer.concat([iv,ct,c.getAuthTag()]);}
  function decGcm(key,blob){const iv=blob.subarray(0,12),tag=blob.subarray(blob.length-16),ct=blob.subarray(12,blob.length-16);const d=crypto.createDecipheriv('aes-256-gcm',key,iv);d.setAuthTag(tag);return Buffer.concat([d.update(ct),d.final()]);}

  async function getUser(nick){const r=await pool.query('SELECT nick, pass_salt, pass_hash, banned FROM users WHERE nick=$1',[nick]); if(!r.rows[0])return null; const e=await pool.query('SELECT premium_exp,plus_exp FROM entitlements WHERE nick=$1',[nick]); const x=e.rows[0]||{premium_exp:0,plus_exp:0}; return {...r.rows[0],premium_exp:x.premium_exp,plus_exp:x.plus_exp};}
  async function bindDevice(nick,device){const r=await pool.query('SELECT device FROM devices WHERE nick=$1',[nick]);if(r.rows.some(x=>x.device===device))return true;if(r.rows.length>=MAX_DEVICES)return false;await pool.query('INSERT INTO devices(nick,device,created) VALUES($1,$2,$3)',[nick,device,Date.now()]);return true;}

  app.get('/',(req,res)=>res.json({status:'ok',service:'rafix-server'}));
  const json=express.json({limit:'8kb'});

  app.post('/api/register',json,rl('reg',5,3600e3,false),authDelay,async(req,res)=>{try{const nick=String(req.body.nick||'').trim().toLowerCase(),pw=String(req.body.password||''),device=req.body.device;if(!NICK.test(nick))return res.json({ok:false,error:'Ник: 3–16 символов, a-z, 0-9, _'});if(pw.length<6||pw.length>128)return res.json({ok:false,error:'Пароль: минимум 6 символов'});if(!deviceOk(device))return res.status(400).json({ok:false,error:'Неверный запрос'});const salt=crypto.randomBytes(16).toString('hex');if(await getUser(nick)){failedAuth(req);return res.json({ok:false,error:'Такой ник уже занят'});}const ins=await pool.query('INSERT INTO users(nick,pass_salt,pass_hash,created) VALUES($1,$2,$3,$4) ON CONFLICT(nick) DO NOTHING RETURNING nick',[nick,salt,await hashPw(pw,salt),Date.now()]);if(!ins.rows.length)return res.json({ok:false,error:'Такой ник уже занят'});await pool.query('INSERT INTO entitlements(nick,premium_exp,plus_exp,updated_at) VALUES($1,0,0,$2) ON CONFLICT(nick) DO NOTHING',[nick,new Date().toISOString()]);await bindDevice(nick,device);const u=await getUser(nick);res.json({ok:true,token:signToken(u,device)});}catch(e){console.error(e);res.status(e.busy?503:500).json({ok:false,error:e.busy?'Сервер занят, повторите позже':'Ошибка сервера'});}});

  app.post('/api/login',json,rl('login',8,900e3,true),authDelay,async(req,res)=>{try{const nick=String(req.body.nick||'').trim().toLowerCase(),pw=String(req.body.password||''),device=req.body.device;if(!deviceOk(device)||!NICK.test(nick))return res.json({ok:false,error:'Неверный ник или пароль'});const u=await getUser(nick);const salt=u?u.pass_salt:'00'.repeat(16);const h=await hashPw(pw.slice(0,128),salt);if(!u||!safeEq(h,u.pass_hash)){failedAuth(req);return res.json({ok:false,error:'Неверный ник или пароль'});}if(u.banned)return res.json({ok:false,error:'Аккаунт заблокирован'});if(!(await bindDevice(nick,device)))return res.json({ok:false,error:'Достигнут лимит устройств для этого аккаунта ('+MAX_DEVICES+')'});res.json({ok:true,token:signToken(u,device)});}catch(e){console.error(e);res.status(500).json({ok:false,error:'Ошибка сервера'});}});

  async function auth(req,res,next){const p=verifyToken(req.body&&req.body.token);if(!p||p.d!==req.body.device)return res.status(401).json({ok:false,error:'Сессия истекла, войдите заново'});const u=await getUser(p.n);if(!u||u.banned)return res.status(401).json({ok:false,error:'Сессия недействительна'});const dv=await pool.query('SELECT 1 FROM devices WHERE nick=$1 AND device=$2',[p.n,p.d]);if(!dv.rows.length)return res.status(401).json({ok:false,error:'Устройство не привязано'});req.user=u;req.device=p.d;next();}
  const wrap=fn=>(req,res,next)=>fn(req,res,next).catch(e=>{console.error(e);res.status(500).json({ok:false,error:'Ошибка сервера'});});
  const perUser=(name,max,windowMs)=>(req,res,next)=>limited(name+'|u|'+req.user.nick,max,windowMs)?res.status(429).json({ok:false,error:'Слишком много попыток, подождите немного'}):next();
  app.post('/api/refresh',json,rl('ref',30,3600e3,false),wrap(auth),(req,res)=>res.json({ok:true,token:signToken(req.user,req.device)}));

  app.post('/api/redeem',json,rl('redeem',10,3600e3,false),wrap(auth),perUser('redeem',10,3600e3),async(req,res)=>{const code=String(req.body.code||'').trim().toUpperCase();if(!CODE_RE.test(code))return res.json({ok:false,error:'Неверный формат кода (XXXX-XXXX-XXXX)'});const result=await redeemPromo(sha256(code),req.user.nick);if(!result||result.ok!==true)return res.json({ok:false,error:result?.error||'Промокод не найден'});const u=await getUser(req.user.nick);res.json({ok:true,tier:result.tier,duration:result.duration,token:signToken(u,req.device)});});

  app.post('/api/app',json,rl('app',20,3600e3,false),wrap(auth),perUser('app',12,3600e3),async(req,res)=>{const name=String(req.body.name||'');if(!/^[A-Za-z0-9_]{2,40}$/.test(name))return res.status(404).json({ok:false,error:'Приложение не найдено'});const r=await pool.query('SELECT tier,blob FROM apps WHERE name=$1',[name]);if(!r.rows.length)return res.status(404).json({ok:false,error:'Приложение не найдено'});const need=r.rows[0].tier,u=req.user,now=Date.now(),okPlus=Number(u.plus_exp)>now,okPrem=Number(u.premium_exp)>now;if(!(need==='PREMIUM'?(okPrem||okPlus):okPlus))return res.status(403).json({ok:false,error:'Нужна подписка '+(need==='PREMIUM'?'Premium':'Premium+')});const plain=decGcm(master,Buffer.from(r.rows[0].blob,'base64')),key=crypto.randomBytes(32),out=encGcm(key,plain);res.set({'Content-Type':'application/octet-stream','X-App-Key':key.toString('base64')});res.send(out);});


  // Owner-only console. Secrets are SHA-256 digests in Render environment.
  const consoleAccess=new Map();
  const consoleCodeHash=String(env.ADMIN_CONSOLE_CODE_SHA256||'').toLowerCase();
  const dbPasswordHash=String(env.ADMIN_DB_PASSWORD_SHA256||'').toLowerCase();
  function validDigest(expected,supplied){return /^[a-f0-9]{64}$/.test(expected)&&safeEq(sha256(supplied),expected);}
  function checkOwner(req,res,next){
    if(req.user.nick!=='avamint')return res.status(403).json({ok:false,error:'Доступ только для AVAMINT'});
    next();
  }
  function consoleSession(req,res,next){
    const id=String(req.get('x-console-session')||'');
    const entry=consoleAccess.get(id);
    if(!entry||entry.exp<=Date.now()||entry.nick!==req.user.nick||entry.device!==req.device)
      return res.status(403).json({ok:false,error:'Консоль заблокирована. Введите код снова'});
    entry.exp=Date.now()+15*60*1000;req.consoleEntry=entry;next();
  }
  const consoleAuth=[json,rl('console',5,600000,true),wrap(auth),checkOwner];
  app.post('/api/console/unlock',...consoleAuth,(req,res)=>{
    if(!validDigest(consoleCodeHash,String(req.body.code||'')))return res.status(403).json({ok:false,error:'Неверный код консоли'});
    const session=crypto.randomBytes(32).toString('hex');
    consoleAccess.set(session,{nick:req.user.nick,device:req.device,exp:Date.now()+15*60*1000,db:false});
    if(consoleAccess.size>500)for(const [k,v] of consoleAccess)if(v.exp<Date.now())consoleAccess.delete(k);
    res.json({ok:true,session});
  });
  const consoleRoute=[json,wrap(auth),checkOwner,consoleSession];
  app.post('/api/console/db-unlock',...consoleRoute,rl('dbunlock',5,600000,true),(req,res)=>{
    if(!validDigest(dbPasswordHash,String(req.body.password||'')))return res.status(403).json({ok:false,error:'Неверный пароль раздела'});
    req.consoleEntry.db=true;res.json({ok:true});
  });
  function dbGate(req,res,next){if(!req.consoleEntry.db)return res.status(403).json({ok:false,error:'Раздел базы закрыт'});next();}
  app.post('/api/console/users',...consoleRoute,dbGate,wrap(async(req,res)=>{
    const search=String(req.body.search||'').trim().toLowerCase().slice(0,32);
    const r=await pool.query('SELECT u.nick,u.banned,e.premium_exp,e.plus_exp FROM users u LEFT JOIN entitlements e ON e.nick=u.nick WHERE u.nick LIKE $1 ORDER BY u.nick LIMIT 100',['%'+search+'%']);
    res.json({ok:true,users:r.rows});
  }));
  app.post('/api/console/user',...consoleRoute,dbGate,wrap(async(req,res)=>{
    const nick=String(req.body.nick||'').toLowerCase();
    if(!NICK.test(nick))return res.status(400).json({ok:false,error:'Неверный ник'});
    const r=await pool.query('SELECT u.nick,u.banned,u.created,e.premium_exp,e.plus_exp,(SELECT count(*)::int FROM devices d WHERE d.nick=u.nick) AS devices FROM users u LEFT JOIN entitlements e ON e.nick=u.nick WHERE u.nick=$1',[nick]);
    if(!r.rows.length)return res.status(404).json({ok:false,error:'Не найден'});
    res.json({ok:true,user:r.rows[0]});
  }));
  app.post('/api/console/grant',...consoleRoute,rl('consolegrant',30,3600000,true),wrap(async(req,res)=>{
    const nick=String(req.body.nick||'').toLowerCase(),tier=String(req.body.tier||''),duration=String(req.body.duration||'');
    if(!NICK.test(nick)||!['PREMIUM','PLUS'].includes(tier)||(!(duration in DUR)&&duration!=='NONE'))
      return res.status(400).json({ok:false,error:'Неверные параметры'});
    const col=tier==='PLUS'?'plus_exp':'premium_exp';
    const r=await pool.query('SELECT premium_exp,plus_exp FROM entitlements WHERE nick=$1',[nick]);
    if(!r.rows.length)return res.status(404).json({ok:false,error:'Пользователь не найден'});
    const current=Number(r.rows[0][col]||0);
    const value=duration==='NONE'?0:duration==='FOREVER'?FOREVER:Math.max(Date.now(),current)+DUR[duration];
    await pool.query(`UPDATE entitlements SET ${col}=$1,updated_at=NOW() WHERE nick=$2`,[value,nick]);
    res.json({ok:true,nick,tier,duration,expires:value});
  }));
  app.post('/api/console/ban',...consoleRoute,dbGate,wrap(async(req,res)=>{
    const nick=String(req.body.nick||'').toLowerCase();
    if(!NICK.test(nick)||nick==='avamint')return res.status(400).json({ok:false,error:'Нельзя изменить этот аккаунт'});
    await pool.query('UPDATE users SET banned=$1 WHERE nick=$2',[req.body.banned===true?1:0,nick]);
    res.json({ok:true});
  }));
  app.post('/api/console/reset-password',...consoleRoute,dbGate,wrap(async(req,res)=>{
    const nick=String(req.body.nick||'').toLowerCase(),password=String(req.body.password||'');
    if(!NICK.test(nick)||password.length<8||password.length>128)return res.status(400).json({ok:false,error:'Пароль: 8–128 символов'});
    const salt=crypto.randomBytes(16).toString('hex'),hash=await hashPw(password,salt);
    const r=await pool.query('UPDATE users SET pass_salt=$1,pass_hash=$2 WHERE nick=$3 RETURNING nick',[salt,hash,nick]);
    if(!r.rows.length)return res.status(404).json({ok:false,error:'Пользователь не найден'});
    await pool.query('DELETE FROM devices WHERE nick=$1',[nick]);res.json({ok:true});
  }));

  function admin(req,res,next){if(!adminSecret||adminSecret.length<16||!safeEq(req.get('x-admin-secret')||'',adminSecret)){if(limited('adm|'+req.ip,10,900e3))return res.status(429).end();return res.status(403).json({ok:false,error:'forbidden'});}next();}
  app.post('/api/admin/codes',json,admin,wrap(async(req,res)=>{const tier=req.body.tier==='PLUS'?'PLUS':'PREMIUM',duration=String(req.body.duration||'').toUpperCase();if(!(duration in DUR))return res.status(400).json({ok:false,error:'duration: HOUR|DAY|WEEK|MONTH|YEAR|FOREVER'});const count=Math.min(Math.max(parseInt(req.body.count||1,10),1),500),alphabet='ABCDEFGHJKLMNPQRSTUVWXYZ23456789',codes=[];for(let i=0;i<count;i++){const raw=Array.from(crypto.randomBytes(12),b=>alphabet[b%alphabet.length]).join(''),code=raw.slice(0,4)+'-'+raw.slice(4,8)+'-'+raw.slice(8);await pool.query('INSERT INTO promo_codes(code_hash,tier,duration,created_at) VALUES($1,$2,$3,$4) ON CONFLICT(code_hash) DO NOTHING',[sha256(code),tier,duration,new Date().toISOString()]);codes.push(code);}res.json({ok:true,tier,duration,codes});}));
  app.post('/api/admin/grant',json,admin,wrap(async(req,res)=>{const nick=String(req.body.nick||'').toLowerCase(),tier=req.body.tier==='PLUS'?'PLUS':'PREMIUM',duration=String(req.body.duration||'').toUpperCase();if(!(duration in DUR)&&duration!=='NONE')return res.status(400).json({ok:false,error:'bad duration'});const e=await pool.query('SELECT premium_exp,plus_exp FROM entitlements WHERE nick=$1',[nick]);if(!e.rows.length)return res.status(404).json({ok:false,error:'no such user'});const col=tier==='PLUS'?'plus_exp':'premium_exp',cur=Number(e.rows[0][col]);let nv=duration==='NONE'?0:(duration==='FOREVER'?FOREVER:Math.max(cur,Date.now())+DUR[duration]);await pool.query(`UPDATE entitlements SET ${col}=$1,updated_at=$2 WHERE nick=$3`,[nv,new Date().toISOString(),nick]);res.json({ok:true});}));
  app.post('/api/admin/ban',json,admin,wrap(async(req,res)=>{await pool.query('UPDATE users SET banned=$1 WHERE nick=$2',[req.body.banned===false?0:1,String(req.body.nick||'').toLowerCase()]);res.json({ok:true});}));
  app.post('/api/admin/resetdevices',json,admin,wrap(async(req,res)=>{await pool.query('DELETE FROM devices WHERE nick=$1',[String(req.body.nick||'').toLowerCase()]);res.json({ok:true});}));
  app.put('/api/admin/app/:name/:tier',admin,express.raw({type:()=>true,limit:'200mb'}),wrap(async(req,res)=>{const name=req.params.name,tier=req.params.tier.toUpperCase();if(!/^[A-Za-z0-9_]{2,40}$/.test(name)||!['PREMIUM','PLUS'].includes(tier)||!Buffer.isBuffer(req.body)||req.body.length<1000)return res.status(400).json({ok:false,error:'bad request'});await pool.query('INSERT INTO apps(name,tier,blob,updated) VALUES($1,$2,$3,$4) ON CONFLICT(name) DO UPDATE SET tier=$2,blob=$3,updated=$4',[name,tier,encGcm(master,req.body).toString('base64'),Date.now()]);res.json({ok:true,name,tier,bytes:req.body.length});}));
  app.use((err,req,res,next)=>{if(res.headersSent)return next(err);res.status(err.status&&err.status<500?err.status:500).json({ok:false,error:'Неверный запрос'});});
  app.use((req,res)=>res.status(404).json({ok:false,error:'not found'})); return app;
}

async function migrate(pool){
  await pool.query(`CREATE TABLE IF NOT EXISTS users(nick TEXT PRIMARY KEY, pass_salt TEXT NOT NULL, pass_hash TEXT NOT NULL, banned INTEGER NOT NULL DEFAULT 0, created BIGINT NOT NULL)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS devices(nick TEXT NOT NULL, device TEXT NOT NULL, created BIGINT NOT NULL, PRIMARY KEY(nick,device))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS apps(name TEXT PRIMARY KEY, tier TEXT NOT NULL, blob TEXT NOT NULL, updated BIGINT NOT NULL)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS entitlements(nick TEXT PRIMARY KEY REFERENCES users(nick) ON DELETE CASCADE, premium_exp BIGINT NOT NULL DEFAULT 0, plus_exp BIGINT NOT NULL DEFAULT 0, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS promo_codes(code_hash TEXT PRIMARY KEY, tier TEXT NOT NULL CHECK (tier IN ('PREMIUM','PLUS')), duration TEXT NOT NULL CHECK (duration IN ('HOUR','DAY','WEEK','MONTH','YEAR','FOREVER')), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), redeemed_by TEXT, redeemed_at BIGINT)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_promo_codes_redeemed_by ON promo_codes(redeemed_by)`);
  // Перенос со старой схемы (подписки в users.premium_exp/plus_exp, промокоды в таблице codes). Идемпотентно, ничего не удаляет.
  const has=async(table,col)=>(await pool.query(`SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name=$2`,[table,col])).rows.length>0;
  if(await has('users','premium_exp')){
    await pool.query(`INSERT INTO entitlements(nick,premium_exp,plus_exp,updated_at) SELECT nick,premium_exp,plus_exp,NOW() FROM users ON CONFLICT(nick) DO NOTHING`);
  } else {
    await pool.query(`INSERT INTO entitlements(nick,premium_exp,plus_exp,updated_at) SELECT nick,0,0,NOW() FROM users ON CONFLICT(nick) DO NOTHING`);
  }
  if(await has('codes','code_hash')){
    await pool.query(`INSERT INTO promo_codes(code_hash,tier,duration,created_at,redeemed_by,redeemed_at) SELECT code_hash,tier,duration,NOW(),used_by,used_at FROM codes WHERE tier IN ('PREMIUM','PLUS') AND duration IN ('HOUR','DAY','WEEK','MONTH','YEAR','FOREVER') ON CONFLICT(code_hash) DO NOTHING`);
  }
}
module.exports={createApp,migrate};
if(require.main===module){const {Pool}=require('pg');const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='off'?false:{rejectUnauthorized:process.env.PGSSL!=='insecure'},max:8});migrate(pool).then(()=>{const port=process.env.PORT||3000;createApp(pool).listen(port,()=>console.log('rafix-server on '+port));}).catch(e=>{console.error('startup failed:',e.message);process.exit(1);});}
