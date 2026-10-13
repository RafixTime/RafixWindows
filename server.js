'use strict';
// RafixWindows license / account / app-delivery server (flat layout: no folders).
// ENV: DATABASE_URL, ADMIN_SECRET, TOKEN_PRIVATE_KEY (Ed25519 PKCS8 DER, base64), APP_MASTER_KEY (32 bytes, base64)
const crypto = require('crypto');
const express = require('express');

const FOREVER = 8640000000000000; // max JS date; client maps >= this to "forever"
const DUR = { HOUR: 3600e3, DAY: 864e5, WEEK: 6048e5, MONTH: 2592e6, YEAR: 31536e6, FOREVER: null };
const NICK = /^[a-z0-9_]{3,16}$/;
const CODE_RE = /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/;
const TOKEN_TTL = 7 * 864e5;
const MAX_DEVICES = parseInt(process.env.MAX_DEVICES || '2', 10);

function b64u(buf) { return Buffer.from(buf).toString('base64url'); }
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function safeEq(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function createApp(pool, env) {
  env = env || process.env;
  const privKey = crypto.createPrivateKey({ key: Buffer.from(env.TOKEN_PRIVATE_KEY, 'base64'), format: 'der', type: 'pkcs8' });
  const pubKey = crypto.createPublicKey(privKey);
  const master = Buffer.from(env.APP_MASTER_KEY, 'base64');
  if (master.length !== 32) throw new Error('APP_MASTER_KEY must be 32 bytes (base64)');
  const adminSecret = env.ADMIN_SECRET || '';

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);
  app.use((req, res, next) => {
    res.set({ 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Strict-Transport-Security': 'max-age=31536000' });
    next();
  });

  // ---------- rate limit (in-memory) ----------
  const hits = new Map();
  function limited(key, max, windowMs) {
    const now = Date.now();
    const arr = (hits.get(key) || []).filter(t => now - t < windowMs);
    arr.push(now); hits.set(key, arr);
    if (hits.size > 50000) for (const [k, v] of hits) if (!v.length || now - v[v.length - 1] > windowMs) hits.delete(k);
    return arr.length > max;
  }
  function rl(name, max, windowMs, withNick) {
    return (req, res, next) => {
      const nick = withNick ? String((req.body && req.body.nick) || '').toLowerCase().slice(0, 32) : '';
      if (limited(name + '|ip|' + req.ip, max * 3, windowMs) || (nick && limited(name + '|n|' + nick, max, windowMs)))
        return res.status(429).json({ ok: false, error: 'Слишком много попыток, подождите немного' });
      next();
    };
  }

  // ---------- tokens ----------
  function signToken(u, device) {
    const now = Date.now();
    const payload = { n: u.nick, p: Number(u.premium_exp), x: Number(u.plus_exp), d: device, i: now, e: now + TOKEN_TTL };
    const body = b64u(JSON.stringify(payload));
    const sig = crypto.sign(null, Buffer.from(body), privKey);
    return body + '.' + b64u(sig);
  }
  function verifyToken(tok) {
    try {
      const [body, sig] = String(tok).split('.');
      if (!body || !sig) return null;
      if (!crypto.verify(null, Buffer.from(body), pubKey, Buffer.from(sig, 'base64url'))) return null;
      const p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
      return p.e > Date.now() ? p : null;
    } catch (e) { return null; }
  }
  function deviceOk(d) { return typeof d === 'string' && /^[a-f0-9]{64}$/.test(d); }

  // ---------- password ----------
  function hashPw(pw, saltHex) {
    return crypto.scryptSync(pw, Buffer.from(saltHex, 'hex'), 32, { N: 16384, r: 8, p: 1 }).toString('hex');
  }

  // ---------- app encryption at rest / in transit ----------
  function encGcm(key, plain) {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([c.update(plain), c.final()]);
    return Buffer.concat([iv, ct, c.getAuthTag()]);
  }
  function decGcm(key, blob) {
    const iv = blob.subarray(0, 12), tag = blob.subarray(blob.length - 16), ct = blob.subarray(12, blob.length - 16);
    const d = crypto.createDecipheriv('aes-256-gcm', key, iv); d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]);
  }

  async function getUser(nick) {
    const r = await pool.query('SELECT nick, pass_salt, pass_hash, premium_exp, plus_exp, banned FROM users WHERE nick=$1', [nick]);
    return r.rows[0] || null;
  }
  async function bindDevice(nick, device) {
    const r = await pool.query('SELECT device FROM devices WHERE nick=$1', [nick]);
    if (r.rows.some(x => x.device === device)) return true;
    if (r.rows.length >= MAX_DEVICES) return false;
    await pool.query('INSERT INTO devices(nick, device, created) VALUES ($1,$2,$3)', [nick, device, Date.now()]);
    return true;
  }
  function addTime(cur, dur) {
    cur = Number(cur);
    if (cur >= FOREVER || DUR[dur] === null) return FOREVER;
    return Math.max(cur, Date.now()) + DUR[dur];
  }

  app.get('/', (req, res) => res.json({ status: 'ok', service: 'rafix-server' }));

  const json = express.json({ limit: '8kb' });

  app.post('/api/register', json, rl('reg', 5, 3600e3, false), async (req, res) => {
    try {
      const nick = String(req.body.nick || '').trim().toLowerCase(), pw = String(req.body.password || ''), device = req.body.device;
      if (!NICK.test(nick)) return res.json({ ok: false, error: 'Ник: 3–16 символов, a-z, 0-9, _' });
      if (pw.length < 6 || pw.length > 128) return res.json({ ok: false, error: 'Пароль: минимум 6 символов' });
      if (!deviceOk(device)) return res.status(400).json({ ok: false, error: 'Неверный запрос' });
      const salt = crypto.randomBytes(16).toString('hex');
      if (await getUser(nick)) return res.json({ ok: false, error: 'Такой ник уже занят' });
      try {
        await pool.query('INSERT INTO users(nick, pass_salt, pass_hash, created) VALUES ($1,$2,$3,$4)', [nick, salt, hashPw(pw, salt), Date.now()]);
      } catch (e) {
        if (e && (e.code === '23505' || /duplicate|unique/i.test(e.message))) return res.json({ ok: false, error: 'Такой ник уже занят' });
        throw e;
      }
      await bindDevice(nick, device);
      const u = await getUser(nick);
      res.json({ ok: true, token: signToken(u, device) });
    } catch (e) { console.error(e); res.status(500).json({ ok: false, error: 'Ошибка сервера' }); }
  });

  app.post('/api/login', json, rl('login', 8, 900e3, true), async (req, res) => {
    try {
      const nick = String(req.body.nick || '').trim().toLowerCase(), pw = String(req.body.password || ''), device = req.body.device;
      if (!deviceOk(device) || !NICK.test(nick)) return res.json({ ok: false, error: 'Неверный ник или пароль' });
      const u = await getUser(nick);
      // одинаковое время работы для несуществующего ника
      const salt = u ? u.pass_salt : '00'.repeat(16);
      const h = hashPw(pw.slice(0, 128), salt);
      if (!u || !safeEq(h, u.pass_hash)) return res.json({ ok: false, error: 'Неверный ник или пароль' });
      if (u.banned) return res.json({ ok: false, error: 'Аккаунт заблокирован' });
      if (!(await bindDevice(nick, device)))
        return res.json({ ok: false, error: 'Достигнут лимит устройств для этого аккаунта (' + MAX_DEVICES + ')' });
      res.json({ ok: true, token: signToken(u, device) });
    } catch (e) { console.error(e); res.status(500).json({ ok: false, error: 'Ошибка сервера' }); }
  });

  async function auth(req, res, next) {
    const p = verifyToken(req.body && req.body.token);
    if (!p || p.d !== req.body.device) return res.status(401).json({ ok: false, error: 'Сессия истекла, войдите заново' });
    const u = await getUser(p.n);
    if (!u || u.banned) return res.status(401).json({ ok: false, error: 'Сессия недействительна' });
    const dv = await pool.query('SELECT 1 FROM devices WHERE nick=$1 AND device=$2', [p.n, p.d]);
    if (!dv.rows.length) return res.status(401).json({ ok: false, error: 'Устройство не привязано' });
    req.user = u; req.device = p.d; next();
  }
  const wrap = fn => (req, res, next) => fn(req, res, next).catch(e => { console.error(e); res.status(500).json({ ok: false, error: 'Ошибка сервера' }); });

  app.post('/api/refresh', json, rl('ref', 30, 3600e3, false), wrap(auth), (req, res) =>
    res.json({ ok: true, token: signToken(req.user, req.device) }));

  app.post('/api/redeem', json, rl('redeem', 10, 3600e3, false), wrap(auth), async (req, res) => {
    const code = String(req.body.code || '').trim().toUpperCase();
    if (!CODE_RE.test(code)) return res.json({ ok: false, error: 'Неверный формат кода (XXXX-XXXX-XXXX)' });
    const h = sha256(code);
    const c = await pool.connect();
    try {
      await c.query('BEGIN');
      const r = await c.query('UPDATE codes SET used_by=$1, used_at=$2 WHERE code_hash=$3 AND used_by IS NULL RETURNING tier, duration', [req.user.nick, Date.now(), h]);
      if (!r.rows.length) {
        await c.query('ROLLBACK');
        const ex = await pool.query('SELECT 1 FROM codes WHERE code_hash=$1', [h]);
        return res.json({ ok: false, error: ex.rows.length ? 'Этот промокод уже использован' : 'Промокод не найден' });
      }
      const { tier, duration } = r.rows[0];
      const col = tier === 'PLUS' ? 'plus_exp' : 'premium_exp';
      const cur = await c.query('SELECT ' + col + ' AS v FROM users WHERE nick=$1 FOR UPDATE', [req.user.nick]);
      const nv = addTime(cur.rows[0].v, duration);
      await c.query('UPDATE users SET ' + col + '=$1 WHERE nick=$2', [nv, req.user.nick]);
      await c.query('COMMIT');
      const u = await getUser(req.user.nick);
      res.json({ ok: true, tier, duration, token: signToken(u, req.device) });
    } catch (e) { try { await c.query('ROLLBACK'); } catch (_) {} throw e; }
    finally { c.release(); }
  });

  // выдача приложения: только при действующей подписке (проверка по БД, не по токену)
  app.post('/api/app', json, rl('app', 20, 3600e3, false), wrap(auth), async (req, res) => {
    const name = String(req.body.name || '');
    const r = await pool.query('SELECT tier, blob FROM apps WHERE name=$1', [name]);
    if (!r.rows.length) return res.status(404).json({ ok: false, error: 'Приложение не найдено' });
    const need = r.rows[0].tier;
    const u = req.user, now = Date.now();
    const okPlus = Number(u.plus_exp) > now, okPrem = Number(u.premium_exp) > now;
    if (!(need === 'PREMIUM' ? (okPrem || okPlus) : okPlus)) return res.status(403).json({ ok: false, error: 'Нужна подписка ' + (need === 'PREMIUM' ? 'Premium' : 'Premium+') });
    const plain = decGcm(master, Buffer.from(r.rows[0].blob, 'base64'));
    const key = crypto.randomBytes(32); // новый ключ на каждую выдачу
    const out = encGcm(key, plain);
    res.set({ 'Content-Type': 'application/octet-stream', 'X-App-Key': key.toString('base64') });
    res.send(out);
  });

  // ---------- admin ----------
  function admin(req, res, next) {
    if (!adminSecret || adminSecret.length < 16 || !safeEq(req.get('x-admin-secret') || '', adminSecret)) {
      if (limited('adm|' + req.ip, 10, 900e3)) return res.status(429).end();
      return res.status(403).json({ ok: false, error: 'forbidden' });
    }
    next();
  }
  app.post('/api/admin/codes', json, admin, wrap(async (req, res) => {
    const tier = req.body.tier === 'PLUS' ? 'PLUS' : 'PREMIUM';
    const duration = String(req.body.duration || '').toUpperCase();
    if (!(duration in DUR)) return res.status(400).json({ ok: false, error: 'duration: HOUR|DAY|WEEK|MONTH|YEAR|FOREVER' });
    const count = Math.min(Math.max(parseInt(req.body.count || 1, 10), 1), 500);
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const codes = [];
    for (let i = 0; i < count; i++) {
      const raw = Array.from(crypto.randomBytes(12), b => alphabet[b % alphabet.length]).join('');
      const code = raw.slice(0, 4) + '-' + raw.slice(4, 8) + '-' + raw.slice(8);
      await pool.query('INSERT INTO codes(code_hash, tier, duration, created) VALUES ($1,$2,$3,$4)', [sha256(code), tier, duration, Date.now()]);
      codes.push(code);
    }
    res.json({ ok: true, tier, duration, codes });
  }));
  app.post('/api/admin/grant', json, admin, wrap(async (req, res) => {
    const nick = String(req.body.nick || '').toLowerCase();
    const tier = req.body.tier === 'PLUS' ? 'PLUS' : 'PREMIUM';
    const duration = String(req.body.duration || '').toUpperCase();
    if (!(duration in DUR) && duration !== 'NONE') return res.status(400).json({ ok: false, error: 'bad duration' });
    const col = tier === 'PLUS' ? 'plus_exp' : 'premium_exp';
    const u = await getUser(nick);
    if (!u) return res.status(404).json({ ok: false, error: 'no such user' });
    const nv = duration === 'NONE' ? 0 : addTime(u[col], duration);
    await pool.query('UPDATE users SET ' + col + '=$1 WHERE nick=$2', [nv, nick]);
    res.json({ ok: true });
  }));
  app.post('/api/admin/ban', json, admin, wrap(async (req, res) => {
    await pool.query('UPDATE users SET banned=$1 WHERE nick=$2', [req.body.banned === false ? 0 : 1, String(req.body.nick || '').toLowerCase()]);
    res.json({ ok: true });
  }));
  app.post('/api/admin/resetdevices', json, admin, wrap(async (req, res) => {
    await pool.query('DELETE FROM devices WHERE nick=$1', [String(req.body.nick || '').toLowerCase()]);
    res.json({ ok: true });
  }));
  app.put('/api/admin/app/:name/:tier', admin, express.raw({ type: () => true, limit: '200mb' }), wrap(async (req, res) => {
    const name = req.params.name, tier = req.params.tier.toUpperCase();
    if (!/^[A-Za-z0-9_]{2,40}$/.test(name) || !['PREMIUM', 'PLUS'].includes(tier) || !Buffer.isBuffer(req.body) || req.body.length < 1000)
      return res.status(400).json({ ok: false, error: 'bad request' });
    await pool.query('INSERT INTO apps(name, tier, blob, updated) VALUES ($1,$2,$3,$4) ON CONFLICT (name) DO UPDATE SET tier=$2, blob=$3, updated=$4',
      [name, tier, encGcm(master, req.body).toString('base64'), Date.now()]);
    res.json({ ok: true, name, tier, bytes: req.body.length });
  }));

  app.use((req, res) => res.status(404).json({ ok: false, error: 'not found' }));
  return app;
}

async function migrate(pool) {
  await pool.query(`CREATE TABLE IF NOT EXISTS users(
    nick TEXT PRIMARY KEY, pass_salt TEXT NOT NULL, pass_hash TEXT NOT NULL,
    premium_exp BIGINT NOT NULL DEFAULT 0, plus_exp BIGINT NOT NULL DEFAULT 0,
    banned INTEGER NOT NULL DEFAULT 0, created BIGINT NOT NULL)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS devices(
    nick TEXT NOT NULL, device TEXT NOT NULL, created BIGINT NOT NULL, PRIMARY KEY(nick, device))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS codes(
    code_hash TEXT PRIMARY KEY, tier TEXT NOT NULL, duration TEXT NOT NULL,
    used_by TEXT, used_at BIGINT, created BIGINT NOT NULL)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS apps(
    name TEXT PRIMARY KEY, tier TEXT NOT NULL, blob TEXT NOT NULL, updated BIGINT NOT NULL)`);
}

module.exports = { createApp, migrate };

if (require.main === module) {
  const { Pool } = require('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSL === 'off' ? false : { rejectUnauthorized: false }, max: 8 });
  migrate(pool).then(() => {
    const port = process.env.PORT || 3000;
    createApp(pool).listen(port, () => console.log('rafix-server on ' + port));
  }).catch(e => { console.error('startup failed:', e.message); process.exit(1); });
}
