'use strict';
// Админ-утилита (запускается у тебя на компьютере, не на Render).
//   set ADMIN_SECRET=...        (Windows: set, Linux/mac: export)
//   node admin.js codes PLUS MONTH 5        -> 5 кодов Premium+ на месяц (PREMIUM|PLUS, HOUR|DAY|WEEK|MONTH|YEAR|FOREVER)
//   node admin.js grant ник PLUS YEAR       -> выдать подписку (duration NONE = забрать)
//   node admin.js upload RafixLauncher PLUS build/RafixLauncher.jar
//   node admin.js upload RafixMusic PLUS build/RafixMusic.jar
//   node admin.js ban ник | unban ник | resetdevices ник
const fs = require('fs');
const BASE = process.env.RAFIX_SERVER || 'https://rafixwindows.onrender.com';
const SECRET = process.env.ADMIN_SECRET;
if (!SECRET) { console.error('Задай переменную окружения ADMIN_SECRET'); process.exit(1); }
const H = { 'x-admin-secret': SECRET };
async function call(path, body) {
  const r = await fetch(BASE + path, { method: 'POST', headers: { ...H, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return r.json();
}
(async () => {
  const [cmd, a, b, c] = process.argv.slice(2);
  let out;
  if (cmd === 'codes') out = await call('/api/admin/codes', { tier: a, duration: b, count: parseInt(c || '1', 10) });
  else if (cmd === 'grant') out = await call('/api/admin/grant', { nick: a, tier: b, duration: c });
  else if (cmd === 'ban') out = await call('/api/admin/ban', { nick: a, banned: true });
  else if (cmd === 'unban') out = await call('/api/admin/ban', { nick: a, banned: false });
  else if (cmd === 'resetdevices') out = await call('/api/admin/resetdevices', { nick: a });
  else if (cmd === 'upload') {
    const buf = fs.readFileSync(c);
    const r = await fetch(`${BASE}/api/admin/app/${a}/${b}`, { method: 'PUT', headers: { ...H, 'content-type': 'application/octet-stream' }, body: buf });
    out = await r.json();
  } else { console.log(fs.readFileSync(__filename, 'utf8').split('\n').slice(1, 11).join('\n')); return; }
  if (out.codes) console.log(out.codes.join('\n')); else console.log(out);
})().catch(e => { console.error(e.message); process.exit(1); });
