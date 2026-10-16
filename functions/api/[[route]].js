const enc = new TextEncoder();
const json = (d, s = 200, h = {}) => new Response(JSON.stringify(d), { status: s, headers: { 'Content-Type': 'application/json', ...h } });
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
async function sign(env, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(env.SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}
async function authed(req, env) {
  const m = (req.headers.get('Cookie') || '').match(/sb=(\d+)\.([\w-]+)/);
  return !!m && +m[1] > Date.now() && m[2] === await sign(env, m[1]);
}
const n = v => Math.max(0, parseInt(v) || 0);
const txt = v => String(v || '').trim().slice(0, 80);

function agg(rows) {
  const a = { enc: rows.length, sur: 0, kil: 0, cap: 0, app: 0, fa: 0, tolf: 0, kia: 0, wia: 0, monthly: Array(12).fill(0), groups: {}, units: {} };
  for (const r of rows) {
    a.sur += r.surrendered; a.kil += r.killed; a.cap += r.captured; a.app += r.apprehended;
    a.fa += r.firearms; a.tolf += r.tolf; a.kia += r.kia; a.wia += r.wia;
    a.monthly[+r.op_date.slice(5, 7) - 1]++;
    const nz = r.surrendered + r.killed + r.captured + r.apprehended;
    a.groups[r.threat_group] = (a.groups[r.threat_group] || 0) + nz;
    const u = a.units[r.unit] ||= { unit: r.unit, area: r.area, enc: 0, neutralized: 0, firearms: 0 };
    u.enc++; u.neutralized += nz; u.firearms += r.firearms;
  }
  a.neutralized = a.sur + a.kil + a.cap + a.app;
  return a;
}

export async function onRequest({ request, env, params }) {
  const route = [].concat(params.route || []);
  const [r0, r1] = route, method = request.method;
  try {
    if (r0 === 'stats' && method === 'GET') {
      const y = n(new URL(request.url).searchParams.get('year')) || new Date().getFullYear();
      const q = year => env.DB.prepare('SELECT * FROM ops WHERE op_date BETWEEN ? AND ?').bind(`${year}-01-01`, `${year}-12-31`).all().then(x => agg(x.results));
      const [cur, prev] = await Promise.all([q(y), q(y - 1)]);
      const t = await env.DB.prepare("SELECT value FROM settings WHERE key='firearms_target'").first();
      return json({
        year: y, target: +(t?.value || 0), cur, prev,
        matrix: Object.values(cur.units).sort((a, b) => b.firearms - a.firearms)
      });
    }
    if (r0 === 'login' && method === 'POST') {
      const { password } = await request.json();
      if (!env.ADMIN_PASSWORD || password !== env.ADMIN_PASSWORD) return json({ error: 'Invalid credentials' }, 401);
      const exp = Date.now() + 12 * 36e5;
      return json({ ok: true }, 200, { 'Set-Cookie': `sb=${exp}.${await sign(env, String(exp))}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=43200` });
    }
    if (r0 === 'logout') return json({ ok: true }, 200, { 'Set-Cookie': 'sb=; Path=/; Max-Age=0' });

    if (!(await authed(request, env))) return json({ error: 'Unauthorized' }, 401);

    if (r0 === 'ops' && method === 'GET') {
      const x = await env.DB.prepare('SELECT * FROM ops ORDER BY op_date DESC, id DESC LIMIT 50').all();
      const t = await env.DB.prepare("SELECT value FROM settings WHERE key='firearms_target'").first();
      return json({ rows: x.results, target: +(t?.value || 0) });
    }
    if (r0 === 'ops' && method === 'POST') {
      const b = await request.json();
      if (!/^\d{4}-\d{2}-\d{2}$/.test(b.op_date) || !txt(b.unit) || !txt(b.threat_group)) return json({ error: 'Date, unit and threat group are required' }, 400);
      await env.DB.prepare('INSERT INTO ops (op_date,unit,area,threat_group,surrendered,killed,captured,apprehended,firearms,tolf,kia,wia) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
        .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.threat_group), n(b.surrendered), n(b.killed), n(b.captured), n(b.apprehended), n(b.firearms), n(b.tolf), n(b.kia), n(b.wia)).run();
      return json({ ok: true });
    }
    if (r0 === 'ops' && method === 'DELETE' && r1) {
      await env.DB.prepare('DELETE FROM ops WHERE id=?').bind(n(r1)).run();
      return json({ ok: true });
    }
    if (r0 === 'target' && method === 'PUT') {
      const { target } = await request.json();
      await env.DB.prepare("INSERT OR REPLACE INTO settings VALUES ('firearms_target', ?)").bind(String(n(target))).run();
      return json({ ok: true });
    }
    return json({ error: 'Not found' }, 404);
  } catch (e) { return json({ error: 'Server error' }, 500); }
}
