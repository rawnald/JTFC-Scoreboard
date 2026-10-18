const enc = new TextEncoder();
const json = (d, s = 200, h = {}) => new Response(JSON.stringify(d), { status: s, headers: { 'Content-Type': 'application/json', ...h } });
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function sign(env, msg) {
  const secret = env.SESSION_SECRET || env.ADMIN_PASSWORD || 'jtfc-session-secret-fallback';
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}

async function authed(req, env) {
  const m = (req.headers.get('Cookie') || '').match(/sb=(\d+)\.([\w-]+)/);
  return !!m && +m[1] > Date.now() && m[2] === await sign(env, m[1]);
}

const n = v => Math.max(0, parseInt(v) || 0);
const txt = (v, max = 120) => String(v || '').trim().slice(0, max);

function getEncounterCount(r) {
  let wm = null;
  if (typeof r.war_materiel === 'string') {
    try { wm = JSON.parse(r.war_materiel); } catch(e){}
  } else if (typeof r.war_materiel === 'object' && r.war_materiel !== null) {
    wm = r.war_materiel;
  }

  // 1. Check structured engagements object in war_materiel
  if (wm && wm.engagements && wm.engagements.encounter !== undefined) {
    return Math.max(0, parseInt(wm.engagements.encounter, 10) || 0);
  }

  // 2. Check engagement_type column
  if (r.engagement_type) {
    const et = String(r.engagement_type).toLowerCase();
    if (et.includes('encounter') || et.includes('government initiated')) {
      const m = et.match(/encounter\s*\((\d+)\)/);
      return m ? Math.max(1, parseInt(m[1], 10)) : 1;
    }
    return 0;
  }

  // 3. Fallback for legacy records without engagement_type specified
  return 1;
}

const STANDARD_THREAT_GROUPS = [
  'BIFF-PSRL', 'BIFF-NPSRL', 'DITG-PSRL', 'DITG-NPSRL', 'ALG', 'LLE',
  'SRC Daguma', 'GF Musa', 'SROC', 'ROC', 'FSMR', 'GF 73', 'Milisyang Bayan', 'UGMO',
  'MILF', 'MNLF'
];

function getBrigade(r) {
  if (typeof r.war_materiel === 'string') {
    try {
      const wm = JSON.parse(r.war_materiel);
      if (wm && wm.brigade) return wm.brigade.trim();
    } catch(e) {}
  } else if (typeof r.war_materiel === 'object' && r.war_materiel?.brigade) {
    return String(r.war_materiel.brigade).trim();
  }
  if (r.unit) {
    const m = r.unit.match(/\((.*?)\)/);
    if (m) return m[1].trim();
    return r.unit.trim();
  }
  return '—';
}

function getProvince(r) {
  if (r.province && r.province.trim()) return r.province.trim();
  if (r.area && r.area.includes(',')) {
    const parts = r.area.split(',');
    return parts[parts.length - 1].trim();
  }
  return r.area ? r.area.trim() : '—';
}

function agg(rows) {
  const initGroups = {};
  for (const g of STANDARD_THREAT_GROUPS) initGroups[g] = 0;
  const a = { enc: 0, sur: 0, kil: 0, cap: 0, app: 0, fa: 0, tolf: 0, kia: 0, wia: 0, monthly: Array(12).fill(0), groups: initGroups, brigades: {}, units: {} };
  for (const r of rows) {
    a.sur += r.surrendered || 0; a.kil += r.killed || 0; a.cap += r.captured || 0; a.app += r.apprehended || 0;
    a.fa += r.firearms || 0; a.tolf += r.tolf || 0; a.kia += r.kia || 0; a.wia += r.wia || 0;

    const encCount = getEncounterCount(r);
    a.enc += encCount;

    if (r.op_date && r.op_date.length >= 7) {
      const mIdx = +r.op_date.slice(5, 7) - 1;
      if (mIdx >= 0 && mIdx < 12) {
        a.monthly[mIdx] += encCount;
      }
    }

    const nz = (r.surrendered || 0) + (r.killed || 0) + (r.captured || 0) + (r.apprehended || 0);
    if (r.threat_group) {
      a.groups[r.threat_group] = (a.groups[r.threat_group] || 0) + nz;
    }

    const bName = getBrigade(r);
    const provName = getProvince(r);
    const b = a.brigades[bName] ||= { brigade: bName, unit: bName, province: provName, area: provName, enc: 0, neutralized: 0, firearms: 0, _provs: new Set() };
    b.enc += encCount;
    b.neutralized += nz;
    b.firearms += (r.firearms || 0);
    if (provName && provName !== '—') b._provs.add(provName);

    const u = a.units[r.unit] ||= { unit: r.unit, area: r.area, enc: 0, neutralized: 0, firearms: 0 };
    u.enc += encCount; u.neutralized += nz; u.firearms += (r.firearms || 0);
  }
  a.neutralized = a.sur + a.kil + a.cap + a.app;
  return a;
}

export async function onRequest({ request, env, params }) {
  const db = env.DB || env.DB_Scoreboard;
  const route = [].concat(params.route || []);
  const [r0, r1] = route, method = request.method;

  try {
    // Public scoreboard statistics
    if (r0 === 'stats' && method === 'GET') {
      const url = new URL(request.url);
      const reqYear = n(url.searchParams.get('year'));
      const startDate = url.searchParams.get('start_date') || (reqYear ? `${reqYear}-01-01` : `${new Date().getFullYear()}-01-01`);
      const endDate = url.searchParams.get('end_date') || (reqYear ? `${reqYear}-12-31` : `${new Date().getFullYear()}-12-31`);
      const threatGroup = (url.searchParams.get('threat_group') || '').trim();
      const province = (url.searchParams.get('province') || '').trim();

      const y = reqYear || parseInt(startDate.slice(0, 4), 10) || new Date().getFullYear();

      // Determine previous year's equivalent date range for comparison
      let prevStartDate = `${y - 1}-01-01`;
      let prevEndDate = `${y - 1}-12-31`;
      if (startDate.startsWith(String(y)) && endDate.startsWith(String(y))) {
        prevStartDate = `${y - 1}${startDate.slice(4)}`;
        prevEndDate = `${y - 1}${endDate.slice(4)}`;
      }

      function filterRows(rows) {
        if (!threatGroup && !province) return rows;
        return rows.filter(r => {
          if (threatGroup && r.threat_group !== threatGroup) return false;
          if (province) {
            const p = getProvince(r).toLowerCase();
            const tp = province.toLowerCase();
            const rp = (r.province || '').toLowerCase();
            const ra = (r.area || '').toLowerCase();
            if (p !== tp && !rp.includes(tp) && !ra.includes(tp)) return false;
          }
          return true;
        });
      }

      const q = (sDate, eDate) => db.prepare('SELECT * FROM ops WHERE op_date BETWEEN ? AND ?')
        .bind(sDate, eDate).all()
        .then(x => agg(filterRows(x.results || [])));

      const [cur, prev, t, tgRows, provRows, yrRows] = await Promise.all([
        q(startDate, endDate),
        q(prevStartDate, prevEndDate),
        db.prepare("SELECT value FROM settings WHERE key='firearms_target'").first().catch(() => null),
        db.prepare("SELECT DISTINCT threat_group FROM ops WHERE threat_group IS NOT NULL AND threat_group != ''").all().catch(() => ({ results: [] })),
        db.prepare("SELECT DISTINCT province FROM ops WHERE province IS NOT NULL AND province != '' UNION SELECT DISTINCT province FROM sleo WHERE province IS NOT NULL AND province != ''").all().catch(() => ({ results: [] })),
        db.prepare("SELECT DISTINCT SUBSTR(op_date, 1, 4) as yr FROM ops WHERE op_date IS NOT NULL AND op_date != '' ORDER BY yr DESC").all().catch(() => ({ results: [] }))
      ]);

      Object.values(cur.brigades).forEach(b => {
        if (b._provs && b._provs.size > 0) {
          b.province = Array.from(b._provs).join(', ');
          b.area = b.province;
        }
        delete b._provs;
      });

      const tgSet = new Set(STANDARD_THREAT_GROUPS);
      (tgRows.results || []).forEach(r => { if (r.threat_group && r.threat_group.trim()) tgSet.add(r.threat_group.trim()); });

      const provSet = new Set(['Maguindanao del Sur', 'Maguindanao del Norte', 'Cotabato', 'Sultan Kudarat', 'South Cotabato', 'Sarangani', 'SGA-BARMM']);
      (provRows.results || []).forEach(r => { if (r.province && r.province.trim()) provSet.add(r.province.trim()); });

      const availableYears = Array.from(new Set([y, new Date().getFullYear(), ...(yrRows.results || []).map(r => +r.yr).filter(Boolean)])).sort((a, b) => b - a);

      return json({
        year: y,
        start_date: startDate,
        end_date: endDate,
        threat_group: threatGroup,
        province: province,
        target: +(t?.value || 0),
        cur,
        prev,
        matrix: Object.values(cur.brigades).sort((a, b) => b.firearms - a.firearms),
        available_threat_groups: Array.from(tgSet).filter(Boolean).sort(),
        available_provinces: Array.from(provSet).filter(Boolean).sort(),
        available_years: availableYears
      });
    }

    // Authentication endpoints
    if (r0 === 'login' && method === 'POST') {
      const { password } = await request.json();
      const expected = (env.ADMIN_PASSWORD || '').trim();
      const actual = (password || '').trim();
      if (!expected || actual !== expected) return json({ error: 'Invalid credentials' }, 401);
      const exp = Date.now() + 12 * 36e5;
      return json({ ok: true }, 200, { 'Set-Cookie': `sb=${exp}.${await sign(env, String(exp))}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=43200` });
    }

    if (r0 === 'logout') return json({ ok: true }, 200, { 'Set-Cookie': 'sb=; Path=/; Max-Age=0' });

    // Protect all remaining admin endpoints
    if (!(await authed(request, env))) return json({ error: 'Unauthorized' }, 401);

    // Firearms annual target
    if (r0 === 'target' && method === 'PUT') {
      const { target } = await request.json();
      await db.prepare("INSERT OR REPLACE INTO settings VALUES ('firearms_target', ?)").bind(String(n(target))).run();
      return json({ ok: true });
    }

    // 1. Combat / Military Operations (ops)
    if (r0 === 'ops') {
      if (method === 'GET') {
        const url = new URL(request.url);
        const y = url.searchParams.get('year');
        let sql = 'SELECT * FROM ops';
        const params = [];
        if (y) {
          sql += ' WHERE op_date LIKE ?';
          params.push(`${y}-%`);
        }
        sql += ' ORDER BY op_date DESC, id DESC LIMIT 500';
        const q = params.length ? db.prepare(sql).bind(...params) : db.prepare(sql);
        const x = await q.all();
        const t = await db.prepare("SELECT value FROM settings WHERE key='firearms_target'").first();
        return json({ rows: x.results, target: +(t?.value || 0) });
      }
      if (method === 'POST') {
        const b = await request.json();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(b.op_date) || !txt(b.unit) || !txt(b.threat_group)) {
          return json({ error: 'Date, Unit, and Threat Group are required' }, 400);
        }
        if (b.fa_breakdown) {
          const bd = b.fa_breakdown;
          const cap = bd.captured || {}, conf = bd.confiscated || {}, sur = bd.surrendered || {}, rec = bd.recovered || {};
          const capCSW = n(cap.csw), capHP = n(cap.hp), capLP = n(cap.lp);
          const confCSW = n(conf.csw), confHP = n(conf.hp), confLP = n(conf.lp);
          const surCSW = n(sur.csw), surHP = n(sur.hp), surLP = n(sur.lp);
          const recCSW = n(rec.csw), recHP = n(rec.hp), recLP = n(rec.lp);

          b.fa_captured = capCSW + capHP + capLP;
          b.fa_confiscated = confCSW + confHP + confLP;
          b.fa_surrendered = surCSW + surHP + surLP;
          b.fa_recovered = recCSW + recHP + recLP;

          b.fa_csw = capCSW + confCSW + surCSW + recCSW;
          b.fa_high_powered = capHP + confHP + surHP + recHP;
          b.fa_low_powered = capLP + confLP + surLP + recLP;

          b.firearms = b.fa_captured + b.fa_confiscated + b.fa_surrendered + b.fa_recovered;

          if (typeof b.war_materiel === 'object' && b.war_materiel !== null) {
            b.war_materiel.fa_breakdown = bd;
          }
        }
        const totalFA = n(b.firearms) || (n(b.fa_captured) + n(b.fa_confiscated) + n(b.fa_surrendered) + n(b.fa_recovered)) || (n(b.fa_csw) + n(b.fa_high_powered) + n(b.fa_low_powered));
        const warMat = typeof b.war_materiel === 'object' ? JSON.stringify(b.war_materiel) : txt(b.war_materiel, 4000);
        await db.prepare(`INSERT INTO ops (
          op_date,unit,area,province,threat_category,threat_group,engagement_type,
          surrendered,killed,enemy_wounded,captured,apprehended,
          firearms,fa_captured,fa_confiscated,fa_surrendered,fa_recovered,
          fa_csw,fa_high_powered,fa_low_powered,tolf,kia,wia,
          war_materiel,remarks
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
          .bind(
            b.op_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.threat_category), txt(b.threat_group), txt(b.engagement_type),
            n(b.surrendered), n(b.killed), n(b.enemy_wounded), n(b.captured), n(b.apprehended),
            totalFA, n(b.fa_captured), n(b.fa_confiscated), n(b.fa_surrendered), n(b.fa_recovered),
            n(b.fa_csw), n(b.fa_high_powered), n(b.fa_low_powered), n(b.tolf), n(b.kia), n(b.wia),
            warMat, txt(b.remarks, 1000)
          ).run();
        return json({ ok: true });
      }
      if (method === 'PUT' && r1) {
        const b = await request.json();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(b.op_date) || !txt(b.unit) || !txt(b.threat_group)) {
          return json({ error: 'Date, Unit, and Threat Group are required' }, 400);
        }
        if (b.fa_breakdown) {
          const bd = b.fa_breakdown;
          const cap = bd.captured || {}, conf = bd.confiscated || {}, sur = bd.surrendered || {}, rec = bd.recovered || {};
          const capCSW = n(cap.csw), capHP = n(cap.hp), capLP = n(cap.lp);
          const confCSW = n(conf.csw), confHP = n(conf.hp), confLP = n(conf.lp);
          const surCSW = n(sur.csw), surHP = n(sur.hp), surLP = n(sur.lp);
          const recCSW = n(rec.csw), recHP = n(rec.hp), recLP = n(rec.lp);

          b.fa_captured = capCSW + capHP + capLP;
          b.fa_confiscated = confCSW + confHP + confLP;
          b.fa_surrendered = surCSW + surHP + surLP;
          b.fa_recovered = recCSW + recHP + recLP;

          b.fa_csw = capCSW + confCSW + surCSW + recCSW;
          b.fa_high_powered = capHP + confHP + surHP + recHP;
          b.fa_low_powered = capLP + confLP + surLP + recLP;

          b.firearms = b.fa_captured + b.fa_confiscated + b.fa_surrendered + b.fa_recovered;

          if (typeof b.war_materiel === 'object' && b.war_materiel !== null) {
            b.war_materiel.fa_breakdown = bd;
          }
        }
        const totalFA = n(b.firearms) || (n(b.fa_captured) + n(b.fa_confiscated) + n(b.fa_surrendered) + n(b.fa_recovered)) || (n(b.fa_csw) + n(b.fa_high_powered) + n(b.fa_low_powered));
        const warMat = typeof b.war_materiel === 'object' ? JSON.stringify(b.war_materiel) : txt(b.war_materiel, 4000);
        await db.prepare(`UPDATE ops SET
          op_date=?,unit=?,area=?,province=?,threat_category=?,threat_group=?,engagement_type=?,
          surrendered=?,killed=?,enemy_wounded=?,captured=?,apprehended=?,
          firearms=?,fa_captured=?,fa_confiscated=?,fa_surrendered=?,fa_recovered=?,
          fa_csw=?,fa_high_powered=?,fa_low_powered=?,tolf=?,kia=?,wia=?,
          war_materiel=?,remarks=?
        WHERE id=?`)
          .bind(
            b.op_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.threat_category), txt(b.threat_group), txt(b.engagement_type),
            n(b.surrendered), n(b.killed), n(b.enemy_wounded), n(b.captured), n(b.apprehended),
            totalFA, n(b.fa_captured), n(b.fa_confiscated), n(b.fa_surrendered), n(b.fa_recovered),
            n(b.fa_csw), n(b.fa_high_powered), n(b.fa_low_powered), n(b.tolf), n(b.kia), n(b.wia),
            warMat, txt(b.remarks, 1000), n(r1)
          ).run();
        return json({ ok: true });
      }
      if (method === 'DELETE' && r1) {
        await db.prepare('DELETE FROM ops WHERE id=?').bind(n(r1)).run();
        return json({ ok: true });
      }
    }

    // 2. Support to Law Enforcement Operations (sleo)
    if (r0 === 'sleo') {
      try { await db.prepare('ALTER TABLE sleo ADD COLUMN enemy_wounded INTEGER DEFAULT 0').run(); } catch(e) {}
      try { await db.prepare('ALTER TABLE sleo ADD COLUMN captured INTEGER DEFAULT 0').run(); } catch(e) {}
      try { await db.prepare('ALTER TABLE sleo ADD COLUMN apprehended INTEGER DEFAULT 0').run(); } catch(e) {}
      try { await db.prepare('ALTER TABLE sleo ADD COLUMN fa_csw INTEGER DEFAULT 0').run(); } catch(e) {}
      try { await db.prepare('ALTER TABLE sleo ADD COLUMN fa_high_powered INTEGER DEFAULT 0').run(); } catch(e) {}
      try { await db.prepare('ALTER TABLE sleo ADD COLUMN fa_low_powered INTEGER DEFAULT 0').run(); } catch(e) {}
      try { await db.prepare('ALTER TABLE sleo ADD COLUMN drugs_grams TEXT').run(); } catch(e) {}
      try { await db.prepare('ALTER TABLE sleo ADD COLUMN drugs_value TEXT').run(); } catch(e) {}
      try { await db.prepare('ALTER TABLE sleo ADD COLUMN war_materiel TEXT').run(); } catch(e) {}
      try { await db.prepare('ALTER TABLE sleo ADD COLUMN province TEXT').run(); } catch(e) {}
      try { await db.prepare('ALTER TABLE sleo ADD COLUMN threat_group TEXT').run(); } catch(e) {}

      if (method === 'GET') {
        const url = new URL(request.url);
        const y = url.searchParams.get('year');
        let sql = 'SELECT * FROM sleo';
        const params = [];
        if (y) {
          sql += ' WHERE op_date LIKE ?';
          params.push(`${y}-%`);
        }
        sql += ' ORDER BY op_date DESC, id DESC LIMIT 500';
        const q = params.length ? db.prepare(sql).bind(...params) : db.prepare(sql);
        const x = await q.all();
        return json({ rows: x.results });
      }
      if (method === 'POST') {
        const b = await request.json();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(b.op_date) || !txt(b.unit) || !txt(b.lead_agency)) {
          return json({ error: 'Date, Unit, and Lead Agency are required' }, 400);
        }
        const app = n(b.apprehended) || n(b.arrested);
        const wnd = n(b.enemy_wounded) || n(b.wounded);
        const cap = n(b.captured);
        const kld = n(b.killed);
        const sur = n(b.surrendered);

        const csw = n(b.fa_csw);
        const hp  = n(b.fa_high_powered);
        const lp  = n(b.fa_low_powered);
        const totalFA = n(b.firearms_seized) || (csw + hp + lp);
        const warMat = typeof b.war_materiel === 'object' ? JSON.stringify(b.war_materiel) : txt(b.war_materiel, 4000);
        const tg = txt(b.threat_group) || txt(b.target_group);
        const tgt = txt(b.target_group) || tg;

        try {
          await db.prepare('INSERT INTO sleo (op_date,unit,area,province,lead_agency,operation_type,threat_group,target_group,arrested,killed,enemy_wounded,surrendered,captured,apprehended,firearms_seized,fa_csw,fa_high_powered,fa_low_powered,drugs_grams,drugs_value,contraband_details,war_materiel,kia,wia,remarks) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
            .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.lead_agency), txt(b.operation_type || 'Law Enforcement Support'), tg, tgt, app, kld, wnd, sur, cap, app, totalFA, csw, hp, lp, txt(b.drugs_grams), txt(b.drugs_value), txt(b.contraband_details, 255), warMat, n(b.kia), n(b.wia), txt(b.remarks, 500)).run();
        } catch(err) {
          try {
            await db.prepare('INSERT INTO sleo (op_date,unit,area,province,lead_agency,operation_type,target_group,arrested,killed,enemy_wounded,surrendered,captured,apprehended,firearms_seized,fa_csw,fa_high_powered,fa_low_powered,drugs_grams,drugs_value,contraband_details,war_materiel,kia,wia,remarks) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
              .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.lead_agency), txt(b.operation_type || 'Law Enforcement Support'), tg || tgt, app, kld, wnd, sur, cap, app, totalFA, csw, hp, lp, txt(b.drugs_grams), txt(b.drugs_value), txt(b.contraband_details, 255), warMat, n(b.kia), n(b.wia), txt(b.remarks, 500)).run();
          } catch(err2) {
            try {
              await db.prepare('INSERT INTO sleo (op_date,unit,area,lead_agency,operation_type,target_group,arrested,killed,enemy_wounded,surrendered,captured,apprehended,firearms_seized,fa_csw,fa_high_powered,fa_low_powered,drugs_grams,drugs_value,contraband_details,war_materiel,kia,wia,remarks) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
                .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.lead_agency), txt(b.operation_type || 'Law Enforcement Support'), tg || tgt, app, kld, wnd, sur, cap, app, totalFA, csw, hp, lp, txt(b.drugs_grams), txt(b.drugs_value), txt(b.contraband_details, 255), warMat, n(b.kia), n(b.wia), txt(b.remarks, 500)).run();
            } catch(err3) {
              try {
                await db.prepare('INSERT INTO sleo (op_date,unit,area,lead_agency,operation_type,target_group,arrested,killed,enemy_wounded,surrendered,captured,apprehended,firearms_seized,fa_csw,fa_high_powered,fa_low_powered,drugs_grams,drugs_value,contraband_details,kia,wia,remarks) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
                  .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.lead_agency), txt(b.operation_type || 'Law Enforcement Support'), tg || tgt, app, kld, wnd, sur, cap, app, totalFA, csw, hp, lp, txt(b.drugs_grams), txt(b.drugs_value), txt(b.contraband_details, 255), n(b.kia), n(b.wia), txt(b.remarks, 500)).run();
              } catch(err4) {
                await db.prepare('INSERT INTO sleo (op_date,unit,area,lead_agency,operation_type,target_group,arrested,killed,surrendered,firearms_seized,contraband_details,kia,wia,remarks) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
                  .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.lead_agency), txt(b.operation_type || 'Law Enforcement Support'), tg || tgt, app, kld, sur, totalFA, txt(b.contraband_details, 255), n(b.kia), n(b.wia), txt(b.remarks, 500)).run();
              }
            }
          }
        }
        return json({ ok: true });
      }
      if (method === 'PUT' && r1) {
        const b = await request.json();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(b.op_date) || !txt(b.unit) || !txt(b.lead_agency)) {
          return json({ error: 'Date, Unit, and Lead Agency are required' }, 400);
        }
        const app = n(b.apprehended) || n(b.arrested);
        const wnd = n(b.enemy_wounded) || n(b.wounded);
        const cap = n(b.captured);
        const kld = n(b.killed);
        const sur = n(b.surrendered);

        const csw = n(b.fa_csw);
        const hp  = n(b.fa_high_powered);
        const lp  = n(b.fa_low_powered);
        const totalFA = n(b.firearms_seized) || (csw + hp + lp);
        const warMat = typeof b.war_materiel === 'object' ? JSON.stringify(b.war_materiel) : txt(b.war_materiel, 4000);
        const tg = txt(b.threat_group) || txt(b.target_group);
        const tgt = txt(b.target_group) || tg;

        try {
          await db.prepare('UPDATE sleo SET op_date=?,unit=?,area=?,province=?,lead_agency=?,operation_type=?,threat_group=?,target_group=?,arrested=?,killed=?,enemy_wounded=?,surrendered=?,captured=?,apprehended=?,firearms_seized=?,fa_csw=?,fa_high_powered=?,fa_low_powered=?,drugs_grams=?,drugs_value=?,contraband_details=?,war_materiel=?,kia=?,wia=?,remarks=? WHERE id=?')
            .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.lead_agency), txt(b.operation_type || 'Law Enforcement Support'), tg, tgt, app, kld, wnd, sur, cap, app, totalFA, csw, hp, lp, txt(b.drugs_grams), txt(b.drugs_value), txt(b.contraband_details, 255), warMat, n(b.kia), n(b.wia), txt(b.remarks, 500), n(r1)).run();
        } catch(err) {
          try {
            await db.prepare('UPDATE sleo SET op_date=?,unit=?,area=?,province=?,lead_agency=?,operation_type=?,target_group=?,arrested=?,killed=?,enemy_wounded=?,surrendered=?,captured=?,apprehended=?,firearms_seized=?,fa_csw=?,fa_high_powered=?,fa_low_powered=?,drugs_grams=?,drugs_value=?,contraband_details=?,war_materiel=?,kia=?,wia=?,remarks=? WHERE id=?')
              .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.lead_agency), txt(b.operation_type || 'Law Enforcement Support'), tg || tgt, app, kld, wnd, sur, cap, app, totalFA, csw, hp, lp, txt(b.drugs_grams), txt(b.drugs_value), txt(b.contraband_details, 255), warMat, n(b.kia), n(b.wia), txt(b.remarks, 500), n(r1)).run();
          } catch(err2) {
            try {
              await db.prepare('UPDATE sleo SET op_date=?,unit=?,area=?,lead_agency=?,operation_type=?,target_group=?,arrested=?,killed=?,enemy_wounded=?,surrendered=?,captured=?,apprehended=?,firearms_seized=?,fa_csw=?,fa_high_powered=?,fa_low_powered=?,drugs_grams=?,drugs_value=?,contraband_details=?,war_materiel=?,kia=?,wia=?,remarks=? WHERE id=?')
                .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.lead_agency), txt(b.operation_type || 'Law Enforcement Support'), tg || tgt, app, kld, wnd, sur, cap, app, totalFA, csw, hp, lp, txt(b.drugs_grams), txt(b.drugs_value), txt(b.contraband_details, 255), warMat, n(b.kia), n(b.wia), txt(b.remarks, 500), n(r1)).run();
            } catch(err3) {
              try {
                await db.prepare('UPDATE sleo SET op_date=?,unit=?,area=?,lead_agency=?,operation_type=?,target_group=?,arrested=?,killed=?,enemy_wounded=?,surrendered=?,captured=?,apprehended=?,firearms_seized=?,fa_csw=?,fa_high_powered=?,fa_low_powered=?,drugs_grams=?,drugs_value=?,contraband_details=?,kia=?,wia=?,remarks=? WHERE id=?')
                  .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.lead_agency), txt(b.operation_type || 'Law Enforcement Support'), tg || tgt, app, kld, wnd, sur, cap, app, totalFA, csw, hp, lp, txt(b.drugs_grams), txt(b.drugs_value), txt(b.contraband_details, 255), n(b.kia), n(b.wia), txt(b.remarks, 500), n(r1)).run();
              } catch(err4) {
                await db.prepare('UPDATE sleo SET op_date=?,unit=?,area=?,lead_agency=?,operation_type=?,target_group=?,arrested=?,killed=?,surrendered=?,firearms_seized=?,contraband_details=?,kia=?,wia=?,remarks=? WHERE id=?')
                  .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.lead_agency), txt(b.operation_type || 'Law Enforcement Support'), tg || tgt, app, kld, sur, totalFA, txt(b.contraband_details, 255), n(b.kia), n(b.wia), txt(b.remarks, 500), n(r1)).run();
              }
            }
          }
        }
        return json({ ok: true });
      }
      if (method === 'DELETE' && r1) {
        await db.prepare('DELETE FROM sleo WHERE id=?').bind(n(r1)).run();
        return json({ ok: true });
      }
    }

    // 3. Turn-Over of Loose Firearms (tolf)
    if (r0 === 'tolf') {
      try { await db.prepare('ALTER TABLE tolf ADD COLUMN province TEXT').run(); } catch(e) {}
      try { await db.prepare('ALTER TABLE tolf ADD COLUMN fa_csw INTEGER DEFAULT 0').run(); } catch(e) {}
      try { await db.prepare('ALTER TABLE tolf ADD COLUMN fa_high_powered INTEGER DEFAULT 0').run(); } catch(e) {}
      try { await db.prepare('ALTER TABLE tolf ADD COLUMN fa_low_powered INTEGER DEFAULT 0').run(); } catch(e) {}
      try { await db.prepare('ALTER TABLE tolf ADD COLUMN war_materiel TEXT').run(); } catch(e) {}

      if (method === 'GET') {
        const url = new URL(request.url);
        const y = url.searchParams.get('year');
        let sql = 'SELECT * FROM tolf';
        const params = [];
        if (y) {
          sql += ' WHERE op_date LIKE ?';
          params.push(`${y}-%`);
        }
        sql += ' ORDER BY op_date DESC, id DESC LIMIT 500';
        const q = params.length ? db.prepare(sql).bind(...params) : db.prepare(sql);
        const x = await q.all();
        return json({ rows: x.results });
      }
      if (method === 'POST') {
        const b = await request.json();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(b.op_date) || !txt(b.unit)) {
          return json({ error: 'Date and Unit are required' }, 400);
        }
        const csw = n(b.fa_csw) || n(b.crew_served);
        const hp  = n(b.fa_high_powered) || n(b.light_weapons);
        const lp  = n(b.fa_low_powered) || n(b.small_arms);
        const totalFA = n(b.firearms_count) || (csw + hp + lp);
        const warMat = typeof b.war_materiel === 'object' ? JSON.stringify(b.war_materiel) : txt(b.war_materiel, 4000);

        try {
          await db.prepare('INSERT INTO tolf (op_date,unit,area,province,source_group,firearms_count,small_arms,light_weapons,crew_served,fa_csw,fa_high_powered,fa_low_powered,explosives_count,war_materiel,facilitated_by,remarks) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
            .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.source_group), totalFA, lp, hp, csw, csw, hp, lp, n(b.explosives_count), warMat, txt(b.facilitated_by), txt(b.remarks, 500)).run();
        } catch(err) {
          try {
            await db.prepare('INSERT INTO tolf (op_date,unit,area,province,source_group,firearms_count,small_arms,light_weapons,crew_served,explosives_count,facilitated_by,remarks) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
              .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.source_group), totalFA, lp, hp, csw, n(b.explosives_count), txt(b.facilitated_by), txt(b.remarks, 500)).run();
          } catch(err2) {
            await db.prepare('INSERT INTO tolf (op_date,unit,area,source_group,firearms_count,small_arms,light_weapons,crew_served,explosives_count,facilitated_by,remarks) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
              .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.source_group), totalFA, lp, hp, csw, n(b.explosives_count), txt(b.facilitated_by), txt(b.remarks, 500)).run();
          }
        }
        return json({ ok: true });
      }
      if (method === 'PUT' && r1) {
        const b = await request.json();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(b.op_date) || !txt(b.unit)) {
          return json({ error: 'Date and Unit are required' }, 400);
        }
        const csw = n(b.fa_csw) || n(b.crew_served);
        const hp  = n(b.fa_high_powered) || n(b.light_weapons);
        const lp  = n(b.fa_low_powered) || n(b.small_arms);
        const totalFA = n(b.firearms_count) || (csw + hp + lp);
        const warMat = typeof b.war_materiel === 'object' ? JSON.stringify(b.war_materiel) : txt(b.war_materiel, 4000);

        try {
          await db.prepare('UPDATE tolf SET op_date=?,unit=?,area=?,province=?,source_group=?,firearms_count=?,small_arms=?,light_weapons=?,crew_served=?,fa_csw=?,fa_high_powered=?,fa_low_powered=?,explosives_count=?,war_materiel=?,facilitated_by=?,remarks=? WHERE id=?')
            .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.source_group), totalFA, lp, hp, csw, csw, hp, lp, n(b.explosives_count), warMat, txt(b.facilitated_by), txt(b.remarks, 500), n(r1)).run();
        } catch(err) {
          try {
            await db.prepare('UPDATE tolf SET op_date=?,unit=?,area=?,province=?,source_group=?,firearms_count=?,small_arms=?,light_weapons=?,crew_served=?,explosives_count=?,facilitated_by=?,remarks=? WHERE id=?')
              .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.source_group), totalFA, lp, hp, csw, n(b.explosives_count), txt(b.facilitated_by), txt(b.remarks, 500), n(r1)).run();
          } catch(err2) {
            await db.prepare('UPDATE tolf SET op_date=?,unit=?,area=?,source_group=?,firearms_count=?,small_arms=?,light_weapons=?,crew_served=?,explosives_count=?,facilitated_by=?,remarks=? WHERE id=?')
              .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.source_group), totalFA, lp, hp, csw, n(b.explosives_count), txt(b.facilitated_by), txt(b.remarks, 500), n(r1)).run();
          }
        }
        return json({ ok: true });
      }
      if (method === 'DELETE' && r1) {
        await db.prepare('DELETE FROM tolf WHERE id=?').bind(n(r1)).run();
        return json({ ok: true });
      }
    }

    // 4. Rido Cases (rido)
    if (r0 === 'rido') {
      try { await db.prepare('ALTER TABLE rido ADD COLUMN province TEXT').run(); } catch(e) {}

      if (method === 'GET') {
        const url = new URL(request.url);
        const y = url.searchParams.get('year');
        let sql = 'SELECT * FROM rido';
        const params = [];
        if (y) {
          sql += ' WHERE case_date LIKE ?';
          params.push(`${y}-%`);
        }
        sql += ' ORDER BY case_date DESC, id DESC LIMIT 500';
        const q = params.length ? db.prepare(sql).bind(...params) : db.prepare(sql);
        const x = await q.all();
        return json({ rows: x.results });
      }
      if (method === 'POST') {
        const b = await request.json();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(b.case_date) || !txt(b.unit) || !txt(b.parties_involved)) {
          return json({ error: 'Date, Unit, and Parties Involved are required' }, 400);
        }
        try {
          await db.prepare('INSERT INTO rido (case_date,unit,area,province,parties_involved,status,casualties_killed,casualties_wounded,firearms_surrendered,mediators,agreement_details,remarks) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
            .bind(b.case_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.parties_involved), txt(b.status || 'Ongoing Mediation'), n(b.casualties_killed), n(b.casualties_wounded), n(b.firearms_surrendered), txt(b.mediators), txt(b.agreement_details, 500), txt(b.remarks, 500)).run();
        } catch(err) {
          await db.prepare('INSERT INTO rido (case_date,unit,area,parties_involved,status,casualties_killed,casualties_wounded,firearms_surrendered,mediators,agreement_details,remarks) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
            .bind(b.case_date, txt(b.unit), txt(b.area), txt(b.parties_involved), txt(b.status || 'Ongoing Mediation'), n(b.casualties_killed), n(b.casualties_wounded), n(b.firearms_surrendered), txt(b.mediators), txt(b.agreement_details, 500), txt(b.remarks, 500)).run();
        }
        return json({ ok: true });
      }
      if (method === 'PUT' && r1) {
        const b = await request.json();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(b.case_date) || !txt(b.unit) || !txt(b.parties_involved)) {
          return json({ error: 'Date, Unit, and Parties Involved are required' }, 400);
        }
        try {
          await db.prepare('UPDATE rido SET case_date=?,unit=?,area=?,province=?,parties_involved=?,status=?,casualties_killed=?,casualties_wounded=?,firearms_surrendered=?,mediators=?,agreement_details=?,remarks=? WHERE id=?')
            .bind(b.case_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.parties_involved), txt(b.status || 'Ongoing Mediation'), n(b.casualties_killed), n(b.casualties_wounded), n(b.firearms_surrendered), txt(b.mediators), txt(b.agreement_details, 500), txt(b.remarks, 500), n(r1)).run();
        } catch(err) {
          await db.prepare('UPDATE rido SET case_date=?,unit=?,area=?,parties_involved=?,status=?,casualties_killed=?,casualties_wounded=?,firearms_surrendered=?,mediators=?,agreement_details=?,remarks=? WHERE id=?')
            .bind(b.case_date, txt(b.unit), txt(b.area), txt(b.parties_involved), txt(b.status || 'Ongoing Mediation'), n(b.casualties_killed), n(b.casualties_wounded), n(b.firearms_surrendered), txt(b.mediators), txt(b.agreement_details, 500), txt(b.remarks, 500), n(r1)).run();
        }
        return json({ ok: true });
      }
      if (method === 'DELETE' && r1) {
        await db.prepare('DELETE FROM rido WHERE id=?').bind(n(r1)).run();
        return json({ ok: true });
      }
    }

    // 5. HADR Operations (hadr)
    if (r0 === 'hadr') {
      if (method === 'GET') {
        const url = new URL(request.url);
        const y = url.searchParams.get('year');
        let sql = 'SELECT * FROM hadr';
        const params = [];
        if (y) {
          sql += ' WHERE op_date LIKE ?';
          params.push(`${y}-%`);
        }
        sql += ' ORDER BY op_date DESC, id DESC LIMIT 500';
        const q = params.length ? db.prepare(sql).bind(...params) : db.prepare(sql);
        const x = await q.all();
        return json({ rows: x.results });
      }
      if (method === 'POST') {
        const b = await request.json();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(b.op_date) || !txt(b.unit) || !txt(b.disaster_type)) {
          return json({ error: 'Date, Unit, and Disaster Type are required' }, 400);
        }
        await db.prepare('INSERT INTO hadr (op_date,unit,area,disaster_type,assisted_families,assisted_individuals,rescued_persons,relief_packs_distributed,personnel_deployed,partner_agencies,remarks) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
          .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.disaster_type), n(b.assisted_families), n(b.assisted_individuals), n(b.rescued_persons), n(b.relief_packs_distributed), n(b.personnel_deployed), txt(b.partner_agencies), txt(b.remarks, 500)).run();
        return json({ ok: true });
      }
      if (method === 'PUT' && r1) {
        const b = await request.json();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(b.op_date) || !txt(b.unit) || !txt(b.disaster_type)) {
          return json({ error: 'Date, Unit, and Disaster Type are required' }, 400);
        }
        await db.prepare('UPDATE hadr SET op_date=?,unit=?,area=?,disaster_type=?,assisted_families=?,assisted_individuals=?,rescued_persons=?,relief_packs_distributed=?,personnel_deployed=?,partner_agencies=?,remarks=? WHERE id=?')
          .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.disaster_type), n(b.assisted_families), n(b.assisted_individuals), n(b.rescued_persons), n(b.relief_packs_distributed), n(b.personnel_deployed), txt(b.partner_agencies), txt(b.remarks, 500), n(r1)).run();
        return json({ ok: true });
      }
      if (method === 'DELETE' && r1) {
        await db.prepare('DELETE FROM hadr WHERE id=?').bind(n(r1)).run();
        return json({ ok: true });
      }
    }

    return json({ error: 'Not found' }, 404);
  } catch (e) {
    return json({ error: e.message || String(e), stack: e.stack }, 500);
  }
}
