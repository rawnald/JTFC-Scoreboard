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

const STANDARD_THREAT_CATEGORIES = [
  'Local Terrorist Groups (LTG)',
  'Communist Terrorist Group (CTG)',
  'PIAGs'
];

const STANDARD_THREAT_GROUPS = [
  'BIFF-PSRL', 'BIFF-NPSRL', 'DITG-PSRL', 'DITG-NPSRL', 'ALG', 'LLE',
  'SRC Daguma', 'GF Musa', 'SROC', 'ROC', 'FSMR', 'GF 73', 'Milisyang Bayan', 'UGMO',
  'MILF', 'MNLF', 'MILF vs MILF', 'MILF vs MNLF', 'MILF vs PAGs', 'MNLF vs PAGs', 'PAGs vs PAGs'
];

const STANDARD_BRIGADES = [
  '601 BDE', '602 BDE', '603 BDE', '1MAR BDE', '1MECH BDE', '1BCT'
];

function cleanBrigadeName(val) {
  if (!val) return '—';
  const str = String(val).trim();
  const lower = str.toLowerCase();
  if (lower.includes('601')) return '601 BDE';
  if (lower.includes('602')) return '602 BDE';
  if (lower.includes('603')) return '603 BDE';
  if (lower.includes('mech')) return '1MECH BDE';
  if (lower.includes('mar')) return '1MAR BDE';
  if (lower.includes('1bct') || lower.includes('bct')) return '1BCT';
  return str;
}

function getBrigade(r) {
  if (r.brigade && typeof r.brigade === 'string' && r.brigade.trim()) return cleanBrigadeName(r.brigade);
  if (typeof r.war_materiel === 'string') {
    try {
      const wm = JSON.parse(r.war_materiel);
      if (wm && wm.brigade) return cleanBrigadeName(wm.brigade);
    } catch(e) {}
  } else if (typeof r.war_materiel === 'object' && r.war_materiel?.brigade) {
    return cleanBrigadeName(r.war_materiel.brigade);
  }
  if (r.unit) {
    const m = r.unit.match(/\((.*?)\)/);
    if (m) return cleanBrigadeName(m[1]);
    return cleanBrigadeName(r.unit);
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

const PROVINCE_TO_REGION = {
  'Maguindanao del Norte': 'BARMM',
  'Maguindanao del Sur': 'BARMM',
  'MDN': 'BARMM',
  'MDS': 'BARMM',
  'SGA-BARMM': 'BARMM',
  'Cotabato City': 'BARMM',
  'Lanao del Sur': 'BARMM',
  'Basilan': 'BARMM',
  'Sulu': 'BARMM',
  'Tawi-Tawi': 'BARMM',
  'North Cotabato': 'Region XII',
  'Cotabato': 'Region XII',
  'South Cotabato': 'Region XII',
  'Sultan Kudarat': 'Region XII',
  'Sarangani': 'Region XII',
  'Saranggani': 'Region XII',
  'Sarangani Province': 'Region XII',
  'General Santos City': 'Region XII'
};

function getRegionForProvince(provName) {
  if (!provName) return '';
  const clean = String(provName).trim();
  if (PROVINCE_TO_REGION[clean]) return PROVINCE_TO_REGION[clean];
  const lower = clean.toLowerCase();
  if (lower.includes('barmm') || lower.includes('maguindanao') || lower.includes('sga') || lower.includes('shariff') || lower.includes('basilan') || lower.includes('sulu') || lower.includes('tawi') || lower.includes('lanao del sur') || lower === 'mds' || lower === 'mdn' || lower.includes('mds') || lower.includes('mdn')) {
    return 'BARMM';
  }
  if (lower.includes('cotabato') || lower.includes('kudarat') || lower.includes('sarangani') || lower.includes('saranggani') || lower.includes('gensan') || lower.includes('general santos') || lower.includes('koronadal') || lower.includes('tacurong') || lower.includes('isulan')) {
    if (lower.includes('cotabato city')) return 'BARMM';
    return 'Region XII';
  }
  if (lower.includes('davao')) return 'Region XI';
  if (lower.includes('bukidnon') || lower.includes('lanao del norte')) return 'Region X';
  return '';
}

function matchRegion(r, targetRegion) {
  if (!targetRegion) return true;
  const p = getProvince(r);
  const reg = getRegionForProvince(p);
  const tr = targetRegion.toLowerCase();
  if (reg && reg.toLowerCase() === tr) return true;
  if ((r.province || '').toLowerCase().includes(tr)) return true;
  if ((r.area || '').toLowerCase().includes(tr)) return true;
  return false;
}

function getOperationsCount(r) {
  let wm = null;
  if (typeof r.war_materiel === 'string') {
    try { wm = JSON.parse(r.war_materiel); } catch(e){}
  } else if (typeof r.war_materiel === 'object' && r.war_materiel !== null) {
    wm = r.war_materiel;
  }
  if (wm && wm.operations !== undefined && Number(wm.operations) > 0) {
    return Number(wm.operations);
  }
  if (wm && wm.total_ops !== undefined && Number(wm.total_ops) > 0) {
    return Number(wm.total_ops);
  }
  if (r.operations && Number(r.operations) > 0) {
    return Number(r.operations);
  }
  return 1;
}

function getThreatCategoryKey(r) {
  const cat = (r.threat_category || '').toLowerCase();
  const grp = (r.threat_group || '').toLowerCase();

  if (cat.includes('ctg') || cat.includes('communist')) return 'ctg';
  if (cat.includes('ltg') || cat.includes('local terrorist')) return 'ltg';
  if (cat.includes('piag') || cat.includes('private armed')) return 'piag';

  const ltgTokens = ['biff', 'ditg', 'alg', 'lle', 'psrl', 'npsrl', 'ltg', 'local terrorist'];
  if (ltgTokens.some(tok => grp.includes(tok))) return 'ltg';

  const ctgTokens = ['daguma', 'musa', 'sroc', 'roc', 'fsmr', 'gf 73', 'gf73', 'milisyang', 'cnt', 'ctg', 'communist', 'npa', 'cpp', 'ugmo'];
  if (ctgTokens.some(tok => grp.includes(tok))) return 'ctg';

  const piagTokens = ['milf', 'mnlf', 'pag', 'piag', 'rido'];
  if (piagTokens.some(tok => grp.includes(tok))) return 'piag';

  return '';
}

function agg(rows) {
  const initGroups = {};
  for (const g of STANDARD_THREAT_GROUPS) initGroups[g] = 0;
  const a = { total_ops: 0, enc: 0, sur: 0, sur_ctg: 0, sur_ltg: 0, sur_piag: 0, kil: 0, cap: 0, app: 0, fa: 0, fa_ctg: 0, fa_ltg: 0, fa_piag: 0, fa_hp: 0, fa_lp: 0, fa_csw: 0, camps: 0, camps_ctg: 0, camps_ltg: 0, camps_piag: 0, tolf: 0, kia: 0, wia: 0, monthly: Array(12).fill(0), monthly_ops: Array(12).fill(0), groups: initGroups, brigades: {}, units: {} };
  for (const r of rows) {
    const opCount = getOperationsCount(r);
    a.total_ops += opCount;
    const rSur = r.surrendered || 0;
    a.sur += rSur;
    if (rSur > 0) {
      const tc = getThreatCategoryKey(r);
      if (tc === 'ctg') a.sur_ctg += rSur;
      else if (tc === 'ltg') a.sur_ltg += rSur;
      else if (tc === 'piag') a.sur_piag += rSur;
    }
    a.kil += r.killed || 0; a.cap += r.captured || 0; a.app += r.apprehended || 0;
    a.tolf += r.tolf || 0; a.kia += r.kia || 0; a.wia += r.wia || 0;

    let hp = r.fa_high_powered || 0;
    let lp = r.fa_low_powered || 0;
    let csw = r.fa_csw || 0;
    let campCount = 0;

    if (r.war_materiel) {
      try {
        const wm = typeof r.war_materiel === 'object' ? r.war_materiel : JSON.parse(r.war_materiel);
        if (wm?.fa_breakdown) {
          const bd = wm.fa_breakdown;
          const cap = bd.captured || {}, conf = bd.confiscated || {}, sur = bd.surrendered || {}, rec = bd.recovered || {};
          csw = (+cap.csw || 0) + (+conf.csw || 0) + (+sur.csw || 0) + (+rec.csw || 0);
          hp = (+cap.hp || 0) + (+conf.hp || 0) + (+sur.hp || 0) + (+rec.hp || 0);
          lp = (+cap.lp || 0) + (+conf.lp || 0) + (+sur.lp || 0) + (+rec.lp || 0);
        }
        if (wm?.enemy_camp) {
          campCount = Number(wm.enemy_camp) || 0;
        }
      } catch(e) {}
    }
    if (!campCount && r.enemy_camp) {
      campCount = Number(r.enemy_camp) || 0;
    }
    if (!campCount && r.war_materiel && typeof r.war_materiel === 'string') {
      const m = r.war_materiel.match(/(\d+)\s*(?:enemy\s*)?camp/i);
      if (m) campCount = parseInt(m[1], 10) || 1;
    }
    if (!campCount && r.remarks && typeof r.remarks === 'string') {
      const m = r.remarks.match(/(\d+)\s*(?:enemy\s*)?camp/i);
      if (m) campCount = parseInt(m[1], 10) || 1;
    }

    a.camps += campCount;
    if (campCount > 0) {
      const tc = getThreatCategoryKey(r);
      if (tc === 'ctg') a.camps_ctg += campCount;
      else if (tc === 'ltg') a.camps_ltg += campCount;
      else if (tc === 'piag') a.camps_piag += campCount;
    }

    a.fa_hp += hp;
    a.fa_lp += lp;
    a.fa_csw += csw;

    const rFa = (r.firearms || 0) || (hp + lp + csw);
    a.fa += rFa;
    if (rFa > 0) {
      const tc = getThreatCategoryKey(r);
      if (tc === 'ctg') a.fa_ctg += rFa;
      else if (tc === 'ltg') a.fa_ltg += rFa;
      else if (tc === 'piag') a.fa_piag += rFa;
    }

    const encCount = getEncounterCount(r);
    a.enc += encCount;

    if (r.op_date && r.op_date.length >= 7) {
      const mIdx = +r.op_date.slice(5, 7) - 1;
      if (mIdx >= 0 && mIdx < 12) {
        a.monthly[mIdx] += encCount;
        a.monthly_ops[mIdx] += opCount;
      }
    }

    const nz = (r.surrendered || 0) + (r.killed || 0) + (r.captured || 0) + (r.apprehended || 0);
    if (r.threat_group) {
      a.groups[r.threat_group] = (a.groups[r.threat_group] || 0) + nz;
    }

    const bName = getBrigade(r);
    const provName = getProvince(r);
    const b = a.brigades[bName] ||= { brigade: bName, unit: bName, province: provName, area: provName, enc: 0, total_ops: 0, neutralized: 0, firearms: 0, fa_hp: 0, fa_lp: 0, fa_csw: 0, sur: 0, sleo: 0, salw: 0, _provs: new Set() };
    b.total_ops = (b.total_ops || 0) + opCount;
    b.enc += encCount;
    b.neutralized += nz;
    b.firearms += (r.firearms || 0);
    b.fa_hp += hp;
    b.fa_lp += lp;
    b.fa_csw += csw;
    b.sur += (r.surrendered || 0);
    if (provName && provName !== '—') b._provs.add(provName);

    const u = a.units[r.unit] ||= { unit: r.unit, area: r.area, enc: 0, total_ops: 0, neutralized: 0, firearms: 0, fa_hp: 0, fa_lp: 0, fa_csw: 0 };
    u.total_ops = (u.total_ops || 0) + opCount;
    u.enc += encCount; u.neutralized += nz; u.firearms += (r.firearms || 0);
    u.fa_hp += hp; u.fa_lp += lp; u.fa_csw += csw;
  }
  a.neutralized = a.sur + a.kil + a.cap + a.app;
  return a;
}

async function getLatestControlNumber(db) {
  try {
    const s = await db.prepare("SELECT value FROM settings WHERE key='latest_control_number'").first();
    if (s && s.value && String(s.value).trim()) return String(s.value).trim();
  } catch(e) {}

  return await syncLatestControlNumberFromDb(db);
}

async function setLatestControlNumber(db, val) {
  if (!val || !String(val).trim()) return;
  try {
    await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('latest_control_number', ?)").bind(String(val).trim()).run();
  } catch(e) {}
}

async function syncLatestControlNumberFromDb(db) {
  const tables = ['incident_reports', 'ops', 'sleo', 'tolf', 'rido', 'hadr'];
  let bestId = -1;
  let bestCtrl = '';

  for (const tbl of tables) {
    try {
      const row = await db.prepare(`SELECT id, control_number FROM ${tbl} WHERE control_number IS NOT NULL AND TRIM(control_number) != '' ORDER BY id DESC LIMIT 1`).first();
      if (row && row.control_number && String(row.control_number).trim()) {
        const idNum = Number(row.id) || 0;
        if (idNum > bestId) {
          bestId = idNum;
          bestCtrl = String(row.control_number).trim();
        }
      }
    } catch(e) {}
  }

  try {
    await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('latest_control_number', ?)").bind(bestCtrl).run();
  } catch(e) {}

  return bestCtrl;
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
      const threatCategory = (url.searchParams.get('threat_category') || url.searchParams.get('threat_group') || '').trim();
      const brigade = (url.searchParams.get('brigade') || '').trim();
      const region = (url.searchParams.get('region') || '').trim();
      const province = (url.searchParams.get('province') || '').trim();

      const y = reqYear || parseInt(startDate.slice(0, 4), 10) || new Date().getFullYear();

      // Determine previous year's equivalent date range for comparison
      let prevStartDate = `${y - 1}-01-01`;
      let prevEndDate = `${y - 1}-12-31`;
      if (startDate.startsWith(String(y)) && endDate.startsWith(String(y))) {
        prevStartDate = `${y - 1}${startDate.slice(4)}`;
        prevEndDate = `${y - 1}${endDate.slice(4)}`;
      }

      function matchThreatCategory(catOrGroup, target) {
        if (!target) return true;
        const t = target.toLowerCase();
        const cg = (catOrGroup || '').toLowerCase();
        if (cg === t || cg.includes(t)) return true;

        const isLTG = t.includes('ltg') || t.includes('local terrorist');
        const isCTG = t.includes('ctg') || t.includes('communist');
        const isPIAG = t.includes('piag');

        if (isLTG) {
          const ltgTokens = ['biff', 'ditg', 'alg', 'lle', 'psrl', 'npsrl', 'ltg', 'local terrorist'];
          if (ltgTokens.some(tok => cg.includes(tok))) return true;
        }
        if (isCTG) {
          const ctgTokens = ['daguma', 'musa', 'sroc', 'roc', 'fsmr', 'gf 73', 'gf73', 'milisyang', 'cnt', 'ctg', 'communist', 'npa', 'cpp'];
          if (ctgTokens.some(tok => cg.includes(tok))) return true;
        }
        if (isPIAG) {
          if (cg.includes('piag') || cg.includes('private armed')) return true;
        }
        return false;
      }

      function filterRows(rows) {
        if (!threatCategory && !brigade && !region && !province) return rows;
        return rows.filter(r => {
          if (threatCategory) {
            const hasCatMatch = r.threat_category && matchThreatCategory(r.threat_category, threatCategory);
            const hasGroupMatch = r.threat_group && matchThreatCategory(r.threat_group, threatCategory);
            if (!hasCatMatch && !hasGroupMatch) return false;
          }
          if (brigade) {
            const b = getBrigade(r).toLowerCase();
            const tb = brigade.toLowerCase();
            const u = (r.unit || '').toLowerCase();
            if (b !== tb && !b.includes(tb) && !u.includes(tb)) return false;
          }
          if (region) {
            if (!matchRegion(r, region)) return false;
          }
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

      function filterTolfRows(rows) {
        if (!threatCategory && !brigade && !region && !province) return rows;
        return rows.filter(r => {
          if (threatCategory) {
            const sg = (r.source_group || '').toLowerCase();
            if (!matchThreatCategory(sg, threatCategory)) return false;
          }
          if (brigade) {
            const b = getBrigade(r).toLowerCase();
            const tb = brigade.toLowerCase();
            const u = (r.unit || '').toLowerCase();
            if (b !== tb && !b.includes(tb) && !u.includes(tb)) return false;
          }
          if (region) {
            if (!matchRegion(r, region)) return false;
          }
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

      function filterSleoRows(rows) {
        if (!threatCategory && !brigade && !region && !province) return rows;
        return rows.filter(r => {
          if (threatCategory) {
            const tg = (r.threat_group || '').toLowerCase();
            const targ = (r.target_group || '').toLowerCase();
            if (!matchThreatCategory(tg, threatCategory) && !matchThreatCategory(targ, threatCategory)) return false;
          }
          if (brigade) {
            const b = getBrigade(r).toLowerCase();
            const tb = brigade.toLowerCase();
            const u = (r.unit || '').toLowerCase();
            if (b !== tb && !b.includes(tb) && !u.includes(tb)) return false;
          }
          if (region) {
            if (!matchRegion(r, region)) return false;
          }
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

      function getMonthlyCounts(rows) {
        const m = Array(12).fill(0);
        for (const r of rows) {
          if (r.op_date && r.op_date.length >= 7) {
            const idx = +r.op_date.slice(5, 7) - 1;
            if (idx >= 0 && idx < 12) m[idx]++;
          }
        }
        return m;
      }

      function getMonthlyFirearms(rows) {
        const m = Array(12).fill(0);
        for (const r of rows) {
          if (r.op_date && r.op_date.length >= 7) {
            const idx = +r.op_date.slice(5, 7) - 1;
            if (idx >= 0 && idx < 12) m[idx] += (r.firearms_count || 0);
          }
        }
        return m;
      }

      function getTolfWarMaterielCount(r) {
        let count = 0;
        if (r.war_materiel) {
          if (typeof r.war_materiel === 'object' && r.war_materiel !== null) {
            const wm = r.war_materiel;
            count = (+wm.ied || 0) + (+wm.uxo || 0) + (+wm.explosives || 0) + (+wm.magazine || 0) + (+wm.ammo || 0);
          } else if (typeof r.war_materiel === 'string') {
            try {
              const wm = JSON.parse(r.war_materiel);
              if (wm && typeof wm === 'object') {
                count = (+wm.ied || 0) + (+wm.uxo || 0) + (+wm.explosives || 0) + (+wm.magazine || 0) + (+wm.ammo || 0);
              }
            } catch (e) {
              const num = parseInt(r.war_materiel, 10);
              if (!isNaN(num) && num > 0) count = num;
            }
          }
        }
        if (!count && r.explosives_count) {
          count = +r.explosives_count || 0;
        }
        return count;
      }

      function getMonthlyTolfWM(rows) {
        const m = Array(12).fill(0);
        for (const r of rows) {
          if (r.op_date && r.op_date.length >= 7) {
            const idx = +r.op_date.slice(5, 7) - 1;
            if (idx >= 0 && idx < 12) m[idx] += getTolfWarMaterielCount(r);
          }
        }
        return m;
      }

      const q = (sDate, eDate) => db.prepare('SELECT * FROM ops WHERE op_date BETWEEN ? AND ?')
        .bind(sDate, eDate).all()
        .then(x => agg(filterRows(x.results || [])));

      const qTolf = (sDate, eDate) => db.prepare('SELECT * FROM tolf WHERE op_date BETWEEN ? AND ?')
        .bind(sDate, eDate).all()
        .then(x => {
          const filtered = filterTolfRows(x.results || []);
          let csw = 0, hp = 0, lp = 0;
          for (const r of filtered) {
            let rCsw = (r.fa_csw || r.crew_served || 0);
            let rHp  = (r.fa_high_powered || r.light_weapons || 0);
            let rLp  = (r.fa_low_powered || r.small_arms || 0);
            if (!rCsw && !rHp && !rLp && r.war_materiel) {
              try {
                const wm = typeof r.war_materiel === 'object' ? r.war_materiel : JSON.parse(r.war_materiel);
                if (wm) {
                  rCsw = +(wm.csw || wm.crew_served || 0);
                  rHp  = +(wm.hp || wm.light_weapons || wm.fa_high_powered || 0);
                  rLp  = +(wm.lp || wm.small_arms || wm.fa_low_powered || 0);
                }
              } catch(e) {}
            }
            csw += rCsw;
            hp  += rHp;
            lp  += rLp;
          }
          return {
            firearms: filtered.reduce((sum, r) => sum + (r.firearms_count || 0), 0),
            fa_csw: csw,
            fa_hp: hp,
            fa_lp: lp,
            monthly: getMonthlyFirearms(filtered),
            wm_monthly: getMonthlyTolfWM(filtered),
            rows: filtered
          };
        })
        .catch(() => ({ firearms: 0, fa_csw: 0, fa_hp: 0, fa_lp: 0, monthly: Array(12).fill(0), wm_monthly: Array(12).fill(0), rows: [] }));

      const qSleo = (sDate, eDate) => db.prepare('SELECT * FROM sleo WHERE op_date BETWEEN ? AND ?')
        .bind(sDate, eDate).all()
        .then(x => {
          const filtered = filterSleoRows(x.results || []);
          let neutralized = 0;
          for (const r of filtered) {
            neutralized += (r.killed || 0) + (r.surrendered || 0) + (r.captured || 0) + (r.apprehended || r.arrested || 0);
          }
          return {
            total: filtered.length,
            neutralized,
            monthly: getMonthlyCounts(filtered),
            rows: filtered
          };
        })
        .catch(() => ({ total: 0, neutralized: 0, monthly: Array(12).fill(0), rows: [] }));

      const [cur, prev, curTolf, prevTolf, curSleo, prevSleo, t, catRows, catGroupRows, provRows, bdeRows, yrRows] = await Promise.all([
        q(startDate, endDate),
        q(prevStartDate, prevEndDate),
        qTolf(startDate, endDate),
        qTolf(prevStartDate, prevEndDate),
        qSleo(startDate, endDate),
        qSleo(prevStartDate, prevEndDate),
        db.prepare("SELECT value FROM settings WHERE key='firearms_target'").first().catch(() => null),
        db.prepare("SELECT DISTINCT threat_category FROM ops WHERE threat_category IS NOT NULL AND threat_category != ''").all().catch(() => ({ results: [] })),
        db.prepare("SELECT DISTINCT threat_category, threat_group FROM ops WHERE threat_group IS NOT NULL AND threat_group != ''").all().catch(() => ({ results: [] })),
        db.prepare("SELECT DISTINCT province FROM ops WHERE province IS NOT NULL AND province != '' UNION SELECT DISTINCT province FROM sleo WHERE province IS NOT NULL AND province != '' UNION SELECT DISTINCT province FROM tolf WHERE province IS NOT NULL AND province != '' UNION SELECT DISTINCT province FROM rido WHERE province IS NOT NULL AND province != ''").all().catch(() => ({ results: [] })),
        db.prepare("SELECT DISTINCT unit, war_materiel FROM ops WHERE unit IS NOT NULL AND unit != '' UNION SELECT DISTINCT unit, war_materiel FROM tolf WHERE unit IS NOT NULL AND unit != ''").all().catch(() => ({ results: [] })),
        db.prepare("SELECT DISTINCT SUBSTR(op_date, 1, 4) as yr FROM ops WHERE op_date IS NOT NULL AND op_date != '' UNION SELECT DISTINCT SUBSTR(op_date, 1, 4) as yr FROM tolf WHERE op_date IS NOT NULL AND op_date != '' ORDER BY yr DESC").all().catch(() => ({ results: [] }))
      ]);

      cur.tolf = curTolf.firearms || cur.tolf || 0;
      cur.tolf_csw = curTolf.fa_csw || 0;
      cur.tolf_hp = curTolf.fa_hp || 0;
      cur.tolf_lp = curTolf.fa_lp || 0;
      prev.tolf = prevTolf.firearms || prev.tolf || 0;
      prev.tolf_csw = prevTolf.fa_csw || 0;
      prev.tolf_hp = prevTolf.fa_hp || 0;
      prev.tolf_lp = prevTolf.fa_lp || 0;
      cur.tolf_monthly = curTolf.monthly || Array(12).fill(0);
      prev.tolf_monthly = prevTolf.monthly || Array(12).fill(0);
      cur.tolf_wm_monthly = curTolf.wm_monthly || Array(12).fill(0);
      prev.tolf_wm_monthly = prevTolf.wm_monthly || Array(12).fill(0);

      cur.sleo = curSleo.total || 0;
      prev.sleo = prevSleo.total || 0;
      cur.sleo_monthly = curSleo.monthly || Array(12).fill(0);
      prev.sleo_monthly = prevSleo.monthly || Array(12).fill(0);

      cur.cmo_neutralized = cur.neutralized || 0;
      cur.sleo_neutralized = curSleo.neutralized || 0;
      cur.total_neutralized = cur.cmo_neutralized + cur.sleo_neutralized;
      cur.neutralized = cur.total_neutralized;

      prev.cmo_neutralized = prev.neutralized || 0;
      prev.sleo_neutralized = prevSleo.neutralized || 0;
      prev.total_neutralized = prev.cmo_neutralized + prev.sleo_neutralized;
      prev.neutralized = prev.total_neutralized;

      (curSleo.rows || []).forEach(r => {
        const bName = getBrigade(r);
        const sleoNz = (r.killed || 0) + (r.surrendered || 0) + (r.captured || 0) + (r.apprehended || r.arrested || 0);
        if (bName && bName !== '—') {
          const provName = getProvince(r);
          const b = cur.brigades[bName] ||= { brigade: bName, unit: bName, province: provName, area: provName, enc: 0, neutralized: 0, firearms: 0, fa_hp: 0, fa_lp: 0, fa_csw: 0, sur: 0, sleo: 0, salw: 0, salw_hp: 0, salw_lp: 0, salw_csw: 0, _provs: new Set() };
          b.sleo = (b.sleo || 0) + 1;
          b.neutralized = (b.neutralized || 0) + sleoNz;
          b.sur = (b.sur || 0) + (r.surrendered || 0);
          if (provName && provName !== '—') b._provs.add(provName);
        }
        const tg = r.threat_group || r.target_group;
        if (sleoNz && tg) {
          cur.groups[tg] = (cur.groups[tg] || 0) + sleoNz;
        }
      });

      (curTolf.rows || []).forEach(r => {
        const bName = getBrigade(r);
        if (bName && bName !== '—') {
          const provName = getProvince(r);
          const b = cur.brigades[bName] ||= { brigade: bName, unit: bName, province: provName, area: provName, enc: 0, neutralized: 0, firearms: 0, fa_hp: 0, fa_lp: 0, fa_csw: 0, sur: 0, sleo: 0, salw: 0, salw_hp: 0, salw_lp: 0, salw_csw: 0, _provs: new Set() };
          b.salw = (b.salw || 0) + (r.firearms_count || 0);
          b.salw_csw = (b.salw_csw || 0) + (r.fa_csw || r.crew_served || 0);
          b.salw_hp  = (b.salw_hp || 0) + (r.fa_high_powered || r.light_weapons || 0);
          b.salw_lp  = (b.salw_lp || 0) + (r.fa_low_powered || r.small_arms || 0);
          if (provName && provName !== '—') b._provs.add(provName);
        }
      });

      STANDARD_BRIGADES.forEach(bName => {
        if (!brigade || bName.toLowerCase().includes(brigade.toLowerCase())) {
          cur.brigades[bName] ||= { brigade: bName, unit: bName, province: '', area: '', enc: 0, total_ops: 0, neutralized: 0, firearms: 0, sur: 0, sleo: 0, salw: 0, _provs: new Set() };
        }
      });

      Object.values(cur.brigades).forEach(b => {
        b.sleo = b.sleo || 0;
        b.salw = b.salw || 0;
        b.firearms = b.firearms || 0;
        b.enc = b.enc || 0;
        b.total_ops = b.total_ops || 0;
        b.sur = b.sur || 0;
        if (b._provs && b._provs.size > 0) {
          b.province = Array.from(b._provs).join(', ');
          b.area = b.province;
        }
        delete b._provs;
      });

      const catSet = new Set(STANDARD_THREAT_CATEGORIES);
      (catRows.results || []).forEach(r => { if (r.threat_category && r.threat_category.trim()) catSet.add(r.threat_category.trim()); });

      const threatCategoryMap = {
        'Local Terrorist Groups (LTG)': ['BIFF-PSRL', 'BIFF-NPSRL', 'DITG-PSRL', 'DITG-NPSRL', 'ALG', 'LLE'],
        'Communist Terrorist Group (CTG)': ['SRC Daguma', 'GF Musa', 'SROC', 'ROC', 'FSMR', 'GF 73', 'Milisyang Bayan', 'UGMO'],
        'PIAGs': ['MILF', 'MNLF', 'MILF vs MILF', 'MILF vs MNLF', 'MILF vs PAGs', 'MNLF vs PAGs', 'PAGs vs PAGs']
      };

      (catGroupRows.results || []).forEach(r => {
        const cat = (r.threat_category || '').trim();
        const grp = (r.threat_group || '').trim();
        if (cat && grp) {
          threatCategoryMap[cat] ||= [];
          if (!threatCategoryMap[cat].includes(grp)) threatCategoryMap[cat].push(grp);
        } else if (grp) {
          if (matchThreatCategory(grp, 'ltg')) {
            if (!threatCategoryMap['Local Terrorist Groups (LTG)'].includes(grp)) threatCategoryMap['Local Terrorist Groups (LTG)'].push(grp);
          } else if (matchThreatCategory(grp, 'ctg')) {
            if (!threatCategoryMap['Communist Terrorist Group (CTG)'].includes(grp)) threatCategoryMap['Communist Terrorist Group (CTG)'].push(grp);
          } else if (matchThreatCategory(grp, 'piag')) {
            if (!threatCategoryMap['PIAGs'].includes(grp)) threatCategoryMap['PIAGs'].push(grp);
          }
        }
      });

      const bdeSet = new Set(STANDARD_BRIGADES);
      (bdeRows.results || []).forEach(r => {
        const b = getBrigade(r);
        if (b && b !== '—') bdeSet.add(b);
      });

      const provSet = new Set();
      const regionSet = new Set(['BARMM', 'Region XII']);
      (provRows.results || []).forEach(r => {
        if (r.province && r.province.trim()) {
          const p = r.province.trim();
          if (p.includes(',')) {
            p.split(',').forEach(sub => {
              const sp = sub.trim();
              if (sp) {
                provSet.add(sp);
                const reg = getRegionForProvince(sp);
                if (reg) regionSet.add(reg);
              }
            });
          } else {
            provSet.add(p);
            const reg = getRegionForProvince(p);
            if (reg) regionSet.add(reg);
          }
        }
      });

      const regionProvinceMap = {};
      Array.from(regionSet).forEach(reg => {
        regionProvinceMap[reg] = [];
      });
      Array.from(provSet).filter(Boolean).sort().forEach(p => {
        const reg = getRegionForProvince(p);
        if (reg && regionProvinceMap[reg]) {
          regionProvinceMap[reg].push(p);
        }
      });

      const availableYears = Array.from(new Set([y, new Date().getFullYear(), ...(yrRows.results || []).map(r => +r.yr).filter(Boolean)])).sort((a, b) => b - a);

      const availCategories = Array.from(catSet).filter(Boolean).sort();

      let matrixList = Object.values(cur.brigades);
      if (brigade) {
        matrixList = matrixList.filter(b => b.brigade.toLowerCase().includes(brigade.toLowerCase()));
      }
      matrixList.sort((a, b) => ((b.firearms || 0) + (b.salw || 0)) - ((a.firearms || 0) + (a.salw || 0)) || (b.enc || 0) - (a.enc || 0) || (b.sleo || 0) - (a.sleo || 0));

      return json({
        year: y,
        start_date: startDate,
        end_date: endDate,
        threat_category: threatCategory,
        threat_group: threatCategory,
        brigade: brigade,
        region: region,
        province: province,
        target: +(t?.value || 0),
        latest_control_number: await getLatestControlNumber(db),
        cur,
        prev,
        matrix: matrixList,
        available_threat_categories: availCategories,
        available_threat_groups: availCategories,
        threat_category_map: threatCategoryMap,
        available_brigades: Array.from(bdeSet).filter(Boolean).sort(),
        available_regions: Array.from(regionSet).filter(Boolean).sort(),
        available_provinces: Array.from(provSet).filter(Boolean).sort(),
        region_province_map: regionProvinceMap,
        available_years: availableYears
      });
    }

    // Public Incident Scoreboard statistics
    if ((r0 === 'incident_stats' || (r0 === 'incident_reports' && r1 === 'stats')) && method === 'GET') {
      const url = new URL(request.url);
      const reqYear = n(url.searchParams.get('year'));
      const startDate = url.searchParams.get('start_date') || (reqYear ? `${reqYear}-01-01` : `${new Date().getFullYear()}-01-01`);
      const endDate = url.searchParams.get('end_date') || (reqYear ? `${reqYear}-12-31` : `${new Date().getFullYear()}-12-31`);
      const threatCategory = (url.searchParams.get('threat_category') || url.searchParams.get('threat_group') || '').trim();
      const brigade = (url.searchParams.get('brigade') || '').trim();
      const region = (url.searchParams.get('region') || '').trim();
      const province = (url.searchParams.get('province') || '').trim();

      const y = reqYear || parseInt(startDate.slice(0, 4), 10) || new Date().getFullYear();

      let prevStartDate = `${y - 1}-01-01`;
      let prevEndDate = `${y - 1}-12-31`;
      if (startDate.startsWith(String(y)) && endDate.startsWith(String(y))) {
        prevStartDate = `${y - 1}${startDate.slice(4)}`;
        prevEndDate = `${y - 1}${endDate.slice(4)}`;
      }

      function matchThreatCategory(catOrGroup, target) {
        if (!target) return true;
        const t = target.toLowerCase();
        const cg = (catOrGroup || '').toLowerCase();
        if (cg === t || cg.includes(t)) return true;

        const isLTG = t.includes('ltg') || t.includes('local terrorist');
        const isCTG = t.includes('ctg') || t.includes('communist');
        const isPIAG = t.includes('piag');

        if (isLTG) {
          const ltgTokens = ['biff', 'ditg', 'alg', 'lle', 'psrl', 'npsrl', 'ltg', 'local terrorist'];
          if (ltgTokens.some(tok => cg.includes(tok))) return true;
        }
        if (isCTG) {
          const ctgTokens = ['daguma', 'musa', 'sroc', 'roc', 'fsmr', 'gf 73', 'gf73', 'milisyang', 'cnt', 'ctg', 'communist', 'npa', 'cpp'];
          if (ctgTokens.some(tok => cg.includes(tok))) return true;
        }
        if (isPIAG) {
          if (cg.includes('piag') || cg.includes('private armed')) return true;
        }
        return false;
      }

      function filterIncidentRows(rows) {
        if (!threatCategory && !brigade && !region && !province) return rows;
        return rows.filter(r => {
          if (threatCategory) {
            const hasCatMatch = r.threat_category && matchThreatCategory(r.threat_category, threatCategory);
            const hasGroupMatch = r.threat_group && matchThreatCategory(r.threat_group, threatCategory);
            if (!hasCatMatch && !hasGroupMatch) return false;
          }
          if (brigade) {
            const b = getBrigade(r).toLowerCase();
            const tb = brigade.toLowerCase();
            const u = (r.unit || '').toLowerCase();
            if (b !== tb && !b.includes(tb) && !u.includes(tb)) return false;
          }
          if (region) {
            if (!matchRegion(r, region)) return false;
          }
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

      function parseEngagements(r) {
        let wm = null;
        if (typeof r.war_materiel === 'string') {
          try { wm = JSON.parse(r.war_materiel); } catch(e){}
        } else if (typeof r.war_materiel === 'object' && r.war_materiel !== null) {
          wm = r.war_materiel;
        }
        const we = (wm && wm.engagements) || {};
        const et = String(r.engagement_type || '').toLowerCase();
        const rem = String(r.remarks || '').toLowerCase();

        const getCount = (key, regexList) => {
          if (we[key] !== undefined && we[key] !== null) {
            return Number(we[key]) || 0;
          }
          for (const rx of regexList) {
            const m = et.match(rx);
            if (m) return m[1] ? Number(m[1]) : 1;
          }
          for (const rx of regexList) {
            if (rem.match(rx)) return 1;
          }
          return 0;
        };

        const h = getCount('harassment', [/harassment\s*(?:\((\d+)\))?/i]);
        const a = getCount('ambush', [/ambush\s*(?:\((\d+)\))?/i]);
        const l = getCount('liquidation', [/liquidation\s*(?:\((\d+)\))?/i, /liquidate[d]?/i]);
        const s = getCount('shooting', [/shooting\s*(?:\((\d+)\))?/i, /shot\s+dead/i]);
        const str = getCount('strafing', [/strafing\s*(?:\((\d+)\))?/i]);
        const c = (Number(we.armed_clash) || Number(we.clash) || 0) || (()=>{
          const m = et.match(/(?:armed\s*clash|clash|encounter)\s*(?:\((\d+)\))?/i);
          return m ? (m[1] ? Number(m[1]) : 1) : (rem.includes('armed clash') ? 1 : 0);
        })();
        const i = (Number(we.ied) || Number(we.ied_explosion) || 0) || (()=>{
          const m = et.match(/(?:ied\s*explosion|ied|explosion)\s*(?:\((\d+)\))?/i);
          return m ? (m[1] ? Number(m[1]) : 1) : (rem.includes('ied explosion') ? 1 : 0);
        })();
        const le = (Number(we.loud_explosion) || 0) || (()=>{
          const m = et.match(/loud\s*explosion\s*(?:\((\d+)\))?/i);
          return m ? (m[1] ? Number(m[1]) : 1) : (rem.includes('loud explosion') ? 1 : 0);
        })();
        const b = (Number(we.bus_bombing) || 0) || (()=>{
          const m = et.match(/bus\s*bomb(?:ing)?\s*(?:\((\d+)\))?/i);
          return m ? (m[1] ? Number(m[1]) : 1) : (rem.includes('bus bombing') ? 1 : 0);
        })();
        const cr = (Number(we.carnapping) || 0) || (()=>{
          const m = et.match(/carnapping\s*(?:\((\d+)\))?/i);
          return m ? (m[1] ? Number(m[1]) : 1) : (rem.includes('carnapping') ? 1 : 0);
        })();
        const ar = (Number(we.active_rido) || Number(we.rido) || 0) || (()=>{
          const m = et.match(/(?:active\s*rido|rido)\s*(?:\((\d+)\))?/i);
          return m ? (m[1] ? Number(m[1]) : 1) : (rem.includes('rido') ? 1 : 0);
        })();
        const oCount = (Number(we.other_incidents) || Number(we.other_act) || Number(we.other_activities) || Number(we.grenade) || 0) || (()=>{
          const m = et.match(/(?:other\s*(?:incident[s]?)?(?:\s*report[s]?)?|other\s*act|grenade\s*(?:throwing)?)\s*(?:\((\d+)\))?/i);
          return m ? (m[1] ? Number(m[1]) : 1) : 0;
        })();

        const isOther = (h === 0 && a === 0 && l === 0 && s === 0 && str === 0 && c === 0 && i === 0 && le === 0 && b === 0 && cr === 0 && ar === 0 && oCount === 0) ? 1 : oCount;

        return {
          harassment: h,
          ambush: a,
          liquidation: l,
          shooting: s,
          strafing: str,
          armed_clash: c,
          ied_explosion: i,
          loud_explosion: le,
          bus_bombing: b,
          carnapping: cr,
          active_rido: ar,
          other_incidents: isOther,
          total_breakdown: h + a + l + s + str + c + i + le + b + cr + ar + isOther
        };
      }

      function getWarMaterielCount(r) {
        let count = 0;
        if (r.war_materiel) {
          if (typeof r.war_materiel === 'object' && r.war_materiel !== null) {
            const wm = r.war_materiel;
            count = (+wm.ied || 0) + (+wm.uxo || 0) + (+wm.explosives || 0) + (+wm.ammo || 0) + (+wm.magazine || 0);
          } else if (typeof r.war_materiel === 'string') {
            try {
              const wm = JSON.parse(r.war_materiel);
              if (wm && typeof wm === 'object') {
                count = (+wm.ied || 0) + (+wm.uxo || 0) + (+wm.explosives || 0) + (+wm.ammo || 0) + (+wm.magazine || 0);
              }
            } catch(e) {}
          }
        }
        return count;
      }

      function aggIncidents(rows) {
        const initGroups = {};
        for (const g of STANDARD_THREAT_GROUPS) initGroups[g] = 0;

        const a = {
          total_records: rows.length,
          total_incidents: 0,
          harassment: 0,
          ambush: 0,
          liquidation: 0,
          shooting: 0,
          strafing: 0,
          armed_clash: 0,
          ied_explosion: 0,
          loud_explosion: 0,
          bus_bombing: 0,
          carnapping: 0,
          active_rido: 0,
          other_incidents: 0,
          kia: 0,
          wia: 0,
          govt_casualties: 0,
          govt_afp: 0,
          govt_caa: 0,
          govt_pnp: 0,
          killed: 0,
          enemy_wounded: 0,
          captured: 0,
          apprehended: 0,
          surrendered: 0,
          sur_ctg: 0,
          sur_ltg: 0,
          sur_piag: 0,
          enemy_neutralized: 0,
          firearms: 0,
          fa_ctg: 0,
          fa_ltg: 0,
          fa_piag: 0,
          fa_hp: 0,
          fa_lp: 0,
          fa_csw: 0,
          war_materiel_count: 0,
          monthly: Array(12).fill(0),
          monthly_harassment: Array(12).fill(0),
          monthly_ambush: Array(12).fill(0),
          monthly_armed_clash: Array(12).fill(0),
          monthly_shooting: Array(12).fill(0),
          monthly_casualties: Array(12).fill(0),
          monthly_firearms: Array(12).fill(0),
          groups: initGroups,
          brigades: {}
        };

        for (const r of rows) {
          const eng = parseEngagements(r);
          const rowIncidents = Math.max(1, eng.total_breakdown);
          a.total_incidents += rowIncidents;
          a.harassment += eng.harassment;
          a.ambush += eng.ambush;
          a.liquidation += eng.liquidation;
          a.shooting += eng.shooting;
          a.strafing = (a.strafing || 0) + eng.strafing;
          a.armed_clash += eng.armed_clash;
          a.ied_explosion += eng.ied_explosion;
          a.loud_explosion = (a.loud_explosion || 0) + eng.loud_explosion;
          a.bus_bombing += eng.bus_bombing;
          a.carnapping += eng.carnapping;
          a.active_rido += eng.active_rido;
          a.other_incidents += eng.other_incidents;

          const rKia = r.kia || 0;
          const rWia = r.wia || 0;
          const rGovtCas = rKia + rWia;
          a.kia += rKia;
          a.wia += rWia;
          a.govt_casualties += rGovtCas;

          let rAfp = 0, rCaa = 0, rPnp = 0;
          if (r.war_materiel) {
            try {
              const wm = typeof r.war_materiel === 'object' ? r.war_materiel : JSON.parse(r.war_materiel);
              rAfp = wm?.govt_casualties?.afp ?? wm?.cas_afp ?? wm?.afp ?? ((wm?.govt_casualties?.afp_kia || 0) + (wm?.govt_casualties?.afp_wia || 0));
              rCaa = wm?.govt_casualties?.caa ?? wm?.cas_caa ?? wm?.caa ?? ((wm?.govt_casualties?.caa_kia || 0) + (wm?.govt_casualties?.caa_wia || 0));
              rPnp = wm?.govt_casualties?.pnp ?? wm?.cas_pnp ?? wm?.pnp ?? ((wm?.govt_casualties?.pnp_kia || 0) + (wm?.govt_casualties?.pnp_wia || 0));
            } catch(e) {}
          }
          a.govt_afp = (a.govt_afp || 0) + Number(rAfp);
          a.govt_caa = (a.govt_caa || 0) + Number(rCaa);
          a.govt_pnp = (a.govt_pnp || 0) + Number(rPnp);

          const rKil = r.killed || 0;
          const rEw = r.enemy_wounded || 0;
          const rCap = r.captured || 0;
          const rApp = r.apprehended || 0;
          const rSur = r.surrendered || 0;
          const rNz = rKil + rCap + rApp + rSur;
          a.killed += rKil;
          a.enemy_wounded += rEw;
          a.captured += rCap;
          a.apprehended += rApp;
          a.surrendered += rSur;
          if (rSur > 0) {
            const tc = getThreatCategoryKey(r);
            if (tc === 'ctg') a.sur_ctg = (a.sur_ctg || 0) + rSur;
            else if (tc === 'ltg') a.sur_ltg = (a.sur_ltg || 0) + rSur;
            else if (tc === 'piag') a.sur_piag = (a.sur_piag || 0) + rSur;
          }
          a.enemy_neutralized += rNz;

          let hp = r.fa_high_powered || 0;
          let lp = r.fa_low_powered || 0;
          let csw = r.fa_csw || 0;
          if (!hp && !lp && !csw && r.war_materiel) {
            try {
              const wm = typeof r.war_materiel === 'object' ? r.war_materiel : JSON.parse(r.war_materiel);
              if (wm?.fa_breakdown) {
                const bd = wm.fa_breakdown;
                const cap = bd.captured || {}, conf = bd.confiscated || {}, sur = bd.surrendered || {}, rec = bd.recovered || {};
                csw = (+cap.csw || 0) + (+conf.csw || 0) + (+sur.csw || 0) + (+rec.csw || 0);
                hp = (+cap.hp || 0) + (+conf.hp || 0) + (+sur.hp || 0) + (+rec.hp || 0);
                lp = (+cap.lp || 0) + (+conf.lp || 0) + (+sur.lp || 0) + (+rec.lp || 0);
              }
            } catch(e) {}
          }
          const rFa = (r.firearms || 0) || (hp + lp + csw);
          a.firearms += rFa;
          if (rFa > 0) {
            const tc = getThreatCategoryKey(r);
            if (tc === 'ctg') a.fa_ctg = (a.fa_ctg || 0) + rFa;
            else if (tc === 'ltg') a.fa_ltg = (a.fa_ltg || 0) + rFa;
            else if (tc === 'piag') a.fa_piag = (a.fa_piag || 0) + rFa;
          }
          a.fa_hp += hp;
          a.fa_lp += lp;
          a.fa_csw += csw;

          const wmCount = getWarMaterielCount(r);
          a.war_materiel_count += wmCount;

          if (r.op_date && r.op_date.length >= 7) {
            const mIdx = +r.op_date.slice(5, 7) - 1;
            if (mIdx >= 0 && mIdx < 12) {
              a.monthly[mIdx] += rowIncidents;
              a.monthly_harassment[mIdx] += eng.harassment;
              a.monthly_ambush[mIdx] += eng.ambush;
              a.monthly_armed_clash[mIdx] += eng.armed_clash;
              a.monthly_shooting[mIdx] += eng.shooting;
              a.monthly_casualties[mIdx] += (rGovtCas + rKil + rEw);
              a.monthly_firearms[mIdx] += rFa;
            }
          }

          if (r.threat_group) {
            a.groups[r.threat_group] = (a.groups[r.threat_group] || 0) + rowIncidents;
          }

          const bName = getBrigade(r);
          const provName = getProvince(r);
          const b = a.brigades[bName] ||= {
            brigade: bName,
            unit: bName,
            province: provName,
            area: provName,
            incidents: 0,
            harassment: 0,
            ambush: 0,
            armed_clash: 0,
            shooting: 0,
            ied: 0,
            others: 0,
            govt_casualties: 0,
            kia: 0,
            wia: 0,
            neutralized: 0,
            killed: 0,
            surrendered: 0,
            firearms: 0,
            fa_hp: 0,
            fa_lp: 0,
            fa_csw: 0,
            _provs: new Set()
          };
          b.incidents += rowIncidents;
          b.harassment += eng.harassment;
          b.ambush += eng.ambush;
          b.armed_clash += eng.armed_clash;
          b.shooting += eng.shooting;
          b.ied += eng.ied_explosion;
          b.others += (eng.liquidation + eng.bus_bombing + eng.carnapping + eng.active_rido + eng.other_incidents);
          b.govt_casualties += rGovtCas;
          b.kia += rKia;
          b.wia += rWia;
          b.neutralized += rNz;
          b.killed += rKil;
          b.surrendered += rSur;
          b.firearms += rFa;
          b.fa_hp += hp;
          b.fa_lp += lp;
          b.fa_csw += csw;
          if (provName && provName !== '—') b._provs.add(provName);
        }

        const sumAll = a.harassment + a.ambush + a.liquidation + a.shooting + a.armed_clash + a.ied_explosion + a.bus_bombing + a.carnapping + a.active_rido + a.other_incidents;
        a.total_incidents = Math.max(a.total_incidents, sumAll, a.total_records);

        return a;
      }

      const qIncident = (sDate, eDate) => db.prepare('SELECT * FROM incident_reports WHERE op_date BETWEEN ? AND ?')
        .bind(sDate, eDate).all()
        .then(x => filterIncidentRows(x.results || []))
        .catch(() => []);

      const [curRows, prevRows, catRows, catGroupRows, provRows, bdeRows, yrRows] = await Promise.all([
        qIncident(startDate, endDate),
        qIncident(prevStartDate, prevEndDate),
        db.prepare("SELECT DISTINCT threat_category FROM incident_reports WHERE threat_category IS NOT NULL AND threat_category != ''").all().catch(() => ({ results: [] })),
        db.prepare("SELECT DISTINCT threat_category, threat_group FROM incident_reports WHERE threat_group IS NOT NULL AND threat_group != ''").all().catch(() => ({ results: [] })),
        db.prepare("SELECT DISTINCT province FROM incident_reports WHERE province IS NOT NULL AND TRIM(province) != ''").all().catch(() => ({ results: [] })),
        db.prepare("SELECT DISTINCT unit, war_materiel FROM incident_reports WHERE unit IS NOT NULL AND unit != ''").all().catch(() => ({ results: [] })),
        db.prepare("SELECT DISTINCT SUBSTR(op_date, 1, 4) as yr FROM incident_reports WHERE op_date IS NOT NULL AND op_date != '' ORDER BY yr DESC").all().catch(() => ({ results: [] }))
      ]);

      const cur = aggIncidents(curRows);
      const prev = aggIncidents(prevRows);

      STANDARD_BRIGADES.forEach(bName => {
        if (!brigade || bName.toLowerCase().includes(brigade.toLowerCase())) {
          cur.brigades[bName] ||= {
            brigade: bName, unit: bName, province: '', area: '',
            incidents: 0, harassment: 0, ambush: 0, armed_clash: 0, shooting: 0, ied: 0, others: 0,
            govt_casualties: 0, kia: 0, wia: 0, neutralized: 0, killed: 0, surrendered: 0,
            firearms: 0, fa_hp: 0, fa_lp: 0, fa_csw: 0, _provs: new Set()
          };
        }
      });

      Object.values(cur.brigades).forEach(b => {
        if (b._provs && b._provs.size > 0) {
          b.province = Array.from(b._provs).join(', ');
          b.area = b.province;
        }
        delete b._provs;
      });

      const catSet = new Set(STANDARD_THREAT_CATEGORIES);
      (catRows.results || []).forEach(r => { if (r.threat_category && r.threat_category.trim()) catSet.add(r.threat_category.trim()); });

      const threatCategoryMap = {
        'Local Terrorist Groups (LTG)': ['BIFF-PSRL', 'BIFF-NPSRL', 'DITG-PSRL', 'DITG-NPSRL', 'ALG', 'LLE'],
        'Communist Terrorist Group (CTG)': ['SRC Daguma', 'GF Musa', 'SROC', 'ROC', 'FSMR', 'GF 73', 'Milisyang Bayan', 'UGMO'],
        'PIAGs': ['MILF', 'MNLF', 'MILF vs MILF', 'MILF vs MNLF', 'MILF vs PAGs', 'MNLF vs PAGs', 'PAGs vs PAGs']
      };

      (catGroupRows.results || []).forEach(r => {
        const cat = (r.threat_category || '').trim();
        const grp = (r.threat_group || '').trim();
        if (cat && grp) {
          threatCategoryMap[cat] ||= [];
          if (!threatCategoryMap[cat].includes(grp)) threatCategoryMap[cat].push(grp);
        } else if (grp) {
          if (matchThreatCategory(grp, 'ltg')) {
            if (!threatCategoryMap['Local Terrorist Groups (LTG)'].includes(grp)) threatCategoryMap['Local Terrorist Groups (LTG)'].push(grp);
          } else if (matchThreatCategory(grp, 'ctg')) {
            if (!threatCategoryMap['Communist Terrorist Group (CTG)'].includes(grp)) threatCategoryMap['Communist Terrorist Group (CTG)'].push(grp);
          } else if (matchThreatCategory(grp, 'piag')) {
            if (!threatCategoryMap['PIAGs'].includes(grp)) threatCategoryMap['PIAGs'].push(grp);
          }
        }
      });

      const bdeSet = new Set(STANDARD_BRIGADES);
      (bdeRows.results || []).forEach(r => {
        const b = getBrigade(r);
        if (b && b !== '—') bdeSet.add(b);
      });

      const provSet = new Set();
      const regionSet = new Set();
      (provRows.results || []).forEach(r => {
        if (r.province && r.province.trim()) {
          const p = r.province.trim();
          if (p.includes(',')) {
            p.split(',').forEach(sub => {
              const sp = sub.trim();
              if (sp) {
                provSet.add(sp);
                const reg = getRegionForProvince(sp);
                if (reg) regionSet.add(reg);
              }
            });
          } else {
            provSet.add(p);
            const reg = getRegionForProvince(p);
            if (reg) regionSet.add(reg);
          }
        }
      });

      const regionProvinceMap = {};
      Array.from(regionSet).forEach(reg => {
        regionProvinceMap[reg] = [];
      });
      Array.from(provSet).filter(Boolean).sort().forEach(p => {
        const reg = getRegionForProvince(p);
        if (reg && regionProvinceMap[reg]) {
          regionProvinceMap[reg].push(p);
        }
      });

      const availableYears = Array.from(new Set([y, new Date().getFullYear(), ...(yrRows.results || []).map(r => +r.yr).filter(Boolean)])).sort((a, b) => b - a);
      const availCategories = Array.from(catSet).filter(Boolean).sort();

      let matrixList = Object.values(cur.brigades);
      if (brigade) {
        matrixList = matrixList.filter(b => b.brigade.toLowerCase().includes(brigade.toLowerCase()));
      }
      matrixList.sort((a, b) => (b.incidents - a.incidents) || (b.armed_clash - a.armed_clash) || (b.shooting - a.shooting) || (b.harassment - a.harassment));

      return json({
        year: y,
        start_date: startDate,
        end_date: endDate,
        threat_category: threatCategory,
        threat_group: threatCategory,
        brigade: brigade,
        region: region,
        province: province,
        latest_control_number: await getLatestControlNumber(db),
        cur,
        prev,
        matrix: matrixList,
        rows: curRows.slice(0, 100),
        available_threat_categories: availCategories,
        available_threat_groups: availCategories,
        threat_category_map: threatCategoryMap,
        available_brigades: Array.from(bdeSet).filter(Boolean).sort(),
        available_regions: Array.from(regionSet).filter(Boolean).sort(),
        available_provinces: Array.from(provSet).filter(Boolean).sort(),
        region_province_map: regionProvinceMap,
        available_years: availableYears
      });
    }

    // Latest Control Number endpoint (publicly readable for displays & admin)
    if (r0 === 'latest_control_number') {
      if (method === 'GET') {
        const ctrl = await getLatestControlNumber(db);
        return json({ latest_control_number: ctrl });
      }
      if (method === 'POST' || method === 'PUT') {
        if (!(await authed(request, env))) return json({ error: 'Unauthorized' }, 401);
        const b = await request.json().catch(() => ({}));
        const val = txt(b.control_number || b.latest_control_number, 100);
        if (val) await setLatestControlNumber(db, val);
        return json({ ok: true, latest_control_number: val });
      }
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
      try { await db.prepare('ALTER TABLE ops ADD COLUMN control_number TEXT').run(); } catch(e) {}
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
        const ctrlNum = txt(b.control_number, 100);
        try {
          await db.prepare(`INSERT INTO ops (
            control_number,op_date,unit,area,province,threat_category,threat_group,engagement_type,
            surrendered,killed,enemy_wounded,captured,apprehended,
            firearms,fa_captured,fa_confiscated,fa_surrendered,fa_recovered,
            fa_csw,fa_high_powered,fa_low_powered,tolf,kia,wia,
            war_materiel,remarks
          ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
            .bind(
              ctrlNum, b.op_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.threat_category), txt(b.threat_group), txt(b.engagement_type),
              n(b.surrendered), n(b.killed), n(b.enemy_wounded), n(b.captured), n(b.apprehended),
              totalFA, n(b.fa_captured), n(b.fa_confiscated), n(b.fa_surrendered), n(b.fa_recovered),
              n(b.fa_csw), n(b.fa_high_powered), n(b.fa_low_powered), n(b.tolf), n(b.kia), n(b.wia),
              warMat, txt(b.remarks, 1000)
            ).run();
        } catch(err) {
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
        }
        if (ctrlNum) await setLatestControlNumber(db, ctrlNum);
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
        const ctrlNum = txt(b.control_number, 100);
        try {
          await db.prepare(`UPDATE ops SET
            control_number=?,op_date=?,unit=?,area=?,province=?,threat_category=?,threat_group=?,engagement_type=?,
            surrendered=?,killed=?,enemy_wounded=?,captured=?,apprehended=?,
            firearms=?,fa_captured=?,fa_confiscated=?,fa_surrendered=?,fa_recovered=?,
            fa_csw=?,fa_high_powered=?,fa_low_powered=?,tolf=?,kia=?,wia=?,
            war_materiel=?,remarks=?
          WHERE id=?`)
            .bind(
              ctrlNum, b.op_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.threat_category), txt(b.threat_group), txt(b.engagement_type),
              n(b.surrendered), n(b.killed), n(b.enemy_wounded), n(b.captured), n(b.apprehended),
              totalFA, n(b.fa_captured), n(b.fa_confiscated), n(b.fa_surrendered), n(b.fa_recovered),
              n(b.fa_csw), n(b.fa_high_powered), n(b.fa_low_powered), n(b.tolf), n(b.kia), n(b.wia),
              warMat, txt(b.remarks, 1000), n(r1)
            ).run();
        } catch(err) {
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
        }
        if (ctrlNum) await setLatestControlNumber(db, ctrlNum);
        return json({ ok: true });
      }
      if (method === 'DELETE' && r1) {
        await db.prepare('DELETE FROM ops WHERE id=?').bind(n(r1)).run();
        await syncLatestControlNumberFromDb(db);
        return json({ ok: true });
      }
    }

    // 2. Support to Law Enforcement Operations (sleo)
    if (r0 === 'sleo') {
      try { await db.prepare('ALTER TABLE sleo ADD COLUMN control_number TEXT').run(); } catch(e) {}
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
        const ctrlNum = txt(b.control_number, 100);

        try {
          await db.prepare('INSERT INTO sleo (control_number,op_date,unit,area,province,lead_agency,operation_type,threat_group,target_group,arrested,killed,enemy_wounded,surrendered,captured,apprehended,firearms_seized,fa_csw,fa_high_powered,fa_low_powered,drugs_grams,drugs_value,contraband_details,war_materiel,kia,wia,remarks) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
            .bind(ctrlNum, b.op_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.lead_agency), txt(b.operation_type || 'Law Enforcement Support'), tg, tgt, app, kld, wnd, sur, cap, app, totalFA, csw, hp, lp, txt(b.drugs_grams), txt(b.drugs_value), txt(b.contraband_details, 255), warMat, n(b.kia), n(b.wia), txt(b.remarks, 500)).run();
        } catch(err0) {
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
        }
        if (ctrlNum) await setLatestControlNumber(db, ctrlNum);
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
        const ctrlNum = txt(b.control_number, 100);

        try {
          await db.prepare('UPDATE sleo SET control_number=?,op_date=?,unit=?,area=?,province=?,lead_agency=?,operation_type=?,threat_group=?,target_group=?,arrested=?,killed=?,enemy_wounded=?,surrendered=?,captured=?,apprehended=?,firearms_seized=?,fa_csw=?,fa_high_powered=?,fa_low_powered=?,drugs_grams=?,drugs_value=?,contraband_details=?,war_materiel=?,kia=?,wia=?,remarks=? WHERE id=?')
            .bind(ctrlNum, b.op_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.lead_agency), txt(b.operation_type || 'Law Enforcement Support'), tg, tgt, app, kld, wnd, sur, cap, app, totalFA, csw, hp, lp, txt(b.drugs_grams), txt(b.drugs_value), txt(b.contraband_details, 255), warMat, n(b.kia), n(b.wia), txt(b.remarks, 500), n(r1)).run();
        } catch(err0) {
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
        }
        if (ctrlNum) await setLatestControlNumber(db, ctrlNum);
        return json({ ok: true });
      }
      if (method === 'DELETE' && r1) {
        await db.prepare('DELETE FROM sleo WHERE id=?').bind(n(r1)).run();
        await syncLatestControlNumberFromDb(db);
        return json({ ok: true });
      }
    }

    // 3. Turn-Over of Loose Firearms (tolf)
    if (r0 === 'tolf') {
      try { await db.prepare('ALTER TABLE tolf ADD COLUMN control_number TEXT').run(); } catch(e) {}
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
        const ctrlNum = txt(b.control_number, 100);

        try {
          await db.prepare('INSERT INTO tolf (control_number,op_date,unit,area,province,source_group,firearms_count,small_arms,light_weapons,crew_served,fa_csw,fa_high_powered,fa_low_powered,explosives_count,war_materiel,facilitated_by,remarks) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
            .bind(ctrlNum, b.op_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.source_group), totalFA, lp, hp, csw, csw, hp, lp, n(b.explosives_count), warMat, txt(b.facilitated_by), txt(b.remarks, 500)).run();
        } catch(err0) {
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
        }
        if (ctrlNum) await setLatestControlNumber(db, ctrlNum);
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
        const ctrlNum = txt(b.control_number, 100);

        try {
          await db.prepare('UPDATE tolf SET control_number=?,op_date=?,unit=?,area=?,province=?,source_group=?,firearms_count=?,small_arms=?,light_weapons=?,crew_served=?,fa_csw=?,fa_high_powered=?,fa_low_powered=?,explosives_count=?,war_materiel=?,facilitated_by=?,remarks=? WHERE id=?')
            .bind(ctrlNum, b.op_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.source_group), totalFA, lp, hp, csw, csw, hp, lp, n(b.explosives_count), warMat, txt(b.facilitated_by), txt(b.remarks, 500), n(r1)).run();
        } catch(err0) {
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
        }
        if (ctrlNum) await setLatestControlNumber(db, ctrlNum);
        return json({ ok: true });
      }
      if (method === 'DELETE' && r1) {
        await db.prepare('DELETE FROM tolf WHERE id=?').bind(n(r1)).run();
        await syncLatestControlNumberFromDb(db);
        return json({ ok: true });
      }
    }

    // 4. Rido Cases (rido)
    if (r0 === 'rido') {
      try { await db.prepare('ALTER TABLE rido ADD COLUMN control_number TEXT').run(); } catch(e) {}
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
        const ctrlNum = txt(b.control_number, 100);
        try {
          await db.prepare('INSERT INTO rido (control_number,case_date,unit,area,province,parties_involved,status,casualties_killed,casualties_wounded,firearms_surrendered,mediators,agreement_details,remarks) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)')
            .bind(ctrlNum, b.case_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.parties_involved), txt(b.status || 'Ongoing Mediation'), n(b.casualties_killed), n(b.casualties_wounded), n(b.firearms_surrendered), txt(b.mediators), txt(b.agreement_details, 500), txt(b.remarks, 500)).run();
        } catch(err0) {
          try {
            await db.prepare('INSERT INTO rido (case_date,unit,area,province,parties_involved,status,casualties_killed,casualties_wounded,firearms_surrendered,mediators,agreement_details,remarks) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
              .bind(b.case_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.parties_involved), txt(b.status || 'Ongoing Mediation'), n(b.casualties_killed), n(b.casualties_wounded), n(b.firearms_surrendered), txt(b.mediators), txt(b.agreement_details, 500), txt(b.remarks, 500)).run();
          } catch(err) {
            await db.prepare('INSERT INTO rido (case_date,unit,area,parties_involved,status,casualties_killed,casualties_wounded,firearms_surrendered,mediators,agreement_details,remarks) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
              .bind(b.case_date, txt(b.unit), txt(b.area), txt(b.parties_involved), txt(b.status || 'Ongoing Mediation'), n(b.casualties_killed), n(b.casualties_wounded), n(b.firearms_surrendered), txt(b.mediators), txt(b.agreement_details, 500), txt(b.remarks, 500)).run();
          }
        }
        if (ctrlNum) await setLatestControlNumber(db, ctrlNum);
        return json({ ok: true });
      }
      if (method === 'PUT' && r1) {
        const b = await request.json();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(b.case_date) || !txt(b.unit) || !txt(b.parties_involved)) {
          return json({ error: 'Date, Unit, and Parties Involved are required' }, 400);
        }
        const ctrlNum = txt(b.control_number, 100);
        try {
          await db.prepare('UPDATE rido SET control_number=?,case_date=?,unit=?,area=?,province=?,parties_involved=?,status=?,casualties_killed=?,casualties_wounded=?,firearms_surrendered=?,mediators=?,agreement_details=?,remarks=? WHERE id=?')
            .bind(ctrlNum, b.case_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.parties_involved), txt(b.status || 'Ongoing Mediation'), n(b.casualties_killed), n(b.casualties_wounded), n(b.firearms_surrendered), txt(b.mediators), txt(b.agreement_details, 500), txt(b.remarks, 500), n(r1)).run();
        } catch(err0) {
          try {
            await db.prepare('UPDATE rido SET case_date=?,unit=?,area=?,province=?,parties_involved=?,status=?,casualties_killed=?,casualties_wounded=?,firearms_surrendered=?,mediators=?,agreement_details=?,remarks=? WHERE id=?')
              .bind(b.case_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.parties_involved), txt(b.status || 'Ongoing Mediation'), n(b.casualties_killed), n(b.casualties_wounded), n(b.firearms_surrendered), txt(b.mediators), txt(b.agreement_details, 500), txt(b.remarks, 500), n(r1)).run();
          } catch(err) {
            await db.prepare('UPDATE rido SET case_date=?,unit=?,area=?,parties_involved=?,status=?,casualties_killed=?,casualties_wounded=?,firearms_surrendered=?,mediators=?,agreement_details=?,remarks=? WHERE id=?')
              .bind(b.case_date, txt(b.unit), txt(b.area), txt(b.parties_involved), txt(b.status || 'Ongoing Mediation'), n(b.casualties_killed), n(b.casualties_wounded), n(b.firearms_surrendered), txt(b.mediators), txt(b.agreement_details, 500), txt(b.remarks, 500), n(r1)).run();
          }
        }
        if (ctrlNum) await setLatestControlNumber(db, ctrlNum);
        return json({ ok: true });
      }
      if (method === 'DELETE' && r1) {
        await db.prepare('DELETE FROM rido WHERE id=?').bind(n(r1)).run();
        await syncLatestControlNumberFromDb(db);
        return json({ ok: true });
      }
    }

    // 5. HADR Operations (hadr)
    if (r0 === 'hadr') {
      try { await db.prepare('ALTER TABLE hadr ADD COLUMN control_number TEXT').run(); } catch(e) {}
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
        const ctrlNum = txt(b.control_number, 100);
        try {
          await db.prepare('INSERT INTO hadr (control_number,op_date,unit,area,disaster_type,assisted_families,assisted_individuals,rescued_persons,relief_packs_distributed,personnel_deployed,partner_agencies,remarks) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
            .bind(ctrlNum, b.op_date, txt(b.unit), txt(b.area), txt(b.disaster_type), n(b.assisted_families), n(b.assisted_individuals), n(b.rescued_persons), n(b.relief_packs_distributed), n(b.personnel_deployed), txt(b.partner_agencies), txt(b.remarks, 500)).run();
        } catch(err) {
          await db.prepare('INSERT INTO hadr (op_date,unit,area,disaster_type,assisted_families,assisted_individuals,rescued_persons,relief_packs_distributed,personnel_deployed,partner_agencies,remarks) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
            .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.disaster_type), n(b.assisted_families), n(b.assisted_individuals), n(b.rescued_persons), n(b.relief_packs_distributed), n(b.personnel_deployed), txt(b.partner_agencies), txt(b.remarks, 500)).run();
        }
        if (ctrlNum) await setLatestControlNumber(db, ctrlNum);
        return json({ ok: true });
      }
      if (method === 'PUT' && r1) {
        const b = await request.json();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(b.op_date) || !txt(b.unit) || !txt(b.disaster_type)) {
          return json({ error: 'Date, Unit, and Disaster Type are required' }, 400);
        }
        const ctrlNum = txt(b.control_number, 100);
        try {
          await db.prepare('UPDATE hadr SET control_number=?,op_date=?,unit=?,area=?,disaster_type=?,assisted_families=?,assisted_individuals=?,rescued_persons=?,relief_packs_distributed=?,personnel_deployed=?,partner_agencies=?,remarks=? WHERE id=?')
            .bind(ctrlNum, b.op_date, txt(b.unit), txt(b.area), txt(b.disaster_type), n(b.assisted_families), n(b.assisted_individuals), n(b.rescued_persons), n(b.relief_packs_distributed), n(b.personnel_deployed), txt(b.partner_agencies), txt(b.remarks, 500), n(r1)).run();
        } catch(err) {
          await db.prepare('UPDATE hadr SET op_date=?,unit=?,area=?,disaster_type=?,assisted_families=?,assisted_individuals=?,rescued_persons=?,relief_packs_distributed=?,personnel_deployed=?,partner_agencies=?,remarks=? WHERE id=?')
            .bind(b.op_date, txt(b.unit), txt(b.area), txt(b.disaster_type), n(b.assisted_families), n(b.assisted_individuals), n(b.rescued_persons), n(b.relief_packs_distributed), n(b.personnel_deployed), txt(b.partner_agencies), txt(b.remarks, 500), n(r1)).run();
        }
        if (ctrlNum) await setLatestControlNumber(db, ctrlNum);
        return json({ ok: true });
      }
      if (method === 'DELETE' && r1) {
        await db.prepare('DELETE FROM hadr WHERE id=?').bind(n(r1)).run();
        await syncLatestControlNumberFromDb(db);
        return json({ ok: true });
      }
    }

    // 6. Incident Reports (incident_reports)
    if (r0 === 'incident_reports' || r0 === 'incidents') {
      try {
        await db.prepare(`CREATE TABLE IF NOT EXISTS incident_reports (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          control_number TEXT,
          op_date TEXT NOT NULL,
          unit TEXT NOT NULL,
          area TEXT NOT NULL,
          province TEXT,
          threat_category TEXT,
          threat_group TEXT NOT NULL,
          engagement_type TEXT,
          surrendered INTEGER DEFAULT 0,
          killed INTEGER DEFAULT 0,
          enemy_wounded INTEGER DEFAULT 0,
          captured INTEGER DEFAULT 0,
          apprehended INTEGER DEFAULT 0,
          firearms INTEGER DEFAULT 0,
          fa_captured INTEGER DEFAULT 0,
          fa_confiscated INTEGER DEFAULT 0,
          fa_surrendered INTEGER DEFAULT 0,
          fa_recovered INTEGER DEFAULT 0,
          fa_csw INTEGER DEFAULT 0,
          fa_high_powered INTEGER DEFAULT 0,
          fa_low_powered INTEGER DEFAULT 0,
          tolf INTEGER DEFAULT 0,
          kia INTEGER DEFAULT 0,
          wia INTEGER DEFAULT 0,
          war_materiel TEXT,
          remarks TEXT
        )`).run();
        await db.prepare(`CREATE INDEX IF NOT EXISTS idx_incident_reports_date ON incident_reports(op_date)`).run();
      } catch(e) {}
      try { await db.prepare('ALTER TABLE incident_reports ADD COLUMN control_number TEXT').run(); } catch(e) {}

      if (method === 'GET') {
        const url = new URL(request.url);
        const y = url.searchParams.get('year');
        const sDate = url.searchParams.get('start_date');
        const eDate = url.searchParams.get('end_date');
        let sql = 'SELECT * FROM incident_reports';
        const params = [];
        if (sDate && eDate) {
          sql += ' WHERE op_date BETWEEN ? AND ?';
          params.push(sDate, eDate);
        } else if (y) {
          sql += ' WHERE op_date LIKE ?';
          params.push(`${y}-%`);
        }
        sql += ' ORDER BY op_date DESC, id DESC LIMIT 1000';
        const q = params.length ? db.prepare(sql).bind(...params) : db.prepare(sql);
        const x = await q.all();
        return json({ rows: x.results });
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
        const ctrlNum = txt(b.control_number, 100);
        try {
          await db.prepare(`INSERT INTO incident_reports (
            control_number,op_date,unit,area,province,threat_category,threat_group,engagement_type,
            surrendered,killed,enemy_wounded,captured,apprehended,
            firearms,fa_captured,fa_confiscated,fa_surrendered,fa_recovered,
            fa_csw,fa_high_powered,fa_low_powered,tolf,kia,wia,
            war_materiel,remarks
          ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
            .bind(
              ctrlNum, b.op_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.threat_category), txt(b.threat_group), txt(b.engagement_type),
              n(b.surrendered), n(b.killed), n(b.enemy_wounded), n(b.captured), n(b.apprehended),
              totalFA, n(b.fa_captured), n(b.fa_confiscated), n(b.fa_surrendered), n(b.fa_recovered),
              n(b.fa_csw), n(b.fa_high_powered), n(b.fa_low_powered), n(b.tolf), n(b.kia), n(b.wia),
              warMat, txt(b.remarks, 1000)
            ).run();
        } catch(err) {
          await db.prepare(`INSERT INTO incident_reports (
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
        }
        if (ctrlNum) await setLatestControlNumber(db, ctrlNum);
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
        const ctrlNum = txt(b.control_number, 100);
        try {
          await db.prepare(`UPDATE incident_reports SET
            control_number=?,op_date=?,unit=?,area=?,province=?,threat_category=?,threat_group=?,engagement_type=?,
            surrendered=?,killed=?,enemy_wounded=?,captured=?,apprehended=?,
            firearms=?,fa_captured=?,fa_confiscated=?,fa_surrendered=?,fa_recovered=?,
            fa_csw=?,fa_high_powered=?,fa_low_powered=?,tolf=?,kia=?,wia=?,
            war_materiel=?,remarks=?
          WHERE id=?`)
            .bind(
              ctrlNum, b.op_date, txt(b.unit), txt(b.area), txt(b.province), txt(b.threat_category), txt(b.threat_group), txt(b.engagement_type),
              n(b.surrendered), n(b.killed), n(b.enemy_wounded), n(b.captured), n(b.apprehended),
              totalFA, n(b.fa_captured), n(b.fa_confiscated), n(b.fa_surrendered), n(b.fa_recovered),
              n(b.fa_csw), n(b.fa_high_powered), n(b.fa_low_powered), n(b.tolf), n(b.kia), n(b.wia),
              warMat, txt(b.remarks, 1000), n(r1)
            ).run();
        } catch(err) {
          await db.prepare(`UPDATE incident_reports SET
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
        }
        if (ctrlNum) await setLatestControlNumber(db, ctrlNum);
        return json({ ok: true });
      }
      if (method === 'DELETE' && r1) {
        await db.prepare('DELETE FROM incident_reports WHERE id=?').bind(n(r1)).run();
        await syncLatestControlNumberFromDb(db);
        return json({ ok: true });
      }
    }

    return json({ error: 'Not found' }, 404);
  } catch (e) {
    return json({ error: e.message || String(e), stack: e.stack }, 500);
  }
}
