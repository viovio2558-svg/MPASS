// MPASS API - Cloudflare Pages Functions + D1
const J = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json' } });
const dayOf = t => new Date(t + 7 * 36e5).toISOString().slice(0, 10); // วันตามเวลาไทย
const ALPHA = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const newCode = () => Array.from(crypto.getRandomValues(new Uint8Array(10)), n => ALPHA[n % ALPHA.length]).join('');
function eq(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function roleOf(req, env) {
  const p = req.headers.get('x-pass') || '';
  if (eq(p, env.ADMIN_PASSWORD)) return 'admin';
  if (eq(p, env.STAFF_PASSWORD)) return 'staff';
  return null;
}
async function info(env, code, now) {
  const v = await env.DB.prepare('SELECT * FROM vouchers WHERE code=?').bind(code).first();
  if (!v) return null;
  const t = await env.DB.prepare('SELECT COUNT(*) n, SUM(day=?) d, MAX(used_at) l FROM redemptions WHERE code=?').bind(dayOf(now), code).first();
  return { code: v.code, title: v.title, holder: v.holder, maxTotal: v.max_total, maxPerDay: v.max_per_day,
    expiresAt: v.expires_at, revoked: !!v.revoked, usedTotal: t.n || 0, usedToday: t.d || 0, lastUsedAt: t.l };
}
function state(i, now) {
  if (i.revoked) return { ok: false, text: 'ถูกยกเลิกแล้ว' };
  if (i.expiresAt && now > i.expiresAt) return { ok: false, text: 'หมดอายุแล้ว' };
  if (i.maxTotal != null && i.usedTotal >= i.maxTotal) return { ok: false, text: 'ใช้ครบแล้ว' };
  if (i.maxTotal == null && i.usedToday >= i.maxPerDay) return { ok: false, text: 'ใช้ครบสิทธิ์ของวันนี้แล้ว' };
  return { ok: true, text: 'ใช้งานได้' };
}
export async function onRequest({ request: req, env, params }) {
  const p = [].concat(params.path || []).join('/'), m = req.method, now = Date.now();
  try {
    if (p === 'me') return J({ role: roleOf(req, env) });
    const mm = p.match(/^voucher\/([A-Za-z0-9]{4,32})$/);
    if (mm && m === 'GET') {
      const code = mm[1].toUpperCase(), i = await info(env, code, now);
      if (!i) return J({ error: 'ไม่พบ Mpass นี้' }, 404);
      i.state = state(i, now);
      if (roleOf(req, env)) {
        const h = await env.DB.prepare('SELECT used_at FROM redemptions WHERE code=? ORDER BY id DESC LIMIT 10').bind(code).all();
        i.history = h.results.map(x => x.used_at);
      }
      return J(i);
    }
    const role = roleOf(req, env);
    if (!role) return J({ error: 'รหัสผ่านไม่ถูกต้อง' }, 401);
    if (p === 'redeem' && m === 'POST') {
      const code = String((await req.json()).code || '').toUpperCase();
      // หักสิทธิ์ด้วยคำสั่งเดียว (atomic) กันสแกนซ้อนกันแล้วหักเกิน
      const r = await env.DB.prepare(`INSERT INTO redemptions(code,used_at,day)
        SELECT ?1,?2,?3 WHERE EXISTS (SELECT 1 FROM vouchers v WHERE v.code=?1 AND v.revoked=0
          AND (v.expires_at IS NULL OR v.expires_at>?2)
          AND ((v.max_total IS NOT NULL AND (SELECT COUNT(*) FROM redemptions r WHERE r.code=v.code)<v.max_total)
            OR (v.max_total IS NULL AND v.max_per_day IS NOT NULL AND (SELECT COUNT(*) FROM redemptions r WHERE r.code=v.code AND r.day=?3)<v.max_per_day)))`)
        .bind(code, now, dayOf(now)).run();
      if (r.meta.changes === 1) return J({ ok: true });
      const i = await info(env, code, now);
      return J({ ok: false, error: i ? 'ใช้ไม่ได้: ' + state(i, now).text : 'ไม่พบ Mpass นี้' }, 409);
    }
    if (role !== 'admin') return J({ error: 'เฉพาะผู้ดูแลเท่านั้น' }, 403);
    if (p === 'vouchers' && m === 'GET') {
      const l = await env.DB.prepare('SELECT v.*, (SELECT COUNT(*) FROM redemptions r WHERE r.code=v.code) used FROM vouchers v ORDER BY created_at DESC LIMIT 200').all();
      return J(l.results);
    }
    if (p === 'vouchers' && m === 'POST') {
      const b = await req.json(), title = String(b.title || '').trim().slice(0, 100);
      const tot = parseInt(b.maxTotal, 10) || 0, day = parseInt(b.maxPerDay, 10) || 0, exp = b.expiresAt ? Number(b.expiresAt) : null;
      if (!title) return J({ error: 'กรุณากรอกชื่อ Mpass' }, 400);
      if (tot && day) return J({ error: 'กรอกได้อย่างเดียว: จำนวนครั้งทั้งหมด หรือ จำนวนครั้งต่อวัน' }, 400);
      if (!tot && !day) return J({ error: 'กรุณากรอกจำนวนครั้งทั้งหมด หรือจำนวนครั้งต่อวัน' }, 400);
      if (!tot && !exp) return J({ error: 'แบบจำกัดต่อวัน ต้องกำหนดวัน-เวลาหมดอายุด้วย' }, 400);
      const code = newCode();
      await env.DB.prepare('INSERT INTO vouchers(code,title,holder,max_total,max_per_day,expires_at,created_at) VALUES(?,?,?,?,?,?,?)')
        .bind(code, title, String(b.holder || '').trim().slice(0, 100) || null, tot || null, tot ? null : day, exp, now).run();
      return J({ code });
    }
    if (p === 'revoke' && m === 'POST') {
      const b = await req.json();
      await env.DB.prepare('UPDATE vouchers SET revoked=? WHERE code=?').bind(b.revoked ? 1 : 0, String(b.code || '').toUpperCase()).run();
      return J({ ok: true });
    }
    return J({ error: 'not found' }, 404);
  } catch (e) { return J({ error: 'เซิร์ฟเวอร์ผิดพลาด' }, 500); }
}
