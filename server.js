require('dotenv').config();
const express = require('express'), multer = require('multer'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'),
  cookie = require('cookie-parser'), helmet = require('helmet'), rate = require('express-rate-limit'),
  fs = require('fs'), path = require('path'), crypto = require('crypto');

const { ADMIN_USER, ADMIN_PASS, JWT_SECRET, PORT = 3000, MAX_UPLOAD_MB = 300, ORG_NAME = 'آموزش‌های آتش‌نشانی' } = process.env;
if (!ADMIN_USER || !ADMIN_PASS || !JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('فایل .env ناقص است: ADMIN_USER، ADMIN_PASS و JWT_SECRET (حداقل ۳۲ حرف) لازم است.');
  process.exit(1);
}
const ADMIN_HASH = bcrypt.hashSync(ADMIN_PASS, 10);

/* ---------- ذخیره‌سازی (پوشه data؛ از آن بکاپ بگیرید) ---------- */
const DATA = path.join(__dirname, 'data'), FILES = path.join(DATA, 'files'), DBF = path.join(DATA, 'db.json');
fs.mkdirSync(FILES, { recursive: true });
let db = { trainings: [] };
if (fs.existsSync(DBF)) db = JSON.parse(fs.readFileSync(DBF, 'utf8'));
const save = () => { fs.writeFileSync(DBF + '.tmp', JSON.stringify(db)); fs.renameSync(DBF + '.tmp', DBF); };
const rid = () => crypto.randomBytes(8).toString('hex');
const rm = p => fs.unlink(p, () => {});
const fixName = n => Buffer.from(n, 'latin1').toString('utf8');
const ext = f => path.extname(f).toLowerCase();

const kind = { pdf: /^\.pdf$/, img: /^\.(jpe?g|png|gif|webp)$/, vid: /^\.(mp4|webm)$/ };
const up = multer({
  storage: multer.diskStorage({ destination: FILES, filename: (q, f, cb) => cb(null, crypto.randomBytes(16).toString('hex') + ext(f.originalname)) }),
  limits: { fileSize: MAX_UPLOAD_MB * 1e6 },
  fileFilter: (q, f, cb) => kind[f.fieldname]?.test(ext(f.originalname)) ? cb(null, true) : cb(new Error('bad'))
}).fields([{ name: 'pdf', maxCount: 1 }, { name: 'img', maxCount: 20 }, { name: 'vid', maxCount: 5 }]);

const U = x => ({ id: x.id, n: x.n, size: x.size, u: '/api/t/' + x.file });
const tr = t => ({ id: t.id, m: t.m, t: t.t, pdf: t.pdf && U(t.pdf), images: t.images.map(U), videos: t.videos.map(U) });
const allF = t => [t.pdf, ...t.images, ...t.videos].filter(Boolean);
const wipe = t => allF(t).forEach(x => rm(path.join(FILES, x.file)));

/* ---------- برنامه ---------- */
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));
app.use(cookie());
app.use((q, s, n) => { try { q.admin = jwt.verify(q.cookies.tk, JWT_SECRET).admin === true; } catch (e) { q.admin = false; } n(); });
const needAdmin = (q, s, n) => q.admin ? n() : s.status(401).json({ err: 'ابتدا به‌عنوان مدیر وارد شوید.' });
const lim = rate({ windowMs: 15 * 60 * 1000, max: 15, message: { err: 'تلاش‌های زیاد؛ چند دقیقه بعد دوباره امتحان کنید.' } });

/* ورود مدیر (ثبت‌نام عمومی وجود ندارد) */
app.post('/api/login', lim, async (q, s) => {
  const okU = String(q.body.u || '') === ADMIN_USER, okP = await bcrypt.compare(String(q.body.p || ''), ADMIN_HASH);
  if (!(okU && okP)) return s.status(401).json({ err: 'نام کاربری یا رمز اشتباه است.' });
  s.cookie('tk', jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '7d' }), { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 6048e5 });
  s.json({ ok: 1 });
});
app.post('/api/logout', (q, s) => { s.clearCookie('tk'); s.json({ ok: 1 }); });
app.get('/api/me', (q, s) => s.json({ admin: q.admin }));

/* بخش عمومی: دیدن و دانلود */
app.get('/api/trainings', (q, s) => s.json({ org: ORG_NAME, items: db.trainings.map(tr) }));
app.get('/api/t/:file', (q, s) => {
  const f = path.basename(q.params.file), x = db.trainings.flatMap(allF).find(k => k.file === f);
  if (!x) return s.sendStatus(404);
  q.query.dl ? s.download(path.join(FILES, f), x.n) : s.sendFile(path.join(FILES, f));   // sendFile: پخش ویدیو با جلو/عقب‌کردن
});

/* فقط مدیر */
const A = express.Router(); app.use('/api/admin', needAdmin, A);
A.post('/trainings', (q, s) => {
  const m = String(q.body.m || ''), t = String(q.body.t || '').trim().slice(0, 120);
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(m) || !t) return s.status(400).json({ err: 'ماه و سرفصل لازم است.' });
  if (db.trainings.filter(x => x.m === m).length >= 7) return s.status(400).json({ err: 'برای هر ماه حداکثر ۷ آموزش مجاز است.' });
  db.trainings.push({ id: rid(), m, t, pdf: null, images: [], videos: [] }); save(); s.json({ ok: 1 });
});
A.put('/trainings/:id', (q, s) => {
  const t = db.trainings.find(x => x.id === q.params.id), n = String(q.body.t || '').trim().slice(0, 120);
  if (!t || !n) return s.sendStatus(400); t.t = n; save(); s.json({ ok: 1 });
});
A.post('/trainings/:id/files', up, (q, s) => {
  const t = db.trainings.find(x => x.id === q.params.id), fl = Object.entries(q.files || {});
  if (!t) { fl.forEach(([k, a]) => a.forEach(f => rm(f.path))); return s.sendStatus(404); }
  for (const [k, a] of fl) for (const f of a) {
    const o = { id: rid(), file: f.filename, n: fixName(f.originalname), size: f.size };
    if (k === 'pdf') { if (t.pdf) rm(path.join(FILES, t.pdf.file)); t.pdf = o; } else t[k === 'img' ? 'images' : 'videos'].push(o);
  }
  save(); s.json({ ok: 1 });
});
A.delete('/trainings/:id/file/:fid', (q, s) => {
  const t = db.trainings.find(x => x.id === q.params.id), x = t && allF(t).find(k => k.id === q.params.fid);
  if (!x) return s.sendStatus(404);
  rm(path.join(FILES, x.file)); if (t.pdf === x) t.pdf = null; t.images = t.images.filter(k => k !== x); t.videos = t.videos.filter(k => k !== x);
  save(); s.json({ ok: 1 });
});
A.delete('/trainings/:id', (q, s) => {
  const t = db.trainings.find(x => x.id === q.params.id); if (!t) return s.sendStatus(404);
  wipe(t); db.trainings = db.trainings.filter(x => x !== t); save(); s.json({ ok: 1 });
});
A.delete('/month/:m', (q, s) => {
  db.trainings.filter(x => x.m === q.params.m).forEach(wipe); db.trainings = db.trainings.filter(x => x.m !== q.params.m); save(); s.json({ ok: 1 });
});

app.get('/admin', (q, s) => s.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.use(express.static(path.join(__dirname, 'public')));
app.use((err, q, s, n) => s.status(400).json({ err: err.code === 'LIMIT_FILE_SIZE' ? 'حجم فایل بیشتر از حد مجاز است.' : 'فایل نامعتبر است (PDF، عکس jpg/png/webp/gif، ویدیو mp4/webm) یا آپلود خطا داد.' }));
app.listen(PORT, () => console.log('Server running on port ' + PORT));
