const express = require('express');
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA = path.join(ROOT, 'data', 'settings.json');
const UP = path.join(ROOT, 'uploads');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

if (!ADMIN_PASSWORD) console.warn('ATTENTION : ADMIN_PASSWORD manquant, connexion admin impossible.');

fs.mkdirSync(UP, { recursive: true });

app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  name: 'bt.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: 'auto', maxAge: 8 * 60 * 60 * 1000 }
}));

// Bloquer l'accès direct au fichier admin
app.get('/admin.html', (req, res) => res.redirect('/admin'));

app.use('/uploads', express.static(UP));
app.use(express.static(path.join(ROOT, 'public')));

function read() { return JSON.parse(fs.readFileSync(DATA, 'utf8')); }
function write(v) { fs.writeFileSync(DATA, JSON.stringify(v, null, 2)); }
function auth(req, res, next) {
  if (req.session && req.session.admin) return next();
  res.status(401).json({ error: 'Non autorisé' });
}

// Limite des essais de connexion
const attempts = new Map();
function sameHash(a, b) {
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function loginPage(error) {
  return `<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connexion — BICHRi TABAX</title>
<style>body{margin:0;font-family:system-ui,sans-serif;background:#f4f6f8;display:grid;place-items:center;min-height:100vh}
form{background:#fff;padding:30px;border-radius:18px;box-shadow:0 10px 35px #0f172a12;width:min(380px,90vw)}
h1{font-size:22px;color:#10243e;margin:0 0 18px}
input{width:100%;padding:12px;border:1px solid #d8dee7;border-radius:10px;font:inherit;box-sizing:border-box;margin-bottom:14px}
button{width:100%;border:0;border-radius:10px;padding:12px;background:#c89b3c;font-weight:800;font-size:16px}
.err{color:#b42318;font-weight:700;margin-bottom:12px}</style></head><body>
<form method="post" action="/login"><h1>🔒 Espace privé</h1>
${error ? '<div class="err">' + error + '</div>' : ''}
<input type="password" name="password" placeholder="Mot de passe" autofocus required>
<button type="submit">Se connecter</button></form></body></html>`;
}

app.get('/admin', (req, res) => {
  if (req.session && req.session.admin) return res.sendFile(path.join(ROOT, 'public', 'admin.html'));
  const msg = req.query.error === '1' ? 'Mot de passe incorrect.' : req.query.error === '2' ? 'Trop d\'essais. Réessaie dans 15 minutes.' : '';
  res.send(loginPage(msg));
});

app.post('/login', (req, res) => {
  const ip = req.ip;
  const now = Date.now();
  const a = attempts.get(ip) || { count: 0, until: 0 };
  if (a.until > now) return res.redirect('/admin?error=2');
  const p = String(req.body.password || '');
  if (ADMIN_PASSWORD && sameHash(p, ADMIN_PASSWORD)) {
    attempts.delete(ip);
    return req.session.regenerate(() => {
      req.session.admin = true;
      res.redirect('/admin');
    });
  }
  a.count += 1;
  if (a.count >= 10) { a.until = now + 15 * 60 * 1000; a.count = 0; }
  attempts.set(ip, a);
  res.redirect('/admin?error=1');
});

app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/admin')));
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

// Lecture publique des réglages (affichage du site)
app.get('/api/settings', (req, res) => res.json(read()));

// Écriture réservée à l'admin
app.put('/api/settings', auth, (req, res) => {
  const current = read();
  const incoming = req.body && typeof req.body === 'object' ? req.body : {};
  const merged = {
    ...current, ...incoming,
    brand: { ...current.brand, ...(incoming.brand || {}) },
    company: { ...current.company, ...(incoming.company || {}) },
    contact: { ...current.contact, ...(incoming.contact || {}) },
    hero: { ...current.hero, ...(incoming.hero || {}) },
    social: { ...current.social, ...(incoming.social || {}) },
    seo: { ...current.seo, ...(incoming.seo || {}) },
    appearance: { ...current.appearance, ...(incoming.appearance || {}) },
    features: { ...current.features, ...(incoming.features || {}) }
  };
  write(merged);
  res.json(merged);
});

// Envoi de fichiers : extension choisie par le serveur selon le type réel
const EXT = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp', 'application/pdf': '.pdf' };
const storage = multer.diskStorage({
  destination: UP,
  filename: (req, file, cb) => cb(null, Date.now() + '-' + crypto.randomBytes(4).toString('hex') + EXT[file.mimetype])
});
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (EXT[file.mimetype]) cb(null, true);
    else cb(new Error('Images JPG, PNG, WEBP ou PDF uniquement.'));
  }
});

app.post('/api/upload', auth, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Aucune image' });
  res.json({ url: '/uploads/' + req.file.filename, name: req.file.originalname });
});

app.post('/api/upload-plan', auth, upload.single('plan'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Aucun plan' });
  res.json({
    url: '/uploads/' + req.file.filename,
    name: req.file.originalname,
    type: req.file.mimetype === 'application/pdf' ? 'pdf' : 'image'
  });
});

app.get('*', (req, res) => res.sendFile(path.join(ROOT, 'public', 'index.html')));

app.use((err, req, res, next) => res.status(400).json({ error: err.message }));

app.listen(PORT, () => console.log('Serveur démarré sur le port ' + PORT));
