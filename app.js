// app.js - DIAB-REG JSON-based backend (no Mongo, cleaned & optimized)

const express     = require('express');
const session     = require('express-session');
const bcrypt      = require('bcryptjs');
const morgan      = require('morgan');
const fs          = require('fs');
const bodyParser  = require('body-parser');
const jwt         = require('jsonwebtoken');
const multer      = require('multer');
const PDFDocument = require('pdfkit');
const bwipjs      = require('bwip-js');
const path        = require('path');
const { v4: uuidv4 } = require('uuid');
// axios може да се користи подоцна (на пр. за интеграции)
const axios       = require('axios');

const { loadDb, saveDb }   = require('./utils/jsonDb');
const { logAction, readLogs } = require('./utils/logger');
const users = require('./config/users');

const app  = express();
const PORT = process.env.PORT || 5050;
const JWT_SECRET = process.env.JWT_SECRET || 'replace_with_env_secret';

// ================== ДИРЕКТОРИУМИ ==================
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const CERT_DIR   = path.join(__dirname, 'certificates');

// Осигурај се дека постојат
[PUBLIC_DIR, UPLOAD_DIR, CERT_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ================== LOGGING ==================
const accessLogStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags:'a' });
app.use(morgan('combined', { stream: accessLogStream }));

// ================== СЕСИИ (ADMIN) ==================
app.use(session({
  secret: 'diabreg-session-key',
  resave: false,
  saveUninitialized: false
}));

// ================== BODY PARSERS ==================
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended:true }));

// ================== STATIC ==================
app.use('/uploads',      express.static(UPLOAD_DIR));
app.use('/certificates', express.static(CERT_DIR));
app.use('/documents',    express.static(path.join(PUBLIC_DIR, 'documents')));
app.use('/logo.jpg',     express.static(path.join(PUBLIC_DIR, 'logo.jpg')));
app.use(express.static(PUBLIC_DIR));

// ================== MULTER (UPLOAD) ==================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const safe   = file.originalname.replace(/[^a-zA-Z0-9.\\-_]/g, '_');
    cb(null, unique + '_' + safe);
  }
});
const upload = multer({ storage });

// ================== HELPERS ==================
function getBaseUrl(req) {
  if (process.env.BASE_URL) return process.env.BASE_URL;
  return req.protocol + '://' + req.get('host');
}

function createCompanyToken(company) {
  return jwt.sign(
    {
      companyId: company.id,
      matichen_broj: company.matichen_broj,
      email: company.email,
      name: company.name
    },
    JWT_SECRET,
    { expiresIn: '8h' }
  );
}

// JWT auth за компании
function authCompany(req, res, next) {
  const header = req.headers['authorization'] || '';
  const parts = header.split(' ');
  const token = parts.length === 2 ? parts[1] : null;

  if (!token) return res.status(401).json({ error: 'Недостасува токен.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.company = payload;
    next();
  } catch (e) {
    console.error('JWT error:', e.message);
    return res.status(401).json({ error: 'Невалиден или истечен токен.' });
  }
}

// Admin guard (session-based)
function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user) {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    return res.redirect('/login');
  }
  next();
}

// ================== STAFF LOGIN (ADMIN / PROCESSOR / CERTIFIER) ==================
app.get('/login', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'login.html'));
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).send('Погрешно корисничко име или лозинка.');

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).send('Погрешно корисничко име или лозинка.');

  req.session.user = { username: user.username, role: user.role };
  res.redirect('/admin');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'admin.html'));
});

// ================== COMPANY AUTH (JSON DB + JWT) ==================

// Register company
app.post('/api/auth/register', (req, res) => {
  const { matichen_broj, name, email, password } = req.body || {};
  if (!matichen_broj || !name || !email || !password) {
    return res.status(400).json({ success:false, error: 'Недостасуваат полиња.' });
  }

  const db = loadDb();
  if (db.companies.find(c => c.matichen_broj === matichen_broj || c.email === email)) {
    return res.status(400).json({ success:false, error: 'Веќе постои компанија со исти ЕМБС или е-пошта.' });
  }

  const hash = bcrypt.hashSync(password, 10);
  const company = {
    id: uuidv4(),
    matichen_broj,
    name,
    email,
    passwordHash: hash,
    createdAt: new Date().toISOString()
  };

  db.companies.push(company);
  saveDb(db);

  res.json({ success:true });
});

// Login company
app.post('/api/auth/login', async (req, res) => {
  const { matichen_broj, password, email } = req.body || {};

  if ((!matichen_broj && !email) || !password) {
    return res.status(400).json({ error: 'Е-пошта/ЕМБС и лозинка се задолжителни.' });
  }

  const db = loadDb();
  const company = db.companies.find(c =>
    (matichen_broj && c.matichen_broj === matichen_broj) ||
    (email && c.email === email)
  );
  if (!company) {
    return res.status(401).json({ error: 'Погрешни креденцијали.' });
  }

  const ok = await bcrypt.compare(password, company.passwordHash);
  if (!ok) {
    return res.status(401).json({ error: 'Погрешни креденцијали.' });
  }

  const token = createCompanyToken(company);
  res.json({ token });
});

// ================== APPLICATIONS (COMPANY SIDE) ==================

// Submit application
app.post('/api/apply', authCompany, upload.array('docs', 30), (req, res) => {
  const { contact, email, category, product } = req.body || {};
  if (!contact || !email || !category || !product) {
    return res.status(400).json({ error: 'Сите полиња се задолжителни.' });
  }

  const db = loadDb();
  const docs = (req.files || []).map(f => f.filename);

  const appDoc = {
    id: uuidv4(),
    companyId: req.company.companyId,
    contact,
    email,
    category,
    product,
    docs,
    status: 'Pending',
    cert_number: null,
    completedBy: null,
    statusHistory: [],
    createdAt: new Date().toISOString(),
    updatedAt: null
  };

  db.applications.push(appDoc);
  saveDb(db);

  logAction('system', 'APPLICATION_CREATED', { appId: appDoc.id, companyId: appDoc.companyId });

  res.json({ id: appDoc.id });
});

// Status check (public)
app.get('/api/status/:id', (req, res) => {
  const db = loadDb();
  const appDoc = db.applications.find(a => a.id === req.params.id);
  if (!appDoc) {
    return res.json({ found:false });
  }
  const company = db.companies.find(c => c.id === appDoc.companyId);
  res.json({
    found: true,
    application: {
      status: appDoc.status,
      company: company ? company.name : 'N/A',
      cert_number: appDoc.cert_number || null
    }
  });
});

// My applications (company)
app.get('/api/my/applications', authCompany, (req, res) => {
  const db = loadDb();
  const apps = db.applications
    .filter(a => a.companyId === req.company.companyId)
    .sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt));

  const result = apps.map(a => {
    const company = db.companies.find(c => c.id === a.companyId);
    return {
      _id: a.id,
      company: company ? {
        id: company.id,
        name: company.name,
        matichen_broj: company.matichen_broj,
        email: company.email
      } : null,
      contact: a.contact,
      email: a.email,
      category: a.category,
      product: a.product,
      docs: a.docs || [],
      status: a.status,
      cert_number: a.cert_number || null,
      createdAt: a.createdAt,
      updatedAt: a.updatedAt,
      completedBy: a.completedBy || null
    };
  });

  res.json(result);
});

// ================== DOCUMENTS (PUBLIC) ==================
app.get('/api/documents', async (req, res) => {
  try {
    const docsDir = path.join(PUBLIC_DIR, 'documents');
    const files   = await fs.promises.readdir(docsDir);
    res.json({ files: files.filter(f => !f.startsWith('.')) });
  } catch (e) {
    console.error('Грешка при читање документи:', e);
    res.status(500).json({ error: 'Cannot list documents' });
  }
});

// ================== ADMIN API (JSON DB) ==================
const ROLE_STATUSES = {
  super:     ['Pending','In Process','Certifying','Completed'],
  processor: ['Pending','In Process'],
  certifier: ['Certifying','Completed']
};

// List applications for admin
app.get('/api/admin/applications', requireAdmin, (req, res) => {
  const db = loadDb();
  const role = req.session.user.role;
  const allowed = ROLE_STATUSES[role] || ROLE_STATUSES.super;

  const apps = db.applications
    .filter(a => allowed.includes(a.status))
    .sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt));

  const result = apps.map(a => {
    const company = db.companies.find(c => c.id === a.companyId);
    return {
      _id: a.id,
      company: company ? {
        id: company.id,
        name: company.name,
        matichen_broj: company.matichen_broj,
        email: company.email
      } : null,
      contact: a.contact,
      email: a.email,
      category: a.category,
      product: a.product,
      docs: a.docs || [],
      status: a.status,
      cert_number: a.cert_number || null,
      statusHistory: a.statusHistory || [],
      createdAt: a.createdAt,
      updatedAt: a.updatedAt,
      completedBy: a.completedBy || null
    };
  });

  res.json(result);
});

// Update status + history
app.patch('/api/admin/applications/:id/status', requireAdmin, (req, res) => {
  const { status, message } = req.body || {};
  if (!status || !message) {
    return res.status(400).json({ error: 'Статус и порака се задолжителни.' });
  }
  if (message.length < 180) {
    return res.status(400).json({ error: 'Пораката мора да има минимум 180 карактери.' });
  }

  const db = loadDb();
  const appDoc = db.applications.find(a => a.id === req.params.id);
  if (!appDoc) return res.status(404).json({ error: 'Не постои апликација.' });

  appDoc.statusHistory = appDoc.statusHistory || [];
  appDoc.statusHistory.push({
    status,
    message,
    user: req.session.user.username,
    timestamp: new Date().toISOString()
  });

  appDoc.status = status;
  appDoc.updatedAt = new Date().toISOString();

  if (status === 'Completed' && !appDoc.completedBy) {
    appDoc.completedBy = req.session.user.username;
  }

  saveDb(db);

  logAction(req.session.user.username, 'STATUS_CHANGE', { appId: appDoc.id, status });

  res.json({ success: true });
});

// DELETE application + files + logs
app.delete('/api/admin/applications/:id', requireAdmin, (req, res) => {
  const db = loadDb();
  const idx = db.applications.findIndex(a => a.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Не постои апликација' });

  const appDoc = db.applications[idx];

  (appDoc.docs || []).forEach(f => {
    const p = path.join(UPLOAD_DIR, f);
    if (fs.existsSync(p)) fs.unlinkSync(p);
  });

  if (appDoc.cert_number) {
    const certPath = path.join(CERT_DIR, `${appDoc.cert_number}.pdf`);
    if (fs.existsSync(certPath)) fs.unlinkSync(certPath);
  }

  db.applications.splice(idx, 1);
  saveDb(db);

  logAction(req.session.user.username, 'APPLICATION_DELETED', { appId: appDoc.id });

  res.json({ success:true });
});

// Admin logs
app.get('/api/admin/logs', requireAdmin, (req, res) => {
  res.json(readLogs());
});

// ================== CERTIFICATES ==================
function generateCertNumber() {
  const now = new Date();
  return 'DIAB-' +
    now.getFullYear() +
    String(now.getMonth() + 1).padStart(2, '0') +
    String(now.getDate()).padStart(2, '0') +
    '-' + now.getTime();
}

// Генерирај PDF за сертификат (admin-only)
app.get('/api/certificate/pdf/:id', requireAdmin, async (req, res) => {
  const db = loadDb();
  const appDoc = db.applications.find(a => a.id === req.params.id);
  if (!appDoc) return res.status(404).send('Апликацијата не постои.');

  if (!appDoc.cert_number) {
    appDoc.cert_number = generateCertNumber();
  }
  appDoc.status = 'Completed';
  appDoc.completedBy = req.session.user.username;
  appDoc.updatedAt = new Date().toISOString();
  saveDb(db);

  const company = db.companies.find(c => c.id === appDoc.companyId);
  const baseUrl = getBaseUrl(req);
  const confirmUrl = `${baseUrl}/confirm/${encodeURIComponent(appDoc.cert_number)}`;

  const pdfPath = path.join(CERT_DIR, `${appDoc.cert_number}.pdf`);

  const doc = new PDFDocument({ size: 'A4', margin: 50 });
  try {
    doc.registerFont('Deja', path.join(__dirname,'public','fonts','DejaVuSans.ttf'));
    doc.font('Deja');
  } catch (e) {
    console.error('Font load error:', e);
  }
  const stream = fs.createWriteStream(pdfPath);
  doc.pipe(stream);

  // Header
  doc.fontSize(22).text('Стандарнизирана потврда за производ', { align: 'center' });
  doc.moveDown();
  doc.fontSize(14).text(`Компанија: ${company ? company.name : 'N/A'}`);
  doc.text(`ЕМБС: ${company ? company.matichen_broj : 'N/A'}`);
  doc.text(`Контакт: ${appDoc.contact} (${appDoc.email})`);
  doc.moveDown();
  doc.text(`Производ: ${appDoc.product}`);
  doc.text(`Категорија: ${appDoc.category || ''}`);
  doc.moveDown();
  doc.text(`Број на потврда: ${appDoc.cert_number}`);
  const issueDate = new Date();
  const validTo = new Date(issueDate);
  validTo.setFullYear(validTo.getFullYear() + 1);
  doc.text(`Датум на издавање: ${issueDate.toLocaleString('mk-MK')}`);
  doc.text(`Важност до: ${validTo.toLocaleDateString('mk-MK')}`);
  doc.moveDown();
  doc.fontSize(12).text(
    'Стандарнизирана потврда за производ е издадена од Сојуз на Здруженија на Дијабетичари на Северна Македонија.\n' +
    'Има важност од една година од датумот на издавање.\n' +
    'За повеќе: +389 78 395 246 или websolution.mn@gmail.com',
    { align: 'center' }
  );
  doc.moveDown();

  // QR со линк до confirm
  try {
    const png = await bwipjs.toBuffer({
      bcid: 'qrcode',
      text: confirmUrl,
      scale: 4,
      includetext: false
    });
    doc.image(png, doc.page.width - 150, 80, { width: 100 });
  } catch (e) {
    console.error('QR error:', e);
  }

  doc.end();

  stream.on('finish', () => {
    logAction(req.session.user.username, 'CERTIFICATE_ISSUED', {
      appId: appDoc.id,
      cert_number: appDoc.cert_number
    });
    res.sendFile(pdfPath);
  });

  stream.on('error', err => {
    console.error(err);
    res.status(500).send('Грешка при генерирање на PDF.');
  });
});

// ================== PUBLIC CONFIRM PAGE ==================
app.get('/confirm/:certNumber', (req, res) => {
  const { certNumber } = req.params;
  const db = loadDb();
  const appDoc = db.applications.find(a => a.cert_number === certNumber);
  if (!appDoc) return res.status(404).send('Невалиден број на потврда.');

  const company = db.companies.find(c => c.id === appDoc.companyId);
  const pdfUrl = `/certificates/${encodeURIComponent(certNumber)}.pdf`;

  const issueDate = appDoc.updatedAt ? new Date(appDoc.updatedAt) : new Date();
  const validTo = new Date(issueDate);
  validTo.setFullYear(validTo.getFullYear() + 1);

  const history = appDoc.statusHistory || [];
  let historyHtml = '';

  if (!history.length) {
    historyHtml = '<p>Нема внесени статуси за процесот на сертификација.</p>';
  } else {
    historyHtml = history.map(h => {
      const ts = h.timestamp ? new Date(h.timestamp).toLocaleString('mk-MK') : '';
      const safeMessage = (h.message || '').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      const safeStatus  = (h.status  || '').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      const safeUser    = (h.user    || '').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      return `
        <div class="timeline-item">
          <div class="timeline-point"></div>
          <div class="timeline-content">
            <p><strong>Статус:</strong> ${safeStatus}</p>
            <p><strong>Корисник:</strong> ${safeUser}</p>
            <p><strong>Датум:</strong> ${ts}</p>
            <p class="timeline-message"><strong>Коментар:</strong><br>${safeMessage}</p>
          </div>
        </div>
      `;
    }).join('');
  }

  const html = `
    <!DOCTYPE html>
    <html lang="mk">
    <head>
      <meta charset="UTF-8"/>
      <title>Потврда ${certNumber}</title>
      <style>
        body {
          font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background:#0f172a;
          margin:0;
          padding:0;
        }
        .outer {
          min-height:100vh;
          display:flex;
          align-items:center;
          justify-content:center;
          padding:24px;
        }
        .wrap {
          max-width:900px;
          width:100%;
          background:#ffffff;
          padding:24px 28px 28px;
          border-radius:18px;
          box-shadow:0 18px 45px rgba(15,23,42,0.30);
          border:1px solid rgba(148,163,184,0.45);
        }
        .header {
          display:flex;
          align-items:center;
          gap:16px;
          margin-bottom:18px;
        }
        .header img.logo {
          height:52px;
          width:auto;
          border-radius:12px;
          background:#ffffff;
          padding:4px 6px;
          box-shadow:0 6px 15px rgba(15,23,42,0.18);
        }
        h1 {
          margin:0;
          font-size:20px;
          color:#0f172a;
        }
        .subtitle {
          margin:2px 0 0;
          font-size:13px;
          color:#6b7280;
        }
        .meta {
          margin:10px 0;
          color:#374151;
          line-height:1.5;
          font-size:14px;
        }
        .meta strong {
          color:#111827;
        }
        .highlight-box {
          margin:14px 0;
          padding:10px 12px;
          border-radius:10px;
          background:#eff6ff;
          border:1px solid #bfdbfe;
          font-size:13px;
          color:#1e3a8a;
        }
        .btn-row {
          margin-top:18px;
          display:flex;
          flex-wrap:wrap;
          gap:10px;
        }
        a.btn {
          display:inline-flex;
          align-items:center;
          justify-content:center;
          padding:9px 16px;
          border-radius:999px;
          border:1px solid #2563eb;
          color:#2563eb;
          background:#ffffff;
          text-decoration:none;
          font-size:13px;
          font-weight:500;
        }
        a.btn:hover {
          background:#2563eb;
          color:#ffffff;
        }
        .btn-secondary {
          border-color:#64748b;
          color:#0f172a;
        }
        .btn-secondary:hover {
          background:#0f172a;
          color:#ffffff;
          border-color:#0f172a;
        }
        .two-col {
          display:grid;
          grid-template-columns: minmax(0,1.4fr) minmax(0,1.1fr);
          gap:20px;
          margin-top:22px;
        }
        .card {
          border-radius:14px;
          border:1px solid #e5e7eb;
          background:#f9fafb;
          padding:14px 16px 16px;
        }
        .card h2 {
          margin:0 0 8px;
          font-size:15px;
          color:#111827;
        }
        .section-label {
          text-transform:uppercase;
          font-size:10px;
          letter-spacing:0.08em;
          color:#9ca3af;
          margin-bottom:4px;
        }
        .timeline-container {
          position:relative;
          margin-top:4px;
        }
        .timeline-container::before {
          content:'';
          position:absolute;
          left:8px;
          top:4px;
          bottom:4px;
          width:2px;
          background:linear-gradient(to bottom, #60a5fa, #22c55e);
          opacity:0.7;
        }
        .timeline-item {
          position:relative;
          padding-left:26px;
          margin-bottom:14px;
        }
        .timeline-point {
          position:absolute;
          left:3px;
          top:5px;
          width:11px;
          height:11px;
          border-radius:999px;
          background:#ffffff;
          border:2px solid #2563eb;
          box-shadow:0 0 0 2px rgba(191,219,254,0.8);
        }
        .timeline-content {
          font-size:12px;
          color:#374151;
          background:#f9fafb;
          border-radius:10px;
          padding:8px 10px;
          border:1px solid #e5e7eb;
        }
        .timeline-content p {
          margin:2px 0;
        }
        .timeline-message {
          margin-top:6px !important;
          font-size:12px;
          white-space:pre-wrap;
        }
        @media (max-width: 768px) {
          .wrap {
            padding:18px 16px 20px;
          }
          .two-col {
            grid-template-columns: minmax(0,1fr);
          }
        }
      </style>
    </head>
    <body>
      <div class="outer">
        <div class="wrap">

          <div class="header">
            <img src="/logo.jpg" alt="DIAB-REG" class="logo"/>
            <div>
              <div class="section-label">Стандарди и потврди</div>
              <h1>Потврда за производ</h1>
              <p class="subtitle">Издадена од Сојуз на Здруженија на Дијабетичари на Северна Македонија (СЗДСМ)</p>
            </div>
          </div>

          <div class="two-col">
            <div class="card">
              <h2>Податоци за потврдата</h2>
              <p class="meta"><strong>Број на потврда:</strong> ${certNumber}</p>
              <p class="meta"><strong>Компанија:</strong> ${company ? company.name : 'N/A'}</p>
              <p class="meta"><strong>Производ:</strong> ${appDoc.product}</p>
              <p class="meta"><strong>Категорија:</strong> ${appDoc.category || ''}</p>
              <p class="meta"><strong>Статус:</strong> ${appDoc.status}</p>
              <p class="meta"><strong>Важи до:</strong> ${validTo.toLocaleDateString('mk-MK')} г.</p>
              <div class="highlight-box">
                Оваа потврда е издадена исклучиво за производи наменети за лица со дијабетес, во координација со СЗДСМ.
              </div>
              <div class="btn-row">
                <a class="btn" href="${pdfUrl}" target="_blank">Отвори PDF потврда</a>
              </div>
            </div>

            <div class="card">
              <h2>Процес на сертификација</h2>
              <div class="timeline-container">
                ${historyHtml}
              </div>
            </div>
          </div>

        </div>
      </div>
    </body>
    </html>
  `;
  res.send(html);
});

// ================== PUBLIC: COMPLETED CERTIFICATES (NO AUTH) ==================
app.get('/api/public/completed', (req, res) => {
  const db = loadDb();

  const apps = db.applications
    .filter(a => a.status === 'Completed' && a.cert_number)
    .sort((a, b) => new Date(b.updatedAt || b.createdAt || 0) - new Date(a.updatedAt || a.createdAt || 0));

  const result = apps.map(a => {
    const company = db.companies.find(c => c.id === a.companyId);
    const issueDate = a.updatedAt ? new Date(a.updatedAt) : (a.createdAt ? new Date(a.createdAt) : null);
    let validTo = null;
    if (issueDate) {
      validTo = new Date(issueDate);
      validTo.setFullYear(validTo.getFullYear() + 1);
    }
    return {
      _id: a.id,
      company: company ? {
        name: company.name,
        matichen_broj: company.matichen_broj,
        email: company.email
      } : { name: 'N/A', matichen_broj: '', email: '' },
      product: a.product,
      category: a.category,
      contact: a.contact,
      email: a.email,
      status: a.status,
      cert_number: a.cert_number,
      createdAt: a.createdAt,
      updatedAt: a.updatedAt,
      validTo: validTo ? validTo.toISOString() : null,
      pdf: a.cert_number ? `/certificates/${encodeURIComponent(a.cert_number)}.pdf` : null
    };
  });

  res.json(result);
});

// ================== HEALTH & SPA ROUTES ==================
app.get('/api/health', (req, res) => {
  res.json({ ok:true, time:new Date().toISOString() });
});

// Front pages
app.get(['/', '/index.html'], (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});
app.get('/en', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'en.html'));
});
app.get('/al', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'al.html'));
});
app.get('/agent', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'agent.html'));
});

// ================== START SERVER ==================
app.listen(PORT, () => {
  console.log(`🚀 DIAB-REG JSON server listening on port ${PORT}`);
});
