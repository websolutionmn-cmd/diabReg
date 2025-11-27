// app.js - DIAB-REG JSON-based backend (no Mongo)

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
const axios       = require('axios');

const { loadDb, saveDb }   = require('./utils/jsonDb');
const { logAction, readLogs } = require('./utils/logger');
const users = require('./config/users');

const app  = express();
const PORT = process.env.PORT || 5050;
const JWT_SECRET = process.env.JWT_SECRET || 'replace_with_env_secret';

// Directories
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const CERT_DIR = path.join(__dirname, 'certificates');


// Ensure dirs exist
[PUBLIC_DIR, UPLOAD_DIR, CERT_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Logging
const accessLogStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags:'a' });
app.use(morgan('combined', { stream: accessLogStream }));

// Sessions (for staff / admin)
app.use(session({
  secret: 'diabreg-session-key',
  resave: false,
  saveUninitialized: false
}));

// Body parsers
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended:true }));

// Static
app.use('/uploads',      express.static(UPLOAD_DIR));
app.use('/certificates', express.static(CERT_DIR));
app.use('/documents',    express.static(path.join(PUBLIC_DIR, 'documents')));
app.use('/logo.jpg',     express.static(path.join(PUBLIC_DIR, 'logo.jpg')));
app.use(express.static(PUBLIC_DIR));

// Multer for uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const safe   = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    cb(null, unique + '_' + safe);
  }
});
const upload = multer({ storage });

// Helpers
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

// JWT auth for companies
function authCompany(req, res, next) {
  const header = req.headers['authorization'] || '';
  const [, token] = header.split(' ');
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
    // Ако JSON API
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    // иначе redirect кон login
    return res.redirect('/login');
  }
  next();
}

// ===== Staff login (admin / processor / certifier) =====

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

// ===== Company auth (JSON DB + JWT) =====

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

// ===== Applications (company side) =====

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

// Status check (public, token optional)
app.get('/api/status/:id', async (req, res) => {
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

// ===== Documents (public) =====

app.get('/api/documents', async (req, res) => {
  try {
    const docsDir = path.join(PUBLIC_DIR, 'documents');
    const files   = await fs.promises.readdir(docsDir);
    // keep same response shape as предходна верзија
    res.json({ files: files.filter(f => !f.startsWith('.')) });
  } catch (e) {
    console.error('Грешка при читање документи:', e);
    res.status(500).json({ error: 'Cannot list documents' });
  }
});

// ===== Admin API (JSON DB) =====

// Allowed statuses by staff role
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

  // ако се комплетира преку овој endpoint
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

  // delete uploads
  (appDoc.docs || []).forEach(f => {
    const p = path.join(UPLOAD_DIR, f);
    if (fs.existsSync(p)) fs.unlinkSync(p);
  });

  // delete PDF
  if (appDoc.cert_number) {
    const certPath = path.join(CERT_DIR, `${appDoc.cert_number}.pdf`);
    if (fs.existsSync(certPath)) fs.unlinkSync(certPath);
  }

  // remove from JSON DB
  db.applications.splice(idx, 1);
  saveDb(db);

  logAction(req.session.user.username, 'APPLICATION_DELETED', { appId: appDoc.id });

  res.json({ success:true });
});

// Admin logs
app.get('/api/admin/logs', requireAdmin, (req, res) => {
  res.json(readLogs());
});

// ===== Certificates =====

function generateCertNumber() {
  const now = new Date();
  return 'DIAB-' +
    now.getFullYear() +
    String(now.getMonth() + 1).padStart(2, '0') +
    String(now.getDate()).padStart(2, '0') +
    '-' + now.getTime();
}

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
  doc.registerFont('Deja', path.join(__dirname,'public','fonts','DejaVuSans.ttf'));
  doc.font('Deja');
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

// Public confirmation page
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

  const html = `
    <!DOCTYPE html>
    <html lang="mk">
    <head>
      <meta charset="UTF-8"/>
      <title>Потврда ${certNumber}</title>
      <style>
        body { font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#f3f4f6; margin:0; padding:0; }
        .wrap { max-width:800px; margin:40px auto; background:#fff; padding:24px 32px; border-radius:12px; box-shadow:0 10px 25px rgba(15,23,42,0.12); }
        h1 { margin-top:0; color:#111827; }
        .meta { margin:12px 0; color:#4b5563; line-height:1.5; }
        a.btn {
          display:inline-block; margin-top:18px; padding:10px 18px;
          border-radius:999px; border:1px solid #2563eb; color:#2563eb; text-decoration:none;
        }
        a.btn:hover { background:#2563eb; color:#fff; }
      </style>
    </head>
    <body>
      <div class="wrap">
        <h1>Потврда за производ</h1>
        <p class="meta"><strong>Број на потврда:</strong> ${certNumber}</p>
        <p class="meta"><strong>Компанија:</strong> ${company ? company.name : 'N/A'}</p>
        <p class="meta"><strong>Производ:</strong> ${appDoc.product}</p>
        <p class="meta"><strong>Категорија:</strong> ${appDoc.category || ''}</p>
        <p class="meta"><strong>Статус:</strong> ${appDoc.status}</p>
        <p class="meta"><strong>Важи до:</strong> ${validTo.toLocaleDateString('mk-MK')}</p>
        <a class="btn" href="${pdfUrl}" target="_blank">Отвори PDF потврда</a>
      </div>
    </body>
    </html>
  `;
  res.send(html);
});

// ===== Optional: Payoneer payment session (kept as-is, but without Mongo) =====

const PRICE_MAP = {
  'Медицински уреди':                            120_00,
  'Инсулинска терапија и аналози':               140_00,
  'Глукометри и консумативи':                    110_00,
  'CGM системи и сензори':                       150_00,
  'Инсулински пумпи и опрема':                   180_00,
  'Диететски суплементи и витамини':             90_00,
  'Храна и пијалоци за лица со дијабетес':       100_00,
  'Облека и обувки за лица со дијабетес':        80_00,
  'Козметика и нега на кожа за лица со дијабетес': 85_00,
  'Образовни материјали и книги за дијабетес':   70_00,
  'Други производи поврзани со дијабетес':       95_00,
  'Телемедицина и дигитални апликации':         160_00,
  'Услуги за советување и едукација':            130_00,
  'Осигурување и финансиски услуги за лица со дијабетес': 170_00,
  'Автоматизирани системи':                      260_00
};

app.post('/api/payment/session', authCompany, express.json(), async (req, res) => {
  const { category } = req.body || {};
  const amountCents  = PRICE_MAP[category];
  if (!amountCents) return res.status(400).json({ error:'Невалидна категорија' });

  const payload = {
    amount: {
      value: amountCents,
      currency: 'EUR'
    },
    reference: `PAY_REF_${Date.now()}`,
    returnUrl: `${getBaseUrl(req)}/payment-success.html`,
    cancelUrl: `${getBaseUrl(req)}/`
  };

  const env = process.env.PAYONEER_ENV === 'live'
    ? 'https://api.live.oscato.com/api/lists'
    : 'https://api.sandbox.oscato.com/api/lists';

  try {
    const auth = {
      username: process.env.PAYONEER_MERCHANT_CODE,
      password: process.env.PAYONEER_PAYMENT_TOKEN
    };
    const { data } = await axios.post(env, payload, { auth });
    res.json({ longId: data.identification.longId });
  } catch (e) {
    console.error('Payoneer session error', e.response?.data || e);
    res.status(500).json({ error:'Не може да се отвори плаќање' });
  }
});

// ===== PUBLIC: Completed certificates (no auth) =====
app.get('/api/public/completed', (req, res) => {
  const db = loadDb();

  const items = db.applications
    .filter(a => a.status === 'Completed' && a.cert_number)
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
    .map(a => {
      const company = db.companies.find(c => c.id === a.companyId);
      return {
        _id: a.id,
        company: company ? { name: company.name } : null,
        product: a.product,
        contact: a.contact,
        email: a.email,
        status: a.status,
        cert_number: a.cert_number,
        createdAt: a.createdAt,
        pdf: `/certificates/${encodeURIComponent(a.cert_number)}.pdf`
      };
    });

  res.json({ items });
});

// ===== Health & SPA routes =====

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

// Start
app.listen(PORT, () => {
  console.log(`🚀 DIAB-REG JSON server listening on port ${PORT}`);
});
