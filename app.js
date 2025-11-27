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
const stripe      = require('stripe')(process.env.STRIPE_SECRET_KEY);

const { loadDb, saveDb }   = require('./utils/jsonDb');
const { logAction, readLogs } = require('./utils/logger');
const users = require('./config/users');

const app  = express();
const PORT = process.env.PORT || 5050;
const JWT_SECRET = process.env.JWT_SECRET || 'replace_with_env_secret';

// Directories
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const CERT_DIR   = path.join(__dirname, 'certificates');

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

// ===== Helpers =====

// фиксен base URL кон Render
function getBaseUrl(_req) {
  return process.env.BASE_URL || 'https://diabreg.onrender.com';
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
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
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

// Submit application (сеуште постои, но Stripe плаќањето е одделно)
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
    res.json({ files: files.filter(f => !f.startsWith('.')) });
  } catch (e) {
    console.error('Грешка при читање документи:', e);
    res.status(500).json({ error: 'Cannot list documents' });
  }
});

// ===== Admin API (JSON DB) =====

const ROLE_STATUSES = {
  super:     ['Pending','In Process','Certifying','Completed'],
  processor: ['Pending','In Process'],
  certifier: ['Certifying','Completed']
};

// List applications for admin (си останува за admin panel)
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

  doc.fontSize(22).text('Стандартизирана потврда за производ', { align: 'center' });
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

// Public confirmation page + Види процес (timeline)
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

  const historyJson = JSON.stringify(appDoc.statusHistory || []);

  const html = `
    <!DOCTYPE html>
    <html lang="mk">
    <head>
      <meta charset="UTF-8"/>
      <title>Потврда ${certNumber}</title>
      <style>
        body { font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#f3f4f6; margin:0; padding:0; }
        .wrap { max-width:900px; margin:40px auto; background:#fff; padding:24px 32px; border-radius:12px; box-shadow:0 10px 25px rgba(15,23,42,0.12); }
        h1 { margin-top:0; color:#111827; }
        .meta { margin:8px 0; color:#4b5563; line-height:1.5; }
        .btn {
          display:inline-block; margin-top:18px; padding:10px 18px;
          border-radius:999px; border:1px solid #2563eb; color:#2563eb; text-decoration:none;
          background:#fff; cursor:pointer;
        }
        .btn.primary {
          background:#2563eb; color:#fff;
        }
        .btn:hover { box-shadow:0 4px 12px rgba(37,99,235,0.25); }
        /* Modal */
        #processModal {
          display:none; position:fixed; inset:0; background:rgba(15,23,42,0.55);
          padding-top:80px; z-index:50;
        }
        #processModalInner {
          background:white; max-width:640px; margin:auto; padding:20px 24px;
          border-radius:16px; box-shadow:0 20px 45px rgba(15,23,42,0.35);
        }
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
        <p class="meta"><strong>Оваа потврда е издадена од Сојуз на Здруженија на Дијабетичари на Северна Македонија - СЗДСМ (szdm.mk@gmail.com)</strong></p>

        <a class="btn primary" href="${pdfUrl}" target="_blank">Отвори PDF потврда</a>
        <button class="btn" id="openProcessBtn">Види процес</button>
      </div>

      <div id="processModal">
        <div id="processModalInner">
          <h2 style="margin-top:0; color:#111827;">Процес на сертификација</h2>
          <div id="processContent" style="max-height:400px; overflow-y:auto; margin-top:12px;"></div>
          <button id="closeProcessBtn"
                  style="margin-top:15px; padding:8px 14px; border-radius:8px; border:1px solid #2563eb;
                         background:#2563eb; color:white; cursor:pointer;">
            Затвори
          </button>
        </div>
      </div>

      <script>
        (function(){
          var history = ${historyJson};

          var modal   = document.getElementById('processModal');
          var openBtn = document.getElementById('openProcessBtn');
          var closeBtn= document.getElementById('closeProcessBtn');
          var content = document.getElementById('processContent');

          openBtn.addEventListener('click', function(){
            modal.style.display = 'block';
          });
          closeBtn.addEventListener('click', function(){
            modal.style.display = 'none';
          });
          modal.addEventListener('click', function(ev){
            if (ev.target === modal) {
              modal.style.display = 'none';
            }
          });

          if (!history || !history.length) {
            content.innerHTML = '<p>Нема внесени статуси.</p>';
            return;
          }

          var html = '';
          for (var i=0; i<history.length; i++) {
            var h = history[i];
            var dt = h.timestamp ? new Date(h.timestamp).toLocaleString('mk-MK') : '';
            html += '' +
              '<div style="display:flex; gap:12px; margin-bottom:16px;">' +
                '<div style="width:14px; display:flex; flex-direction:column; align-items:center;">' +
                  '<div style="width:10px;height:10px;border-radius:999px;background:#2563eb;"></div>' +
                  (i < history.length-1
                    ? '<div style="flex:1;width:2px;background:#cbd5f5;margin-top:2px;"></div>'
                    : ''
                  ) +
                '</div>' +
                '<div style="flex:1; padding:10px 12px; border-radius:8px; background:#f3f4f6;">' +
                  '<div style="font-weight:600; color:#111827;">Статус: ' + (h.status || '') + '</div>' +
                  '<div style="font-size:12px; color:#4b5563; margin-top:2px;">' +
                    (dt || '') + (h.user ? ' · ' + h.user : '') +
                  '</div>' +
                  '<div style="font-size:13px; color:#111827; margin-top:6px; white-space:pre-wrap;">' +
                    (h.message || '') +
                  '</div>' +
                '</div>' +
              '</div>';
          }
          content.innerHTML = html;
        })();
      </script>
    </body>
    </html>
  `;
  res.send(html);
});

// ===== Stripe payments (варијанта A, MKD → EUR) =====

// Цени во МКД според категориите во index.html
const CATEGORY_PRICES_MKD = {
  'Додатоци и потрошен материјал': 2500,
  'Потрошен материјал за мерење/инјектирање': 4000,
  'Уреди за мерење': 7500,
  'Уреди за апликација на инсулин': 10000,
  'Автоматизирани системи': 15000
};

// едноставна конверзија MKD → EUR cents (приближно)
function mkdToEurCents(mkd) {
  const rate = 61.5; // 1 EUR ≈ 61.5 MKD (пример)
  const eur = mkd / rate;
  return Math.round(eur * 100);
}

// Користиме ИСТАТА рута како претходно Payoneer: /api/payment/session
// Frontend: праќа { category } и добива { url } за Stripe Checkout
app.post('/api/payment/session', authCompany, async (req, res) => {
  try {
    const { category } = req.body || {};
    const mkd = CATEGORY_PRICES_MKD[category];

    if (!category || !mkd) {
      return res.status(400).json({ error: 'Невалидна категорија' });
    }

    const amountEurCents = mkdToEurCents(mkd);

    const baseUrl = getBaseUrl(req);

    const sessionStripe = await stripe.checkout.sessions.create({
      mode: 'payment',
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'eur',
            unit_amount: amountEurCents,
            product_data: {
              name: 'DIAB-REG сертификат',
              description: `Категорија: ${category} (цената е дефинирана во МКД во DIAB-REG системот)`
            }
          },
          quantity: 1
        }
      ],
      metadata: {
        diabreg_category: category,
        diabreg_mkd_price: String(mkd),
        diabreg_companyId: req.company.companyId,
        diabreg_companyName: req.company.name || ''
      },
      success_url: `${baseUrl}/payment-success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${baseUrl}/payment-cancel.html`
    });

    res.json({ id: sessionStripe.id, url: sessionStripe.url });
  } catch (e) {
    console.error('Stripe session error', e);
    res.status(500).json({ error: 'Не може да се отвори плаќање' });
  }
});

// ===== PUBLIC: Completed certificates (no auth, за "Потврдени производи") =====

app.get('/api/public/completed', (req, res) => {
  const db = loadDb();

  const items = db.applications
    .filter(a => a.status === 'Completed' && a.cert_number)
    .sort((a, b) => new Date(b.updatedAt || b.createdAt || 0) - new Date(a.updatedAt || a.createdAt || 0))
    .map(a => {
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
        } : null,
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
