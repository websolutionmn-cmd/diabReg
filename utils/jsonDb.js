const fs   = require('fs');
const path = require('path');

const DB_FILE = path.join(__dirname, '..', 'db.json');

function loadDb() {
  if (!fs.existsSync(DB_FILE)) {
    return { companies: [], applications: [] };
  }
  const raw = fs.readFileSync(DB_FILE, 'utf8') || '{}';
  try {
    const data = JSON.parse(raw);
    return {
      companies:    Array.isArray(data.companies)    ? data.companies    : [],
      applications: Array.isArray(data.applications) ? data.applications : []
    };
  } catch (e) {
    console.error('Грешка при парсирање db.json:', e);
    return { companies: [], applications: [] };
  }
}

function saveDb(db) {
  const safe = {
    companies:    Array.isArray(db.companies)    ? db.companies    : [],
    applications: Array.isArray(db.applications) ? db.applications : []
  };
  fs.writeFileSync(DB_FILE, JSON.stringify(safe, null, 2), 'utf8');
}

module.exports = { loadDb, saveDb };
