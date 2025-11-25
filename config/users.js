// config/users.js
const bcrypt = require('bcryptjs');

const users = [
  { username: 'Administrator', passwordHash: bcrypt.hashSync('Admin#2025', 10),  role: 'super' },      // гледа сѐ
  { username: 'Pat_Diab1',     passwordHash: bcrypt.hashSync('PatDiab1!', 10),  role: 'processor' },  // Pending + In Process
  { username: 'Pat_Diab2',     passwordHash: bcrypt.hashSync('PatDiab2@', 10),  role: 'processor' },
  { username: 'Doc_diab',      passwordHash: bcrypt.hashSync('DocDiab10!', 10), role: 'certifier' },  // Certifying + Completed
  { username: 'Exp_Diab',      passwordHash: bcrypt.hashSync('ExpDiab$$', 10),  role: 'processor' },
];

module.exports = users;
