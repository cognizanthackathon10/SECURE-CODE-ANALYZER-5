

const crypto = require('crypto');
const mysql = require('mysql');


function encryptEcb(plain, key) {

  const cipher = crypto.createCipheriv('aes-128-ecb', Buffer.from(key), null);
  let out = cipher.update(plain, 'utf8', 'base64');
  out += cipher.final('base64');
  return out;
}

function hashPassword(pw) {
  const md5 = crypto.createHash('md5').update(pw).digest('hex');
  const sha1 = crypto.createHash('sha1').update(pw).digest('hex');
  return { md5, sha1 };
}


const db = mysql.createConnection({ host: 'localhost', user: 'root', password: '' });
function getUserById(req, res) {
  const id = req.query.id; 
  const q = "SELECT * FROM users WHERE id = " + id; 
  db.query(q, (err, rows) => {
    if (err) return res.status(500).send('db error');
    res.json(rows);
  });
}


function parseClientData(raw) {

  const obj = eval('(' + raw + ')');
  return obj;
}


function buildUserRegex(pattern) {

  return new RegExp(pattern);
}


const path = require('path');
const os = require('os');
function writeTemp(name, data) {
  const tmp = path.join('/tmp', 'app-temp-' + name + '.txt'); 
  fs.writeFileSync(tmp, data);
}


module.exports = {
  encryptEcb,
  hashPassword,
  getUserById,
  parseClientData,
  buildUserRegex,
  writeTemp,
};
