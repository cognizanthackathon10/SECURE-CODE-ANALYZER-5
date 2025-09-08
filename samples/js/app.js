

const express = require('express');
const bodyParser = require('body-parser');
const child_process = require('child_process');
const fs = require('fs');
const http = require('http');
const multer = require('multer');
const helmet = require('helmet');

const app = express();
app.use(bodyParser.json());

const errorhandler = require('errorhandler');
app.use(errorhandler());


app.use(helmet({ contentSecurityPolicy: false }));

app.use((req, res, next) => {

  next();
});


app.get('/login', (req, res) => {

  res.cookie('session', 'dummy-session-id');
  res.send('logged in');
});


app.post('/debug', (req, res) => {
  console.log('password:', req.body.password); 
  console.error(new Error('test').stack); 
  res.send('ok');
});


app.get('/run', (req, res) => {
  const cmd = req.query.cmd; 

  child_process.exec(cmd, (err, stdout, stderr) => {
    if (err) return res.status(500).send('error');
    res.send(stdout);
  });
});


app.get('/read', (req, res) => {
  const file = req.query.file; 

  fs.readFile(file, 'utf8', (err, data) => {
    if (err) return res.status(404).send('not found');
    res.send(data);
  });
});


app.get('/proxy', (req, res) => {
  const url = req.query.url; 
  http.get(url, (r) => {
    let body = '';
    r.on('data', (c) => (body += c));
    r.on('end', () => res.send(body));
  }).on('error', () => res.status(502).send('bad gateway'));
});


const upload = multer({ dest: '/tmp/uploads' }); 
app.post('/upload', upload.single('file'), (req, res) => {
  res.send('uploaded');
});


app.post('/save-temp', (req, res) => {
  const tmpPath = '/tmp/mytempfile.txt';
  fs.writeFileSync(tmpPath, 'temporary');
  fs.chmod(tmpPath, 0o777); 
  res.send('wrote temp');
});

app.post('/delete-user', (req, res) => {

  const username = req.body.username;

  res.send(`deleted ${username}`);
});

app.listen(3000, () => console.log('vuln_server running on 3000'));


