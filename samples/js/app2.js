// OWASP Top 10: A05, A07, A08
const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const app = express();
app.use(express.json());

// A05: Security Misconfiguration - Content Security Policy disabled
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', ""); // Disabled CSP
    next();
});

// A07: Weak login
const USERS = [{ username: "admin", password: "1234" }]; // Weak password
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = USERS.find(u => u.username === username && u.password === password);
    if(user) res.send("Logged in!");
    else res.status(401).send("Invalid credentials");
});

// A08: Insecure file upload (no validation)
app.post('/upload', (req, res) => {
    const { data, filename } = req.body;
    const buf = Buffer.from(data, 'base64');
    fs.writeFileSync(`uploads/${filename}`, buf);
    res.send("Uploaded");
});

app.listen(3002, () => console.log("App2 running on port 3002"));
