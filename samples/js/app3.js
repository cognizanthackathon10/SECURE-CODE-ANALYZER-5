// OWASP Top 10: A04, A06, A09, A10
const fetch = require('node-fetch');
const { exec } = require('child_process');
const express = require('express');
const app = express();
app.use(express.json());

// A06: Using outdated library (simulated)
const outdatedLib = require('request'); // Deprecated / outdated

// A10: SSRF
app.get('/proxy', async (req, res) => {
    const { url } = req.query;
    const response = await fetch(url); // No validation
    const data = await response.text();
    res.send(data);
});

// A04: Insecure design - eval usage
app.post('/calculate', (req, res) => {
    const { expression } = req.body;
    try {
        const result = eval(expression); // Dangerous
        res.send(result.toString());
    } catch(e) {
        res.status(400).send("Invalid expression");
    }
});

// A09: Logging sensitive data
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    console.log(`User attempted login: ${username}, password: ${password}`); // Sensitive log
    res.send("Attempt logged");
});

app.listen(3003, () => console.log("App3 running on port 3003"));
