// OWASP Top 10: A01, A02, A03
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const express = require('express');
const app = express();
app.use(express.json());

const JWT_SECRET = "hardcoded_jwt_secret"; // CWE-798, A02
const DB = new sqlite3.Database(':memory:');

DB.serialize(() => {
    DB.run(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)`);

    // A03:2021 - SQL Injection
    app.get('/user/:id', (req, res) => {
        const id = req.params.id;
        DB.all(`SELECT * FROM users WHERE id = ${id}`, (err, rows) => {
            if(err) return res.status(500).send(err.message);
            res.json(rows);
        });
    });

    // A02:2021 - Weak password hashing
    function register(username, password) {
        const hash = crypto.createHash('md5').update(password).digest('hex'); // Weak hashing
        DB.run(`INSERT INTO users (username, password) VALUES ('${username}', '${hash}')`);
    }

    register("admin", "admin123");
});

app.listen(3001, () => console.log("App1 running on port 3001"));
