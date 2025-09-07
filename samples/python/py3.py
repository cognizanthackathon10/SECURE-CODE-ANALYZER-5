#!/usr/bin/env python3
"""
owasp_vuln_demo.py

Intentional vulnerable code for demonstrating OWASP Top 10 categories.
⚠️ DO NOT USE IN PRODUCTION ⚠️

Included:
 A01:2021 – Broken Access Control
 A03:2021 – Injection (SQL)
 A05:2021 – Security Misconfiguration
 A07:2021 – Identification & Authentication Failures
 A08:2021 – Software and Data Integrity Failures
"""

import os
import sqlite3
import pickle
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "hardcoded-secret"   # A05: Security Misconfiguration (weak secret key)


# -------------------------
# DB SETUP (for demo only)
# -------------------------
def init_db():
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    cur.execute("DELETE FROM users")
    cur.execute("INSERT INTO users (username, password, role) VALUES ('admin','admin123','admin')")
    cur.execute("INSERT INTO users (username, password, role) VALUES ('bob','bob123','user')")
    conn.commit()
    conn.close()


# -------------------------
# A07: Identification & Authentication Failures
# -------------------------
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    # ❌ Storing passwords in plaintext, comparing directly
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute(f"SELECT role FROM users WHERE username='{username}' AND password='{password}'")  # A03: Injection
    row = cur.fetchone()
    conn.close()

    if row:
        session["user"] = username
        session["role"] = row[0]
        return f"Logged in as {username} with role {row[0]}"
    else:
        return "Invalid login", 401


# -------------------------
# A01: Broken Access Control
# -------------------------
@app.route("/admin")
def admin_panel():
    # ❌ No proper access control check
    if "user" not in session:
        return "Unauthorized", 403
    # Missing role check → any logged in user can access
    return "Welcome to the admin panel! (everyone logged in can see this)"


# -------------------------
# A05: Security Misconfiguration
# -------------------------
@app.route("/debug")
def debug():
    # ❌ Exposes environment variables and debug info
    return str(dict(os.environ))


# -------------------------
# A08: Software and Data Integrity Failures
# -------------------------
@app.route("/upload", methods=["POST"])
def upload_pickle():
    f = request.files["file"]
    # ❌ Insecure deserialization: loading pickle from untrusted upload
    data = pickle.loads(f.read())
    return f"Unpickled object: {data}"


if __name__ == "__main__":
    init_db()
    # ❌ Running with debug=True exposes interactive console (A05: Security Misconfiguration)
    app.run(host="0.0.0.0", port=5000, debug=True)
