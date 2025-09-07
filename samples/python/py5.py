#!/usr/bin/env python3
"""
Vulnerable Flask App (for security testing/education ONLY)

This single-file app intentionally includes a wide variety of common
vulnerabilities (OWASP Top 10 & common CWEs) to help you verify static
and dynamic application security testing (SAST/DAST) tools.

⚠️ WARNING: Do NOT deploy this in production or expose it to the internet.
Run only in a controlled, isolated environment for testing.

Python: 3.10+ (tested)
Run:    pip install flask flask_cors pyyaml itsdangerous==2.1.2
        python vulnerable_flask_app.py
"""

from flask import Flask, request, jsonify, redirect, make_response, render_template_string, send_file
from flask_cors import CORS
import sqlite3
import os
import subprocess
import random
import hashlib
import base64
import pickle  # CWE-502: Insecure Deserialization
import tempfile
import time
import requests  # Used to demonstrate SSRF; install via pip if needed
import yaml      # Unsafe loader demo
from itsdangerous import TimestampSigner  # Legit lib, misused below

# =============================
# Security Misconfig / Secrets
# =============================

# A05: Security Misconfiguration + A07: Auth failures
# - Hardcoded, weak secret key (CWE-798: Use of Hard-coded Credentials)
# - Short length makes it guessable
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'  # DANGEROUS: hardcoded & weak

# A05: Security Misconfiguration
# - CORS wide open (CWE-942: Permissive Cross-domain Policy)
CORS(app, resources={r"/*": {"origins": "*"}})  # DANGEROUS

# A02: Cryptographic Failures
# - Hardcoded API key in source (CWE-798)
PAYMENT_GATEWAY_API_KEY = "sk_test_12345_PLAIN_TEXT"  # DANGEROUS: exposed secret


DB_PATH = os.path.abspath("vuln.db")

def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    con = db()
    cur = con.cursor()
    # Simple schema with intentionally bad design choices
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT, -- A02: storing plaintext (CWE-256)
            role TEXT DEFAULT 'user'
        );

        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            content TEXT, -- CWE-79: XSS sink (stored XSS)
            created_at INTEGER
        );

        -- Seed a predictable admin (A07: default creds)
        INSERT OR IGNORE INTO users (id, username, password, role)
        VALUES (1, 'admin', 'admin', 'admin');
        """
    )
    con.commit()
    con.close()

init_db()

# ===========================================
# Helpers (intentionally flawed where noted)
# ===========================================

def unsafe_query(sql):  # CWE-89: SQL Injection
    con = db()
    cur = con.cursor()
    # No parameterization; dangerous
    return cur.execute(sql)

def user_by_username(username):
    con = db()
    cur = con.cursor()
    return cur.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

def add_comment(user_id, content):
    con = db()
    cur = con.cursor()
    cur.execute("INSERT INTO comments(user_id, content, created_at) VALUES(?,?,?)",
                (user_id, content, int(time.time())))
    con.commit()

# ===========================================
# Routes showcasing vulnerabilities
# ===========================================

@app.route("/")
def index():
    # A03: Reflected XSS (CWE-79) via 'q' parameter
    q = request.args.get("q", "")
    template = """
    <h1>Vulnerable Flask App</h1>
    <p>Try endpoints below (for testing only).</p>
    <ul>
      <li><a href="/search?user=admin'--">/search (SQLi)</a></li>
      <li><a href="/xss?msg=<script>alert(1)</script>">/xss (Reflected XSS)</a></li>
      <li><a href="/comment?content=<b>bold</b>%3Cscript%3Ealert(1)%3C/script%3E">/comment (Stored XSS)</a></li>
      <li><a href="/calc?expr=__import__('os').system('whoami')">/calc (eval RCE)</a></li>
      <li><a href="/cmd?cmd=whoami">/cmd (Command Injection)</a></li>
      <li><a href="/download?file=../../etc/passwd">/download (Path Traversal)</a></li>
      <li><a href="/fetch?url=http://127.0.0.1:5000/secret">/fetch (SSRF)</a></li>
      <li><a href="/redirect?next=https://example.com">/redirect (Open Redirect)</a></li>
      <li><a href="/yaml_load?data=aTogJmx0O2JydDsmZ3Q7">/yaml_load (Unsafe YAML)</a></li>
      <li><a href="/pickle_load?b64=...">/pickle_load (Insecure Deserialization)</a></li>
      <li><a href="/transfer?to=2&amount=100">/transfer (CSRF-able GET)</a></li>
      <li><a href="/set_session?id=99">/set_session (Session Fixation)</a></li>
      <li><a href="/jwt_none?user=admin">/jwt_none (JWT \"none\" alg)</a></li>
      <li><a href="/hash?password=secret">/hash (Weak Crypto)</a></li>
      <li><a href="/user/1">/user/&lt;id&gt; (IDOR)</a></li>
    </ul>
    <hr/>
    <p>Search: {{q}}</p>
    """
    # CWE-79: Directly render unsanitized input
    return render_template_string(template, q=q)

@app.route("/search")
def search():
    # A03: SQL Injection (CWE-89)
    user = request.args.get("user", "")
    sql = f"SELECT id, username, role FROM users WHERE username = '{user}'"  # DANGEROUS
    rows = unsafe_query(sql).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/xss")
def xss():
    # A03: Reflected XSS (CWE-79)
    msg = request.args.get("msg", "Hello")
    return f"<h2>Message:</h2> {msg}"  # DANGEROUS: no escaping

@app.route("/comment")
def comment():
    # Stored XSS (CWE-79) + A01: no auth checks
    content = request.args.get("content", "")
    add_comment(1, content)  # Always user_id=1 for demo (IDOR-like)
    return "Comment stored"

@app.route("/comments")
def comments():
    # Render all comments directly (Stored XSS sink)
    con = db()
    rows = con.execute("SELECT content FROM comments ORDER BY id DESC").fetchall()
    html = "<h2>Comments</h2>" + "<br/>".join([r["content"] for r in rows])
    return html  # DANGEROUS

@app.route("/calc")
def calc():
    # A03: Injection via eval (CWE-94: Code Injection)
    expr = request.args.get("expr", "1+1")
    return str(eval(expr))  # DANGEROUS: arbitrary code execution

@app.route("/cmd")
def cmd():
    # A03: OS Command Injection (CWE-78)
    command = request.args.get("cmd", "echo hi")
    output = subprocess.check_output(command, shell=True)  # DANGEROUS
    return f"<pre>{output.decode('utf-8', errors='ignore')}</pre>"

@app.route("/download")
def download():
    # A01: Broken access/path traversal (CWE-22)
    file = request.args.get("file", "vuln.db")
    # DANGEROUS: user controls path; no validation or whitelist
    return send_file(file, as_attachment=True)

@app.route("/fetch")
def fetch():
    # A10: SSRF (CWE-918)
    url = request.args.get("url", "http://127.0.0.1:5000/")
    r = requests.get(url, timeout=3)  # No SSRF protections, can hit metadata/internal
    return (r.text, r.status_code, dict(r.headers))

@app.route("/redirect")
def redir():
    # Open Redirect (CWE-601)
    target = request.args.get("next", "/")
    return redirect(target)  # DANGEROUS: no allowlist

@app.route("/yaml_load")
def yaml_load():
    # CWE-20/CWE-502-ish: Unsafe YAML load (PyYAML full loader)
    # Example payloads can construct arbitrary objects
    b64 = request.args.get("data")
    if not b64:
        return "Provide ?data=<base64-encoded YAML>"
    data = base64.b64decode(b64)
    obj = yaml.load(data, Loader=yaml.FullLoader)  # DANGEROUS: use safe_load in real apps
    return jsonify({"loaded": str(obj)})

@app.route("/pickle_load")
def pickle_load_route():
    # CWE-502: Insecure Deserialization (arbitrary code exec possible)
    b64 = request.args.get("b64", "")
    try:
        raw = base64.b64decode(b64)
        obj = pickle.loads(raw)  # DANGEROUS
        return jsonify({"ok": True, "type": str(type(obj))})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/transfer")
def transfer():
    # A08/A01: CSRF-prone state change via GET, no auth (CWE-352)
    to = request.args.get("to", "1")
    amount = request.args.get("amount", "0")
    # No authentication/authorization/rate-limiting
    return f"Transferred {amount} credits to user {to}"

@app.route("/set_session")
def set_session():
    # A07: Session Fixation (CWE-384) demonstration
    # Misuse a signer to accept attacker-chosen session id
    sid = request.args.get("id", str(random.randint(1, 1000)))
    signer = TimestampSigner(app.config['SECRET_KEY'])
    # Attacker can set predictable session ids
    token = signer.sign(sid).decode()
    resp = make_response(f"Session set to {sid}")
    resp.set_cookie("sessionid", token)  # Not HttpOnly/Secure set
    return resp

@app.route("/jwt_none")
def jwt_none():
    # A02/A07: Accept "none" algorithm-like behavior (conceptual demo)
    # Not a real JWT implementation—illustrates trusting unsigned tokens.
    user = request.args.get("user", "guest")
    alg = request.args.get("alg", "none")  # if 'none', no signature checked
    if alg == "none":
        # Trust claims without verification (CWE-347: Improper Verification of Cryptographic Signature)
        return jsonify({"authenticated": True, "user": user, "alg": "none"})
    # pretend verification for others
    return jsonify({"authenticated": False, "reason": "bad signature"})

@app.route("/hash")
def weak_hash():
    # A02: Weak crypto (CWE-327/328)
    password = request.args.get("password", "password")
    # MD5 without salt—trivial to crack
    return hashlib.md5(password.encode()).hexdigest()

@app.route("/user/<int:uid>")
def user_profile(uid):
    # A01: Broken Access Control / IDOR (CWE-639)
    # Anyone can read any user's profile by numeric id
    con = db()
    user = con.execute("SELECT id, username, password, role FROM users WHERE id=?", (uid,)).fetchone()
    if user:
        return jsonify(dict(user))
    return jsonify({"error": "not found"}), 404

@app.route("/register", methods=["POST"])
def register():
    # A02/A07: Stores plaintext password; no validation or complexity checks
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    con = db()
    try:
        con.execute("INSERT INTO users(username, password) VALUES(?,?)", (username, password))
        con.commit()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True})

@app.route("/login", methods=["POST"])
def login():
    # A07: ID/Auth failures: no rate limiting, plaintext compare, no lockout
    data = request.get_json(force=True, silent=True) or {}
    user = user_by_username(data.get("username", ""))
    if user and user["password"] == data.get("password", ""):
        resp = jsonify({"ok": True, "msg": "logged in"})
        # Missing Secure/HttpOnly flags (CWE-614)
        resp.set_cookie("auth", f"user:{user['id']}")
        return resp
    return jsonify({"ok": False}), 401

@app.route("/secret")
def secret():
    # A02/A05: Leaks sensitive data (CWE-200)
    return jsonify({
        "api_key": PAYMENT_GATEWAY_API_KEY,
        "db_path": DB_PATH
    })

@app.route("/update_from_url")
def update_from_url():
    # A08: Software and Data Integrity Failures
    # Downloads and executes Python from a URL (combines SSRF + RCE)
    url = request.args.get("url")
    if not url:
        return "Provide ?url=<http(s)://...>"
    code = requests.get(url, timeout=3).text
    # DANGEROUS: executing untrusted code
    exec(code, globals(), globals())  # CWE-494/829
    return "Updated from URL"

@app.route("/tempfile")
def tempfile_demo():
    # CWE-377: Insecure Temporary File
    # Uses predictable filename in world-writable dir
    name = request.args.get("name", "report.txt")
    path = os.path.join(tempfile.gettempdir(), name)  # Predictable
    with open(path, "w") as f:
        f.write("temporary data")
    return jsonify({"tmp": path})

@app.route("/leaky_exception")
def leaky_exception():
    # A09: Poor error handling/logging (CWE-209: Info Exposure Through an Error Message)
    try:
        1 / 0
    except Exception as e:
        return f"Error: {e}, SECRET_KEY={app.config['SECRET_KEY']}", 500  # leaks secrets

# ===========================================
# Debug mode (A05)
# ===========================================
if __name__ == "__main__":
    # DANGEROUS: debug=True exposes interactive debugger + reloader
    app.run(host="0.0.0.0", port=5000, debug=True)
