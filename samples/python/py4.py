#!/usr/bin/env python3
"""
ULTRA-DANGEROUS VULNERABLE CODE - FOR SECURITY TESTING & EDUCATION ONLY
This file contains a comprehensive list of severe security vulnerabilities.
DO NOT DEPLOY. EVER.
"""

import os
import sys
import subprocess
import pickle
import json
import xml.etree.ElementTree as ET
import sqlite3
import tempfile
import base64
import hashlib
import hmac
import socket
import urllib.request
import logging
from flask import Flask, request, render_template_string, redirect, session, make_response, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import yaml
import redis
from itsdangerous import URLSafeSerializer

# ========================
# CONFIGURATION & HARDCODED SECRETS (CWE-798)
# ========================
app = Flask(__name__)
app.secret_key = 'insecure_secret_key_12345'  # Hardcoded, weak secret
DATABASE_PASSWORD = "super_secret_db_pass"
API_KEY = "sk_live_51Mn8JqL5fG8hT9wXyZvB7cRtNpQ2aKdE6"
JWT_SECRET = "weak_jwt_secret"
JWT_ALGORITHM = "HS256"

# Hardcoded credentials (CWE-798)
HARDCODED_USER = "admin"
HARDCODED_PASS = "password123"

# ========================
# VULNERABLE ROUTES
# ========================

# 1. CROSS-SITE SCRIPTING (XSS) - (CWE-79)
# =============================================
@app.route('/search')
def search():
    # Reflected XSS - User input directly rendered without escaping
    query = request.args.get('q', '')
    # Using render_template_string unsafely
    return render_template_string(f'<h1>Search Results for: {query}</h1>')

@app.route('/profile/<username>')
def profile(username):
    # Stored XSS simulation (imagine bio from DB)
    user_bio = request.args.get('bio', '<script>alert("XSS")</script>')
    return render_template_string(f'''
        <h1>Profile: {username}</h1>
        <p>Bio: {user_bio}</p>
    ''')

# 2. CROSS-SITE REQUEST FORGERY (CSRF) - (CWE-352)
# =============================================
@app.route('/change_email', methods=['GET', 'POST'])
def change_email():
    if request.method == 'POST':
        # No CSRF token validation!
        new_email = request.form['email']
        # ... change email logic ...
        return f'Email changed to {new_email} (Vulnerable to CSRF!)'
    return '''
    <form method="POST">
        New Email: <input type="text" name="email">
        <input type="submit" value="Change Email">
    </form>
    '''

# 3. SQL INJECTION (CWE-89)
# =============================================
@app.route('/user')
def get_user():
    user_id = request.args.get('id', '1')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Direct concatenation - SQL Injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    result = cursor.fetchall()
    return str(result)

# 4. COMMAND INJECTION (CWE-78)
# =============================================
@app.route('/ping')
def ping():
    host = request.args.get('host', '127.0.0.1')
    # Shell injection vulnerability
    cmd = f"ping -c 1 {host}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return f'<pre>{result.stdout}</pre>'

# 5. INSECURE DESERIALIZATION (CWE-502)
# =============================================
@app.route('/deserialize')
def deserialize():
    data = request.args.get('data', '')
    try:
        # Dangerous pickle deserialization
        deserialized = pickle.loads(base64.urlsafe_b64decode(data))
        return str(deserialized)
    except Exception as e:
        return f"Error: {str(e)}"

# 6. XXE (XML External Entity) (CWE-611)
# =============================================
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    xml_data = request.data
    try:
        # XXE enabled by default
        root = ET.fromstring(xml_data)
        return ET.tostring(root, encoding='unicode')
    except Exception as e:
        return f"Error: {str(e)}"

# 7. INSECURE DIRECT OBJECT REFERENCE (IDOR) (CWE-639)
# =============================================
@app.route('/file')
def get_file():
    filename = request.args.get('name', 'test.txt')
    # No authorization check - path traversal possible
    filepath = os.path.join('/tmp/uploads', filename)
    try:
        with open(filepath, 'r') as f:
            return f.read()
    except:
        return "File not found"

# 8. SECURITY MISCONFIGURATION
# =============================================
@app.route('/debug')
def debug_info():
    # Information exposure (CWE-497)
    debug_info = {
        'system': os.uname(),
        'environment': dict(os.environ),
        'python_path': sys.path
    }
    return json.dumps(debug_info, indent=2)

# 9. WEAK CRYPTOGRAPHY
# =============================================
def weak_hash(password):
    # Using broken MD5 (CWE-327, CWE-328)
    return hashlib.md5(password.encode()).hexdigest()

@app.route('/login_weak', methods=['POST'])
def login_weak():
    username = request.form['username']
    password = request.form['password']
    if username == HARDCODED_USER and weak_hash(password) == weak_hash(HARDCODED_PASS):
        return "Logged in (with weak hash!)"
    return "Login failed"

# 10. INSECURE FILE UPLOAD (CWE-434)
# =============================================
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file"
    file = request.files['file']
    if file.filename == '':
        return "No filename"
    
    # No validation of file type or content
    filename = file.filename
    upload_path = os.path.join('/tmp/uploads', filename)
    file.save(upload_path)
    
    # Dangerous permissions (CWE-732)
    os.chmod(upload_path, 0o777)
    return f"File uploaded to {upload_path}"

# 11. SERVER-SIDE REQUEST FORGERY (SSRF) (CWE-918)
# =============================================
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url', 'http://example.com')
    try:
        # No URL validation or allowlisting
        response = urllib.request.urlopen(url)
        return response.read().decode('utf-8')
    except Exception as e:
        return f"Error fetching URL: {str(e)}"

# 12. INSECURE SESSION MANAGEMENT (CWE-384, CWE-613)
# =============================================
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if username == HARDCODED_USER and password == HARDCODED_PASS:
        session['user'] = username
        session.permanent = True  # No expiration (CWE-613)
        return "Logged in successfully"
    return "Invalid credentials"

# 13. CODE INJECTION (CWE-94)
# =============================================
@app.route('/eval')
def evaluate():
    code = request.args.get('code', '1+1')
    try:
        # Dynamic code execution - EXTREMELY DANGEROUS
        result = eval(code)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

# 14. OPEN REDIRECT (CWE-601)
# =============================================
@app.route('/redirect')
def unsafe_redirect():
    url = request.args.get('url', '/')
    # No validation of redirect URL
    return redirect(url)

# 15. RACE CONDITION (CWE-367)
# =============================================
@app.route('/transfer', methods=['POST'])
def transfer_funds():
    amount = float(request.form['amount'])
    # Simulated race condition vulnerability
    balance = 1000.0  # Starting balance
    
    # Time-of-check time-of-use (TOCTOU) gap
    if amount <= balance:
        # Imagine a context switch happens here
        balance -= amount
        return f"Transferred ${amount}. New balance: ${balance}"
    return "Insufficient funds"

# 16. WEAK RANDOMNESS (CWE-338)
# =============================================
import random
@app.route('/generate_token')
def generate_token():
    # Using cryptographically weak PRNG
    token = random.randint(100000, 999999)
    return f"Your secure token: {token}"

# 17. LOGGING SENSITIVE DATA (CWE-532)
# =============================================
logging.basicConfig(filename='app.log', level=logging.INFO)

@app.route('/pay', methods=['POST'])
def process_payment():
    card_number = request.form['card_number']
    # Logging sensitive data
    logging.info(f"Payment processed with card: {card_number}")
    return "Payment processed (and logged!)"

# 18. MISCONFIGURED CORS (CWE-942)
# =============================================
from flask_cors import CORS
# Overly permissive CORS
CORS(app, resources={r"/*": {"origins": "*"}})

# 19. NO RATE LIMITING (CWE-770)
# =============================================
@app.route('/forgot_password')
def forgot_password():
    # No rate limiting on password reset
    email = request.args.get('email', '')
    return f"Password reset link sent to {email} (maybe)"

# 20. HARDCODED CRYPTOGRAPHIC KEY (CWE-321)
# =============================================
# Hardcoded encryption key
CRYPTO_KEY = b'thisisveryweakkey'
serializer = URLSafeSerializer(CRYPTO_KEY)

@app.route('/get_token')
def get_secure_token():
    # Using hardcoded key for serialization
    return serializer.dumps({'user': 'admin', 'role': 'superuser'})

# 21. NO INPUT VALIDATION (CWE-20)
# =============================================
@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    # No validation of username length, type, or content
    return f"User {username} created!"

# 22. EXPOSED SENSITIVE INFORMATION (CWE-497, CWE-538)
# =============================================
@app.route('/.git/HEAD')
def git_exposure():
    # Simulated git information exposure
    return "ref: refs/heads/master"

@app.route('/env')
def environment_exposure():
    # Exposing environment variables
    return json.dumps(dict(os.environ))

# ========================
# MAIN & STARTUP
# ========================
def init_database():
    """Initialize a vulnerable database"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY, name TEXT, password TEXT)''')
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password123')")
    conn.commit()
    conn.close()

if __name__ == '__main__':
    print("🚨 EXTREME WARNING: Starting ultra-vulnerable server 🚨")
    print("This application contains dozens of critical security vulnerabilities")
    print("DO NOT expose this to any network. For testing in isolated environments only.")
    
    init_database()
    
    # Create vulnerable upload directory
    os.makedirs('/tmp/uploads', exist_ok=True)
    
    # Start the dangerously configured server
    app.run(
        host='0.0.0.0',  # Listen on all interfaces (CWE-1327)
        port=5000,
        debug=True,      # Debug mode enabled (CWE-489, CWE-215)
        threaded=True
    )