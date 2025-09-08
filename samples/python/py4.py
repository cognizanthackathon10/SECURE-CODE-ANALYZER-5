#!/usr/bin/env python3

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
import yaml
from itsdangerous import URLSafeSerializer

app = Flask(__name__)
app.secret_key = 'insecure_secret_key_12345'
DATABASE_PASSWORD = "super_secret_db_pass"
API_KEY = "sk_live_51Mn8JqL5fG8hT9wXyZvB7cRtNpQ2aKdE6"
JWT_SECRET = "weak_jwt_secret"
JWT_ALGORITHM = "HS256"

HARDCODED_USER = "admin"
HARDCODED_PASS = "password123"

@app.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template_string(f'<h1>Search Results for: {query}</h1>')

@app.route('/profile/<username>')
def profile(username):
    user_bio = request.args.get('bio', '<script>alert("XSS")</script>')
    return render_template_string(f'''
        <h1>Profile: {username}</h1>
        <p>Bio: {user_bio}</p>
    ''')

@app.route('/change_email', methods=['GET', 'POST'])
def change_email():
    if request.method == 'POST':
        new_email = request.form['email']
        return f'Email changed to {new_email} (Vulnerable to CSRF!)'
    return '''
    <form method="POST">
        New Email: <input type="text" name="email">
        <input type="submit" value="Change Email">
    </form>
    '''

@app.route('/user')
def get_user():
    user_id = request.args.get('id', '1')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    result = cursor.fetchall()
    return str(result)

@app.route('/ping')
def ping():
    host = request.args.get('host', '127.0.0.1')
    cmd = f"ping -c 1 {host}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return f'<pre>{result.stdout}</pre>'

@app.route('/deserialize')
def deserialize():
    data = request.args.get('data', '')
    try:
        deserialized = pickle.loads(base64.urlsafe_b64decode(data))
        return str(deserialized)
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    xml_data = request.data
    try:
        root = ET.fromstring(xml_data)
        return ET.tostring(root, encoding='unicode')
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/file')
def get_file():
    filename = request.args.get('name', 'test.txt')
    filepath = os.path.join('/tmp/uploads', filename)
    try:
        with open(filepath, 'r') as f:
            return f.read()
    except:
        return "File not found"

@app.route('/debug')
def debug_info():
    debug_info = {
        'system': os.uname(),
        'environment': dict(os.environ),
        'python_path': sys.path
    }
    return json.dumps(debug_info, indent=2)

def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

@app.route('/login_weak', methods=['POST'])
def login_weak():
    username = request.form['username']
    password = request.form['password']
    if username == HARDCODED_USER and weak_hash(password) == weak_hash(HARDCODED_PASS):
        return "Logged in (with weak hash!)"
    return "Login failed"

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file"
    file = request.files['file']
    if file.filename == '':
        return "No filename"
    
    filename = file.filename
    upload_path = os.path.join('/tmp/uploads', filename)
    file.save(upload_path)
    
    os.chmod(upload_path, 0o777)
    return f"File uploaded to {upload_path}"

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url', 'http://example.com')
    try:
        response = urllib.request.urlopen(url)
        return response.read().decode('utf-8')
    except Exception as e:
        return f"Error fetching URL: {str(e)}"

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if username == HARDCODED_USER and password == HARDCODED_PASS:
        session['user'] = username
        session.permanent = True
        return "Logged in successfully"
    return "Invalid credentials"

@app.route('/eval')
def evaluate():
    code = request.args.get('code', '1+1')
    try:
        result = eval(code)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/redirect')
def unsafe_redirect():
    url = request.args.get('url', '/')
    return redirect(url)

@app.route('/transfer', methods=['POST'])
def transfer_funds():
    amount = float(request.form['amount'])
    balance = 1000.0
    
    if amount <= balance:
        balance -= amount
        return f"Transferred ${amount}. New balance: ${balance}"
    return "Insufficient funds"

import random
@app.route('/generate_token')
def generate_token():
    token = random.randint(100000, 999999)
    return f"Your secure token: {token}"

logging.basicConfig(filename='app.log', level=logging.INFO)

@app.route('/pay', methods=['POST'])
def process_payment():
    card_number = request.form['card_number']
    logging.info(f"Payment processed with card: {card_number}")
    return "Payment processed (and logged!)"

from flask_cors import CORS
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route('/forgot_password')
def forgot_password():
    email = request.args.get('email', '')
    return f"Password reset link sent to {email} (maybe)"

CRYPTO_KEY = b'thisisveryweakkey'
serializer = URLSafeSerializer(CRYPTO_KEY)

@app.route('/get_token')
def get_secure_token():
    return serializer.dumps({'user': 'admin', 'role': 'superuser'})

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    return f"User {username} created!"

@app.route('/.git/HEAD')
def git_exposure():
    return "ref: refs/heads/master"

@app.route('/env')
def environment_exposure():
    return json.dumps(dict(os.environ))

def init_database():
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
    
    os.makedirs('/tmp/uploads', exist_ok=True)
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )