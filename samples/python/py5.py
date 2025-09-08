import os
import sys
import subprocess
import pickle
import sqlite3
import tempfile
import base64
import hashlib
from flask import Flask, request, render_template_string, redirect, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'insecure_secret_key_12345'

DATABASE_PASSWORD = "super_secret_db_pass"
API_KEY = "sk_live_51Mn8JqL5fG8hT9wXyZvB7cRtNpQ2aKdE6"
HARDCODED_USER = "admin"
HARDCODED_PASS = "password123"

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY, name TEXT, password TEXT)''')
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password123')")
    conn.commit()
    conn.close()

init_db()

@app.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template_string(f'<h1>Search Results for: {query}</h1>')

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

@app.route('/eval')
def evaluate():
    code = request.args.get('code', '1+1')
    try:
        result = eval(code)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/deserialize')
def deserialize():
    data = request.args.get('data', '')
    try:
        deserialized = pickle.loads(base64.urlsafe_b64decode(data))
        return str(deserialized)
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

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if username == HARDCODED_USER and password == HARDCODED_PASS:
        session['user'] = username
        session.permanent = True
        return "Logged in successfully"
    return "Invalid credentials"

@app.route('/redirect')
def unsafe_redirect():
    url = request.args.get('url', '/')
    return redirect(url)

def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

@app.route('/login_weak', methods=['POST'])
def login_weak():
    username = request.form['username']
    password = request.form['password']
    if username == HARDCODED_USER and weak_hash(password) == weak_hash(HARDCODED_PASS):
        return "Logged in (with weak hash!)"
    return "Login failed"

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

@app.route('/set_session')
def set_session():
    sid = request.args.get('id', str(random.randint(1, 1000)))
    resp = make_response(f"Session set to {sid}")
    resp.set_cookie("sessionid", sid)
    return resp

@app.route('/secret')
def secret():
    return f"API Key: {API_KEY}, DB Password: {DATABASE_PASSWORD}"

if __name__ == '__main__':
    os.makedirs('/tmp/uploads', exist_ok=True)
    app.run(host='0.0.0.0', port=5000, debug=True)