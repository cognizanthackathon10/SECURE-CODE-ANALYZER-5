
import os
import sqlite3
import pickle
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "hardcoded-secret" 



def init_db():
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    cur.execute("DELETE FROM users")
    cur.execute("INSERT INTO users (username, password, role) VALUES ('admin','admin123','admin')")
    cur.execute("INSERT INTO users (username, password, role) VALUES ('bob','bob123','user')")
    conn.commit()
    conn.close()


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")


    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute(f"SELECT role FROM users WHERE username='{username}' AND password='{password}'")  
    row = cur.fetchone()
    conn.close()

    if row:
        session["user"] = username
        session["role"] = row[0]
        return f"Logged in as {username} with role {row[0]}"
    else:
        return "Invalid login", 401


@app.route("/admin")
def admin_panel():

    if "user" not in session:
        return "Unauthorized", 403

    return "Welcome to the admin panel! (everyone logged in can see this)"



@app.route("/debug")
def debug():

    return str(dict(os.environ))



@app.route("/upload", methods=["POST"])
def upload_pickle():
    f = request.files["file"]

    data = pickle.loads(f.read())
    return f"Unpickled object: {data}"


if __name__ == "__main__":
    init_db()

    app.run(host="0.0.0.0", port=5000, debug=True)
