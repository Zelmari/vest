import sqlite3
import os
from flask import Flask, request, render_template_string, make_response, send_file

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "demo.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )"""
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'supersecret123')"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password) VALUES ('jdoe', 'password123')"
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return """<html><body>
    <h1>Demo Portal</h1>
    <ul>
        <li><a href="/login">Login</a></li>
        <li><a href="/search">Search</a></li>
        <li><a href="/files">View Files</a></li>
    </ul>
    </body></html>"""


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = get_db()
        query = (
            f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        )
        cursor = conn.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            message = f"Welcome back, {username}!"
        else:
            message = "Invalid credentials."
    return f"""<html><body>
    <h1>Login</h1>
    <form method="post">
        <input name="username" placeholder="Username"><br>
        <input name="password" placeholder="Password" type="password"><br>
        <button type="submit">Login</button>
    </form>
    <p>{message}</p>
    </body></html>"""


@app.route("/search")
def search():
    query = request.args.get("q", "")
    results_html = ""
    if query:
        results_html = f"<p>Results for: {query}</p>"
    return f"""<html><body>
    <h1>Search</h1>
    <form method="get">
        <input name="q" placeholder="Search...">
        <button type="submit">Search</button>
    </form>
    {results_html}
    </body></html>"""


@app.route("/files")
def file_viewer():
    filename = request.args.get("filename", "")
    if not filename:
        return """<html><body>
        <h1>File Viewer</h1>
        <form method="get">
            <input name="filename" placeholder="Enter filename...">
            <button type="submit">View</button>
        </form>
        </body></html>"""
    try:
        with open(filename, "r") as f:
            content = f.read()
        return f"""<html><body>
        <h1>File: {filename}</h1>
        <pre>{content}</pre>
        </body></html>"""
    except Exception:
        return f"<p>Could not open file: {filename}</p>"


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "*"
    return response


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5555, debug=True)
