

from flask import Flask, render_template_string, request, redirect, url_for, flash
import sqlite3
import re
import os

# ------------------------------
# Configuration and Setup
# ------------------------------

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Needed for flash messaging
DATABASE = "security_logs.db"

# Define patterns for detecting suspicious SQL queries (e.g., SQL injection signatures)
SUSPICIOUS_PATTERNS = [
    re.compile(r"(UNION\s+SELECT)", re.IGNORECASE),
    re.compile(r"(' OR '1'='1)", re.IGNORECASE),
    re.compile(r"(--|#|/\*)", re.IGNORECASE),  # SQL comment operators
]

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Enable accessing columns by name
    return conn

def create_tables():
    """Creates the necessary tables if they don't already exist."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            query_text TEXT,
            ip_address TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS suspicious_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER,
            detection_rule TEXT,
            severity_level INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(log_id) REFERENCES logs(log_id)
        )
    """)
    conn.commit()
    conn.close()

# ------------------------------
# Core Functions
# ------------------------------

def detect_suspicious_query(query_text):
    """
    Check the query_text for suspicious patterns.
    Returns a tuple: (score, triggered_rules)
    """
    score = 0
    triggered_rules = []
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(query_text):
            score += 1
            triggered_rules.append(pattern.pattern)
    return score, triggered_rules

def log_query(user_id, query_text, ip_address):
    """Logs a query into the logs table and returns its log_id."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO logs (user_id, query_text, ip_address) VALUES (?, ?, ?)",
        (user_id, query_text, ip_address)
    )
    log_id = cur.lastrowid
    conn.commit()
    conn.close()
    return log_id

def mark_suspicious(log_id, detection_rule, severity=2):
    """Marks a query as suspicious by logging an event."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO suspicious_events (log_id, detection_rule, severity_level) VALUES (?, ?, ?)",
        (log_id, detection_rule, severity)
    )
    conn.commit()
    conn.close()

def get_all_logs():
    """Retrieves all logged queries."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs ORDER BY timestamp DESC")
    logs = cur.fetchall()
    conn.close()
    return logs

def get_suspicious_events():
    """Retrieves all suspicious events joined with their query details."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT s.event_id, s.log_id, s.detection_rule, s.severity_level, s.timestamp,
               l.query_text, l.user_id, l.ip_address
        FROM suspicious_events s
        JOIN logs l ON s.log_id = l.log_id
        ORDER BY s.timestamp DESC
    """)
    events = cur.fetchall()
    conn.close()
    return events

# ------------------------------
# Flask Routes - Web Dashboard
# ------------------------------

@app.route("/")
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Dashboard</title>
    </head>
    <body>
        <h1>Security Dashboard</h1>
        <ul>
            <li><a href="{{ url_for('log_query_route') }}">Log a New Query</a></li>
            <li><a href="{{ url_for('show_logs') }}">View All Logs</a></li>
            <li><a href="{{ url_for('show_suspicious') }}">View Suspicious Events</a></li>
        </ul>
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            <ul>
            {% for category, message in messages %}
              <li><strong>{{ category.capitalize() }}:</strong> {{ message }}</li>
            {% endfor %}
            </ul>
          {% endif %}
        {% endwith %}
    </body>
    </html>
    """)

@app.route("/log", methods=["GET", "POST"])
def log_query_route():
    if request.method == "POST":
        user_id = request.form.get("user_id")
        query_text = request.form.get("query_text")
        ip_address = request.form.get("ip_address")
        
        try:
            user_id_int = int(user_id)
        except ValueError:
            flash("User ID must be a number.", "error")
            return redirect(url_for('log_query_route'))
        
        # Log the query
        log_id = log_query(user_id_int, query_text, ip_address)
        
        # Run detection on the query
        score, triggered_rules = detect_suspicious_query(query_text)
        if score > 0:
            for rule in triggered_rules:
                mark_suspicious(log_id, rule)
            flash("Query logged and flagged as suspicious!", "warning")
        else:
            flash("Query logged successfully.", "success")
        return redirect(url_for('index'))
    
    # GET request renders the logging form
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Log a New Query</title>
    </head>
    <body>
        <h1>Log a New Query</h1>
        <form method="post">
            <label for="user_id">User ID:</label><br>
            <input type="text" id="user_id" name="user_id" required><br><br>
            
            <label for="query_text">SQL Query Text:</label><br>
            <textarea id="query_text" name="query_text" rows="4" cols="50" required></textarea><br><br>
            
            <label for="ip_address">IP Address:</label><br>
            <input type="text" id="ip_address" name="ip_address" required><br><br>
            
            <input type="submit" value="Log Query">
        </form>
        <br>
        <a href="{{ url_for('index') }}">Back to Dashboard</a>
    </body>
    </html>
    """)

@app.route("/logs")
def show_logs():
    logs = get_all_logs()
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>All Logs</title>
    </head>
    <body>
        <h1>All Logs</h1>
        <table border="1" cellpadding="5">
            <tr>
                <th>Log ID</th>
                <th>User ID</th>
                <th>Query Text</th>
                <th>IP Address</th>
                <th>Timestamp</th>
            </tr>
            {% for log in logs %}
            <tr>
                <td>{{ log.log_id }}</td>
                <td>{{ log.user_id }}</td>
                <td>{{ log.query_text }}</td>
                <td>{{ log.ip_address }}</td>
                <td>{{ log.timestamp }}</td>
            </tr>
            {% endfor %}
        </table>
        <br>
        <a href="{{ url_for('index') }}">Back to Dashboard</a>
    </body>
    </html>
    """, logs=logs)

@app.route("/suspicious")
def show_suspicious():
    events = get_suspicious_events()
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Suspicious Events</title>
    </head>
    <body>
        <h1>Suspicious Events</h1>
        <table border="1" cellpadding="5">
            <tr>
                <th>Event ID</th>
                <th>Log ID</th>
                <th>User ID</th>
                <th>Query Text</th>
                <th>IP Address</th>
                <th>Detection Rule</th>
                <th>Severity</th>
                <th>Timestamp</th>
            </tr>
            {% for event in events %}
            <tr>
                <td>{{ event.event_id }}</td>
                <td>{{ event.log_id }}</td>
                <td>{{ event.user_id }}</td>
                <td>{{ event.query_text }}</td>
                <td>{{ event.ip_address }}</td>
                <td>{{ event.detection_rule }}</td>
                <td>{{ event.severity_level }}</td>
                <td>{{ event.timestamp }}</td>
            </tr>
            {% endfor %}
        </table>
        <br>
        <a href="{{ url_for('index') }}">Back to Dashboard</a>
    </body>
    </html>
    """, events=events)

# ------------------------------
# Main Entry Point
# ------------------------------

if __name__ == "__main__":
    # Ensure the database and tables exist before starting the server.
    if not os.path.exists(DATABASE):
        create_tables()
    else:
        create_tables()  # In case tables are missing.
    app.run(debug=True)
