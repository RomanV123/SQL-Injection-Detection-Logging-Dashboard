
import sqlite3

DATABASE = "security_logs.db"

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Allows accessing columns by name
    return conn

def create_tables():
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

def log_query(user_id, query_text, ip_address):
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
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO suspicious_events (log_id, detection_rule, severity_level) VALUES (?, ?, ?)",
        (log_id, detection_rule, severity)
    )
    conn.commit()
    conn.close()

def get_all_logs():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs ORDER BY timestamp DESC")
    logs = cur.fetchall()
    conn.close()
    return logs

def get_suspicious_events():
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
