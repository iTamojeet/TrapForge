from flask import Flask, render_template, jsonify
from database import get_connection

app = Flask(__name__)

@app.route("/")
def dashboard():
    return render_template("index.html")

@app.route("/api/stats")
def stats():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) AS total FROM unified_logs")
    total = cursor.fetchone()["total"]
    cursor.execute("SELECT COUNT(DISTINCT source_ip) AS unique_ips FROM unified_logs")
    unique_ips = cursor.fetchone()["unique_ips"]
    cursor.execute("SELECT COUNT(*) AS high_risk FROM session_scores WHERE aei_level='High'")
    high_risk = cursor.fetchone()["high_risk"]
    cursor.execute("SELECT COUNT(*) AS sessions FROM session_scores")
    sessions = cursor.fetchone()["sessions"]
    cursor.execute("SELECT ROUND(AVG(aei_score),2) AS avg_aei FROM session_scores")
    avg_aei = cursor.fetchone()["avg_aei"] or 0
    conn.close()
    return jsonify({"total": total, "unique_ips": unique_ips, "high_risk": high_risk, "sessions": sessions, "avg_aei": float(avg_aei)})

@app.route("/api/recent")
def recent():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.timestamp, u.source_ip, u.service, u.event_type,
               COALESCE(s.aei_score, 0) AS aei_score,
               COALESCE(s.aei_level, 'Low') AS aei_level
        FROM unified_logs u
        LEFT JOIN session_scores s ON u.session_id = s.session_id
        ORDER BY u.timestamp DESC LIMIT 20
    """)
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)

@app.route("/api/aei")
def aei():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            SUM(CASE WHEN aei_level='Low' THEN 1 ELSE 0 END) AS low_count,
            SUM(CASE WHEN aei_level='Medium' THEN 1 ELSE 0 END) AS medium_count,
            SUM(CASE WHEN aei_level='High' THEN 1 ELSE 0 END) AS high_count
        FROM session_scores
    """)
    result = cursor.fetchone()
    conn.close()
    return jsonify(result)

@app.route("/api/hourly")
def hourly():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT HOUR(timestamp) AS hour, COUNT(*) AS attacks FROM unified_logs GROUP BY HOUR(timestamp) ORDER BY hour")
    result = cursor.fetchall()
    conn.close()
    return jsonify(result)

@app.route("/api/services")
def services():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT service, COUNT(*) AS count FROM unified_logs GROUP BY service")
    result = cursor.fetchall()
    conn.close()
    return jsonify(result)

@app.route("/api/top_attackers")
def top_attackers():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT source_ip, aei_score, aei_level, drs_score,
               total_events, services_hit, first_seen, last_seen
        FROM session_scores ORDER BY aei_score DESC LIMIT 10
    """)
    result = cursor.fetchall()
    conn.close()
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
