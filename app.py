from flask import Flask,render_template,jsonify
from database import get_connection
app=Flask(__name__)

@app.route("/")
def dashboard():
    return render_template("index.html")

@app.route("/api/stats")
def stats():
    conn=get_connection()
    cursor=conn.cursor()
    cursor.execute("SELECT COUNT(*) AS total FROM attacks")
    total=cursor.fetchone()["total"]
    cursor.execute("SELECT COUNT(DISTINCT src_ip) AS unique_ips FROM attacks")
    unique_ips=cursor.fetchone()["unique_ips"]
    cursor.execute("SELECT COUNT(*) AS high_risk FROM attacks WHERE aei_score>=7")
    high_risk=cursor.fetchone()["high_risk"]
    data={
        "total":total,
        "unique_ips":unique_ips,
        "high_risk":high_risk
    }
    conn.close()
    return jsonify(data)

@app.route("/api/recent")
def recent():
    conn=get_connection()
    cursor=conn.cursor()
    cursor.execute("""SELECT timestamp,src_ip,service,event_type,aei_score FROM attacks ORDER BY timestamp DESC LIMIT 20""")
    rows=cursor.fetchall()
    conn.close()
    return jsonify(rows)

@app.route("/api/aei")
def aei():
    conn=get_connection()
    cursor=conn.cursor()
    cursor.execute("""SELECT 
                   SUM(CASE WHEN sei_score<=3 THEN 1 ELSE 0 END) low_count,
                   SUM(CASE WHEN aei_score BETWEEN 4 AND 6 THEN 1 ELSE 0 END) medium_count,
                   SUM(CASE WHEN aei_score>=7 THEN 1 ELSE 0 END) high_count
                FROM attacks""")
    result=cursor.fetchone()
    conn.close()
    return jsonify(result)

@app.route("/api/hourly")
def hourly():
    conn=get_connection()
    cursor=conn.cursor()
    cursor.execute("""SELECT
                   HOUR(timestamp) AS hour,
                   COUNT(*) AS attacks
                   FROM attacks
                   GROUP BY HOUR(timestamp)
                   ORDER BY hour""")
    result=cursor.fetchall()
    conn.close()
    return jsonify(result)

if __name__=="__main__":
    app.run(debug=True)