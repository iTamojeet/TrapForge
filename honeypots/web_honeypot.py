from flask import Flask, request, jsonify
import pymysql
from datetime import datetime

app = Flask(__name__)

def log_to_db(src_ip, username, password, path):
    try:
        conn = pymysql.connect(host='localhost', user='deceptiq',
                               password='TrapForge@123', database='honeypot')
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO attacks 
            (session_id, timestamp, src_ip, service, username, password, event_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (f"web-{src_ip}-{datetime.now().timestamp()}", datetime.now(),
              src_ip, 'web', username, password, 'login_attempt'))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB error: {e}")

@app.route('/')
def index():
    return '''
    <html><body style="background:#1a1a1a; display:flex; justify-content:center; align-items:center; height:100vh;">
    <div style="background:#fff; padding:40px; border-radius:8px; width:300px;">
        <h2 style="text-align:center;">Admin Panel</h2>
        <form method="POST" action="/login">
            <input name="username" placeholder="Username" style="width:100%; padding:8px; margin:8px 0;"><br>
            <input name="password" type="password" placeholder="Password" style="width:100%; padding:8px; margin:8px 0;"><br>
            <button type="submit" style="width:100%; padding:10px; background:#007bff; color:#fff; border:none;">Login</button>
        </form>
    </div></body></html>
    '''

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    src_ip = request.remote_addr
    log_to_db(src_ip, username, password, '/login')
    return '''<html><body style="background:#1a1a1a; display:flex; justify-content:center; 
    align-items:center; height:100vh;">
    <div style="background:#fff; padding:40px; border-radius:8px;">
    <h3>Invalid credentials. Please try again.</h3></div></body></html>'''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)
