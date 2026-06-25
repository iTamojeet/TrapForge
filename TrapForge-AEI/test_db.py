import mysql.connector
from config import DB_CONFIG

conn = mysql.connector.connect(**DB_CONFIG)
cursor = conn.cursor()
cursor.execute("SELECT COUNT(*) FROM unified_logs")
count = cursor.fetchone()[0]
print(f"Connected successfully! Total log entries: {count}")
conn.close()