import pymysql
def get_connection():
    return pymysql.connect(
        host="localhost",
        user="deceptiq",
        password="TrapForge@123",
        database="honeypot",
        cursorclass=pymysql.cursors.DictCursor
    )