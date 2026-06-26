import mysql.connector
import json
import time

from adaptation_rules import RULES

DB_CONFIG = {
    "host": "localhost",
    "port": 3306,
    "user": "deceptiq",
    "password": "TrapForge@123",
    "database": "honeypot"
}


def get_latest_attacker():

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT session_id,
               source_ip,
               aei_score,
               aei_level
        FROM session_scores
        ORDER BY aei_score DESC
        LIMIT 1
    """)

    attacker = cursor.fetchone()

    cursor.close()
    conn.close()

    return attacker


def push_configuration(config):

    with open("current_mode.json", "w") as f:
        json.dump(config, f, indent=4)


def adapt_environment(attacker):

    level = attacker["aei_level"]

    config = RULES[level]

    push_configuration(config)

    print("\n=== ADAPTIVE RESPONSE ACTIVATED ===")
    print("IP :", attacker["source_ip"])
    print("AEI :", attacker["aei_score"])
    print("Level :", level)
    print("Mode :", config["mode"])
    print("Fake Files :", config["fake_files"])
    print("Services :", config["fake_services"])
    print("Fake Login :", config["allow_fake_login"])
    print("===================================")


if __name__ == "__main__":

    print("Adaptive Response Engine Started...")

    while True:

        try:

            attacker = get_latest_attacker()

            if attacker:
                adapt_environment(attacker)

        except Exception as e:
            print("Error:", e)

        time.sleep(5)