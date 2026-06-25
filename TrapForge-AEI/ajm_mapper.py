import mysql.connector
from config import DB_CONFIG

# ================================================================
# AJM — Attack Journey Mapper
# ================================================================
# AJM reconstructs the exact step-by-step path each attacker
# took through our honeypot environment.
#
# Each event is labelled with a PHASE from the attack lifecycle:
#   Reconnaissance  → attacker is scanning/probing
#   Initial Access  → login attempts
#   Execution       → running commands on the system
#   Exfiltration    → stealing/transferring files or data
#   Impact          → destructive actions (DROP TABLE, etc.)
#   Lateral Move    → jumping to a new service
# ================================================================

# Keywords that map an event to a specific attack phase
PHASE_RULES = {
    "Exfiltration": [
        "wget", "curl", "download", "upload", "scp",
        "ftp", "/etc/shadow", "/etc/passwd", "exfil"
    ],
    "Impact": [
        "DROP", "DELETE FROM", "TRUNCATE", "rm -rf",
        "format", "shutdown", "reboot", "mkfs"
    ],
    "Execution": [
        "chmod", "bash", "python", "perl", "sh ",
        "exec", "whoami", "uname", "ls ", "cat ",
        "id ", "ps ", "netstat", "ifconfig", "exploit",
        "rootkit", "payload", "/tmp/", "reverse"
    ],
    "Reconnaissance": [
        "nmap", "scan", "probe", "ping", "traceroute",
        "GET /", "HEAD /", "OPTIONS /", "config", "admin",
        "phpmyadmin", "SELECT *", "SHOW TABLES"
    ],
}

LATERAL_SERVICES = {"ssh", "ftp", "http", "db"}


def classify_phase(event_type, raw_payload, service):
    """
    Decide which attack phase this single event belongs to.
    Checks keywords in the payload, then falls back to event_type.
    """
    payload = (raw_payload or "").lower()

    # Check keyword rules in priority order
    for phase, keywords in PHASE_RULES.items():
        for keyword in keywords:
            if keyword.lower() in payload:
                return phase

    # Fallback: classify by event_type if no keyword matched
    if event_type == "login_attempt":
        return "Initial Access"
    elif event_type == "command":
        return "Execution"
    elif event_type == "file_transfer":
        return "Exfiltration"
    elif event_type == "http_request":
        return "Reconnaissance"
    elif event_type == "query":
        return "Reconnaissance"

    return "Reconnaissance"  # default


def detect_lateral_movement(events):
    """
    Find all points where the attacker switched to a new service.
    Returns a set of step indexes (0-based) where a service switch happened.
    """
    lateral_steps = set()
    prev_service = None
    for i, event in enumerate(events):
        current_service = event[1]  # service column
        if prev_service is not None and current_service != prev_service:
            lateral_steps.add(i)
        prev_service = current_service
    return lateral_steps


def get_all_attackers(cursor):
    """Get every unique attacker IP address in the logs."""
    cursor.execute("""
        SELECT DISTINCT source_ip 
        FROM unified_logs 
        WHERE source_ip IS NOT NULL
    """)
    return [row[0] for row in cursor.fetchall()]


def get_attacker_events(cursor, source_ip):
    """Fetch all events for one IP, across ALL sessions, ordered by time."""
    cursor.execute("""
        SELECT timestamp, service, event_type, raw_payload,
               session_id, source_country
        FROM unified_logs
        WHERE source_ip = %s
        ORDER BY timestamp ASC
    """, (source_ip,))
    return cursor.fetchall()


def build_journey(source_ip, cursor):
    """
    Build the full step-by-step attack journey for one IP.
    Returns a list of step dictionaries.
    """
    events = get_attacker_events(cursor, source_ip)
    if not events:
        return []

    lateral_steps = detect_lateral_movement(events)
    journey = []

    for i, event in enumerate(events):
        timestamp, service, event_type, raw_payload, session_id, country = event

        # Classify phase — upgrade to "Lateral Move" if service switched
        phase = classify_phase(event_type, raw_payload, service)
        if i in lateral_steps:
            phase = "Lateral Move"

        step = {
            "source_ip":   source_ip,
            "session_id":  session_id,
            "step_number": i + 1,
            "event_time":  timestamp,
            "service":     service,
            "event_type":  event_type,
            "raw_payload": raw_payload,
            "phase":       phase,
        }
        journey.append(step)

    return journey


def save_journey(cursor, conn, journey):
    """Write all journey steps into attack_journeys table."""
    if not journey:
        return

    source_ip = journey[0]["source_ip"]

    # Clear old journey for this IP before inserting fresh
    cursor.execute(
        "DELETE FROM attack_journeys WHERE source_ip = %s",
        (source_ip,)
    )

    for step in journey:
        cursor.execute("""
            INSERT INTO attack_journeys
                (source_ip, session_id, step_number, event_time,
                 service, event_type, raw_payload, phase)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            step["source_ip"],
            step["session_id"],
            step["step_number"],
            step["event_time"],
            step["service"],
            step["event_type"],
            step["raw_payload"],
            step["phase"],
        ))
    conn.commit()


def print_journey(source_ip, journey):
    """Print the journey in a readable format."""
    print(f"\nAttacker IP : {source_ip}")
    print(f"Total Steps : {len(journey)}")
    print("-" * 62)
    print(f"{'Step':<5} {'Time':<22} {'Service':<7} {'Phase':<16} {'Action'}")
    print("-" * 62)
    for step in journey:
        time_str = step["event_time"].strftime("%H:%M:%S")
        payload  = (step["raw_payload"] or "")[:35]
        print(f"{step['step_number']:<5} {time_str:<22} "
              f"{step['service']:<7} {step['phase']:<16} {payload}")
    print("-" * 62)


def run_ajm_engine():
    """Main function: map journeys for all attacker IPs."""
    conn   = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    print("=" * 62)
    print("   TrapForge AJM Engine — Attack Journey Mapper")
    print("=" * 62)

    attackers = get_all_attackers(cursor)
    print(f"\nUnique attackers found: {len(attackers)}")

    for ip in attackers:
        journey = build_journey(ip, cursor)
        save_journey(cursor, conn, journey)
        print_journey(ip, journey)

    print(f"\nAll journeys saved to attack_journeys table.")
    cursor.close()
    conn.close()


if __name__ == "__main__":
    run_ajm_engine()