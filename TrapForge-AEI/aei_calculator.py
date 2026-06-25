import mysql.connector
from config import DB_CONFIG

# ================================================================
# AEI CALCULATOR — Attack Engagement Index
# ================================================================
# AEI measures how deeply an attacker engaged with our honeypot.
# Score is 0 to 10.
#   Low    (0 - 3.0) : Bot/scanner, barely interacted
#   Medium (3.0 - 6.0): Some exploration, moderate threat
#   High   (6.0 - 10) : Deep engagement, skilled attacker
# ================================================================

# --- WEIGHTS: each sub-metric's contribution to AEI ---
# All weights must add up to 1.0
WEIGHTS = {
    "session_duration":  0.20,  # How long they stayed
    "command_diversity": 0.25,  # How many unique commands they used
    "service_breadth":   0.20,  # How many services they hit
    "exploitation":      0.20,  # Dangerous commands detected
    "file_transfers":    0.10,  # File upload/download attempts
    "login_attempts":    0.05,  # Number of login tries
}

# Keywords in commands that suggest exploitation
EXPLOIT_KEYWORDS = [
    "wget", "curl", "chmod", "exploit", "payload", "rootkit",
    "reverse", "shell", "nc ", "bash -i", "python -c",
    "DROP", "SELECT *", "UNION", "malicious", "/tmp/", "passwd"
]

# Max realistic values per session (used for normalization)
MAX_DURATION   = 300   # 5 minutes max expected
MAX_DIVERSITY  = 10    # 10 unique commands max
MAX_SERVICES   = 4     # 4 services: ssh, ftp, http, db
MAX_EXPLOITS   = 10    # 10 exploit attempts max
MAX_TRANSFERS  = 5     # 5 file transfers max
MAX_LOGINS     = 20    # 20 login attempts max


def normalize(value, max_value):
    """Bring any number into 0-1 range."""
    if max_value == 0:
        return 0.0
    return min(value / max_value, 1.0)


def count_exploits(events):
    """Count events that contain dangerous/exploit keywords."""
    count = 0
    for event in events:
        payload = event[3] or ""  # raw_payload column
        for keyword in EXPLOIT_KEYWORDS:
            if keyword.lower() in payload.lower():
                count += 1
                break  # count each event only once
    return count


def get_all_sessions(cursor):
    """Get list of every unique session ID in the database."""
    cursor.execute(
        "SELECT DISTINCT session_id FROM unified_logs "
        "WHERE session_id IS NOT NULL"
    )
    return [row[0] for row in cursor.fetchall()]


def get_session_events(cursor, session_id):
    """Fetch all events for one session, ordered by time."""
    cursor.execute("""
        SELECT timestamp, service, event_type, raw_payload,
               source_ip, source_country
        FROM unified_logs
        WHERE session_id = %s
        ORDER BY timestamp ASC
    """, (session_id,))
    return cursor.fetchall()


def calculate_aei(session_id, cursor):
    """
    Compute AEI score for one session.
    Returns a result dictionary.
    """
    events = get_session_events(cursor, session_id)
    if not events:
        return None

    # ---- Step 1: Extract raw numbers from the events ----

    # Session duration in seconds
    first_time       = events[0][0]
    last_time        = events[-1][0]
    duration_secs    = (last_time - first_time).total_seconds()

    # Unique commands/payloads
    payloads         = [e[3] for e in events if e[3]]
    unique_commands  = len(set(payloads))
    total_events     = len(events)

    # Services touched (ssh, ftp, http, db)
    services_hit     = set(e[1] for e in events)
    service_count    = len(services_hit)

    # Exploitation attempts
    exploit_count    = count_exploits(events)

    # File transfers
    file_transfers   = sum(1 for e in events if e[2] == 'file_transfer')

    # Login attempts
    login_attempts   = sum(1 for e in events if e[2] == 'login_attempt')

    # ---- Step 2: Normalize each number to 0-1 ----
    n_duration  = normalize(duration_secs,   MAX_DURATION)
    n_diversity = normalize(unique_commands,  MAX_DIVERSITY)
    n_breadth   = normalize(service_count,    MAX_SERVICES)
    n_exploit   = normalize(exploit_count,    MAX_EXPLOITS)
    n_transfers = normalize(file_transfers,   MAX_TRANSFERS)
    n_logins    = normalize(login_attempts,   MAX_LOGINS)

    # ---- Step 3: Weighted sum → multiply by 10 for final score ----
    raw_score = (
        WEIGHTS["session_duration"]  * n_duration  +
        WEIGHTS["command_diversity"] * n_diversity +
        WEIGHTS["service_breadth"]   * n_breadth   +
        WEIGHTS["exploitation"]      * n_exploit   +
        WEIGHTS["file_transfers"]    * n_transfers +
        WEIGHTS["login_attempts"]    * n_logins
    )
    aei_score = round(raw_score * 10, 2)

    # ---- Step 4: Classify into Low / Medium / High ----
    if aei_score < 3.0:
        aei_level = "Low"
    elif aei_score < 6.0:
        aei_level = "Medium"
    else:
        aei_level = "High"

    return {
        "session_id":      session_id,
        "source_ip":       events[0][4],
        "source_country":  events[0][5],
        "first_seen":      first_time,
        "last_seen":       last_time,
        "total_events":    total_events,
        "services_hit":    ",".join(sorted(services_hit)),
        "duration_secs":   duration_secs,
        "unique_commands": unique_commands,
        "exploit_count":   exploit_count,
        "file_transfers":  file_transfers,
        "login_attempts":  login_attempts,
        "aei_score":       aei_score,
        "aei_level":       aei_level,
    }


def save_aei_result(cursor, conn, result):
    """Write computed AEI result into session_scores table."""
    cursor.execute("""
        INSERT INTO session_scores
            (session_id, source_ip, first_seen, last_seen,
             aei_score, aei_level, total_events, services_hit)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            aei_score    = VALUES(aei_score),
            aei_level    = VALUES(aei_level),
            total_events = VALUES(total_events),
            services_hit = VALUES(services_hit),
            computed_at  = CURRENT_TIMESTAMP(3)
    """, (
        result["session_id"],
        result["source_ip"],
        result["first_seen"],
        result["last_seen"],
        result["aei_score"],
        result["aei_level"],
        result["total_events"],
        result["services_hit"],
    ))
    conn.commit()


def run_aei_engine():
    """Main function: score all sessions and save results."""
    conn   = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    print("=" * 58)
    print("   TrapForge AEI Engine — Attack Engagement Index")
    print("=" * 58)

    sessions = get_all_sessions(cursor)
    print(f"\nSessions found: {len(sessions)}\n")

    for session_id in sessions:
        result = calculate_aei(session_id, cursor)
        if result:
            save_aei_result(cursor, conn, result)
            print(f"Session  : {result['session_id']}")
            print(f"  IP           : {result['source_ip']} ({result['source_country']})")
            print(f"  Duration     : {result['duration_secs']}s")
            print(f"  Services hit : {result['services_hit']}")
            print(f"  Unique cmds  : {result['unique_commands']}")
            print(f"  Exploits     : {result['exploit_count']}")
            print(f"  Transfers    : {result['file_transfers']}")
            print(f"  Logins tried : {result['login_attempts']}")
            print(f"  *** AEI Score : {result['aei_score']} / 10 ***")
            print(f"  *** AEI Level : {result['aei_level']} ***")
            print("-" * 58)

    print("\nAll scores saved to session_scores table.")
    cursor.close()
    conn.close()


if __name__ == "__main__":
    run_aei_engine()