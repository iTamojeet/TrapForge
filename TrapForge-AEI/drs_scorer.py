import mysql.connector
from config import DB_CONFIG

# ================================================================
# DRS — Deception Resilience Score
# ================================================================
# DRS measures how well our FAKE environment fooled the attacker.
# It answers: "Did the attacker believe our honeypot was real?"
#
# High DRS (7-10): Attacker was fully convinced. Stayed long,
#                  moved across services, attempted destruction.
# Medium DRS (4-7): Partially convinced. Some exploration.
# Low DRS  (0-4) : Quickly left. Likely detected it was a trap.
#
# 5 sub-metrics (all normalized 0-1, weighted sum x 10):
#   1. Persistence     — kept trying after failures
#   2. Service Spread  — moved to multiple services
#   3. Phase Diversity — went through multiple attack phases
#   4. Destructive Act — tried to destroy/damage things
#   5. Time Investment — total time spent in our environment
# ================================================================

DRS_WEIGHTS = {
    "persistence":     0.20,
    "service_spread":  0.25,
    "phase_diversity": 0.20,
    "destructive_act": 0.25,
    "time_investment": 0.10,
}

MAX_DURATION    = 300  # seconds
MAX_SERVICES    = 4
MAX_PHASES      = 6    # total distinct phases possible
DESTRUCTIVE_KEYWORDS = [
    "DROP", "DELETE FROM", "TRUNCATE", "rm -rf",
    "mkfs", "format", "shutdown", "reboot", "> /dev/sda"
]


def normalize(value, max_value):
    if max_value == 0:
        return 0.0
    return min(value / max_value, 1.0)


def get_session_data_for_drs(cursor, session_id):
    """Fetch events + journey phases for one session."""
    # Get raw events from unified_logs
    cursor.execute("""
        SELECT timestamp, service, event_type, raw_payload
        FROM unified_logs
        WHERE session_id = %s
        ORDER BY timestamp ASC
    """, (session_id,))
    events = cursor.fetchall()

    # Get mapped phases from attack_journeys
    cursor.execute("""
        SELECT DISTINCT phase
        FROM attack_journeys
        WHERE session_id = %s
    """, (session_id,))
    phases = [row[0] for row in cursor.fetchall()]

    return events, phases


def check_destructive(events):
    """
    Returns 1 if any destructive command was attempted, else 0.
    Destructive action = strong signal attacker believed env was real.
    """
    for event in events:
        payload = (event[3] or "").upper()
        for keyword in DESTRUCTIVE_KEYWORDS:
            if keyword.upper() in payload:
                return 1
    return 0


def calculate_drs(session_id, cursor):
    """Compute DRS for one session. Returns result dict."""
    events, phases = get_session_data_for_drs(cursor, session_id)
    if not events:
        return None

    source_ip = None
    cursor.execute(
        "SELECT source_ip FROM unified_logs "
        "WHERE session_id = %s LIMIT 1", (session_id,)
    )
    row = cursor.fetchone()
    if row:
        source_ip = row[0]

    # ---- Sub-metric 1: Persistence ----
    # Count login attempts. More attempts = attacker kept trying
    # = they believed a real system was behind the login.
    login_count   = sum(1 for e in events if e[2] == "login_attempt")
    total_events  = len(events)
    # Persistence = ratio of events after first one (they stayed)
    persistence   = (total_events - 1) / max(total_events, 1)

    # ---- Sub-metric 2: Service Spread ----
    services_hit  = len(set(e[1] for e in events))

    # ---- Sub-metric 3: Phase Diversity ----
    # More phases covered = deeper belief in the environment
    phase_count   = len(set(phases)) if phases else 1

    # ---- Sub-metric 4: Destructive Action ----
    # Binary: 1 = tried to destroy something (fully convinced it was real)
    destructive   = check_destructive(events)

    # ---- Sub-metric 5: Time Investment ----
    first_time    = events[0][0]
    last_time     = events[-1][0]
    duration_secs = (last_time - first_time).total_seconds()

    # ---- Normalize all to 0-1 ----
    n_persistence = normalize(persistence,    1.0)
    n_spread      = normalize(services_hit,   MAX_SERVICES)
    n_phases      = normalize(phase_count,    MAX_PHASES)
    n_destructive = float(destructive)       # already 0 or 1
    n_time        = normalize(duration_secs, MAX_DURATION)

    # ---- Weighted sum → scale to 10 ----
    raw_score = (
        DRS_WEIGHTS["persistence"]     * n_persistence +
        DRS_WEIGHTS["service_spread"]  * n_spread      +
        DRS_WEIGHTS["phase_diversity"] * n_phases      +
        DRS_WEIGHTS["destructive_act"] * n_destructive +
        DRS_WEIGHTS["time_investment"] * n_time
    )
    drs_score = round(raw_score * 10, 2)

    # ---- Classify ----
    if drs_score < 4.0:
        drs_level = "Low"
    elif drs_score < 7.0:
        drs_level = "Medium"
    else:
        drs_level = "High"

    return {
        "session_id":    session_id,
        "source_ip":     source_ip,
        "persistence":   round(n_persistence, 2),
        "service_spread":services_hit,
        "phase_count":   phase_count,
        "destructive":   destructive,
        "duration_secs": duration_secs,
        "drs_score":     drs_score,
        "drs_level":     drs_level,
    }


def save_drs_result(cursor, conn, result):
    """Update session_scores table with the DRS score."""
    cursor.execute("""
        UPDATE session_scores
        SET drs_score = %s
        WHERE session_id = %s
    """, (result["drs_score"], result["session_id"]))
    conn.commit()


def run_drs_engine():
    """Main: compute DRS for all sessions."""
    conn   = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    print("=" * 58)
    print("   TrapForge DRS Engine — Deception Resilience Score")
    print("=" * 58)

    cursor.execute(
        "SELECT DISTINCT session_id FROM unified_logs "
        "WHERE session_id IS NOT NULL"
    )
    sessions = [row[0] for row in cursor.fetchall()]
    print(f"\nSessions found: {len(sessions)}\n")

    for session_id in sessions:
        result = calculate_drs(session_id, cursor)
        if result:
            save_drs_result(cursor, conn, result)
            print(f"Session  : {result['session_id']}")
            print(f"  IP             : {result['source_ip']}")
            print(f"  Persistence    : {result['persistence']}")
            print(f"  Services hit   : {result['service_spread']}")
            print(f"  Phases covered : {result['phase_count']}")
            print(f"  Destructive act: {'YES' if result['destructive'] else 'NO'}")
            print(f"  Duration       : {result['duration_secs']}s")
            print(f"  *** DRS Score  : {result['drs_score']} / 10 ***")
            print(f"  *** DRS Level  : {result['drs_level']} ***")
            print("-" * 58)

    print("\nAll DRS scores saved to session_scores table.")
    cursor.close()
    conn.close()


if __name__ == "__main__":
    run_drs_engine()