import mysql.connector
from config import DB_CONFIG
from aei_calculator import run_aei_engine
from ajm_mapper import run_ajm_engine
from drs_scorer import run_drs_engine

# ================================================================
# TrapForge Part 3 — AEI Engine Master Runner
# Runs all three components in correct order:
#   1. AEI Calculator  — scores attacker engagement
#   2. AJM Mapper      — reconstructs attack journey
#   3. DRS Scorer      — evaluates deception effectiveness
# ================================================================

def print_final_summary():
    """Print combined AEI + DRS summary table from the database."""
    conn   = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT session_id, source_ip, aei_score, aei_level,
               drs_score, services_hit, total_events
        FROM session_scores
        ORDER BY aei_score DESC
    """)
    rows = cursor.fetchall()

    print("\n")
    print("=" * 78)
    print("   FINAL COMBINED REPORT — AEI + DRS per Session")
    print("=" * 78)
    print(f"{'Session':<12} {'IP':<18} {'AEI':>5} {'Level':<8} "
          f"{'DRS':>5} {'Services':<18} {'Events'}")
    print("-" * 78)
    for row in rows:
        session, ip, aei, aei_lvl, drs, services, events = row
        print(f"{session:<12} {ip:<18} {aei:>5} {aei_lvl:<8} "
              f"{drs:>5} {services:<18} {events}")
    print("=" * 78)
    print("\nMost dangerous attacker:",
          rows[0][1] if rows else "None",
          f"(AEI={rows[0][2]}, DRS={rows[0][4]})" if rows else "")

    cursor.close()
    conn.close()


if __name__ == "__main__":
    print("\n")
    print("*" * 58)
    print("*   TrapForge — AEI Engine Starting                *")
    print("*   Components: AEI + AJM + DRS                    *")
    print("*" * 58)

    print("\n--- STEP 1: Computing AEI Scores ---")
    run_aei_engine()

    print("\n--- STEP 2: Mapping Attack Journeys ---")
    run_ajm_engine()

    print("\n--- STEP 3: Computing DRS Scores ---")
    run_drs_engine()

    print("\n--- STEP 4: Final Report ---")
    print_final_summary()

    print("\nEngine run complete. All results saved to database.")