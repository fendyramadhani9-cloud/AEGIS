import sqlite3
import json
import os
import sys

def audit_db(db_path, label):
    print(f"\n==================================================")
    print(f"AUDITING {label}: {db_path}")
    print(f"==================================================")
    if not os.path.exists(db_path):
        print(f"ERROR: Database file does not exist: {db_path}")
        return None

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cur = conn.cursor()

    cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
    tables = [r[0] for r in cur.fetchall() if not r[0].startswith('sqlite_')]

    stats = {
        "label": label,
        "db_path": db_path,
        "tables": {},
        "operational_records": 0,
        "meta_records": 0,
        "total_records": 0,
    }

    operational_tables = [
        "security_check_runs",
        "security_findings",
        "incidents",
        "incident_alerts",
        "incident_risk_factors",
        "incident_timeline",
        "ai_analyses",
        "incident_status_history",
    ]

    for t in tables:
        cur.execute(f"SELECT count(*) FROM \"{t}\";")
        cnt = cur.fetchone()[0]
        stats["tables"][t] = cnt
        stats["total_records"] += cnt
        if t in operational_tables:
            stats["operational_records"] += cnt
        else:
            stats["meta_records"] += cnt
        print(f"  {t:30s}: {cnt:4d}")

    print(f"\n  Operational Records Sum : {stats['operational_records']}")
    print(f"  Metadata Records Sum    : {stats['meta_records']}")
    print(f"  Total Rows Sum          : {stats['total_records']}")

    # Distinct IDs check
    if "incidents" in tables:
        cur.execute("SELECT id, status, risk_score FROM incidents ORDER BY id;")
        stats["incident_ids"] = [dict(zip(["id", "status", "risk_score"], r)) for r in cur.fetchall()]

    conn.close()
    return stats

if __name__ == "__main__":
    local_db = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "aegis_incidents.db")
    workstation_stats = audit_db(local_db, "WORKSTATION SQLITE")

    # If running on VM or path supplied
    target_path = sys.argv[1] if len(sys.argv) > 1 else local_db
    if target_path != local_db:
        target_stats = audit_db(target_path, "TARGET SQLITE")
