import sqlite3
import json
import sys
import os

db_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "aegis_incidents.db")

print(f"Auditing SQLite Database at: {db_path}")
conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
cur = conn.cursor()

cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;")
tables = [r[0] for r in cur.fetchall()]

table_counts = {}
total_records = 0

for t in tables:
    cur.execute(f"SELECT count(*) FROM \"{t}\";")
    cnt = cur.fetchone()[0]
    table_counts[t] = cnt
    total_records += cnt

print("\n--- EXACT ROW COUNTS PER TABLE ---")
for t, c in sorted(table_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"  {t:30s}: {c:4d}")

print(f"\nTOTAL ROWS SUM ACROSS ALL TABLES: {total_records}")

# Check foreign key relations
print("\n--- FOREIGN KEY INTEGRITY AUDIT ---")
# 1. incident_alerts -> incidents
cur.execute("SELECT count(*) FROM incident_alerts WHERE incident_id NOT IN (SELECT id FROM incidents);")
orphaned_ia_inc = cur.fetchone()[0]
print(f"  Orphaned incident_alerts (missing parent incident): {orphaned_ia_inc}")

# 2. incident_risk_factors -> incidents
cur.execute("SELECT count(*) FROM incident_risk_factors WHERE incident_id NOT IN (SELECT id FROM incidents);")
orphaned_irf_inc = cur.fetchone()[0]
print(f"  Orphaned incident_risk_factors (missing parent incident): {orphaned_irf_inc}")

# 3. incident_timeline -> incidents
cur.execute("SELECT count(*) FROM incident_timeline WHERE incident_id NOT IN (SELECT id FROM incidents);")
orphaned_it_inc = cur.fetchone()[0]
print(f"  Orphaned incident_timeline (missing parent incident): {orphaned_it_inc}")

# 4. ai_analyses -> incidents
cur.execute("SELECT count(*) FROM ai_analyses WHERE incident_id NOT IN (SELECT id FROM incidents);")
orphaned_ai_inc = cur.fetchone()[0]
print(f"  Orphaned ai_analyses (missing parent incident): {orphaned_ai_inc}")

# 5. incident_status_history -> incidents
cur.execute("SELECT count(*) FROM incident_status_history WHERE incident_id NOT IN (SELECT id FROM incidents);")
orphaned_sh_inc = cur.fetchone()[0]
print(f"  Orphaned incident_status_history (missing parent incident): {orphaned_sh_inc}")

# 6. security_findings -> security_check_runs
cur.execute("SELECT count(*) FROM security_findings WHERE run_id NOT IN (SELECT id FROM security_check_runs);")
orphaned_sf_run = cur.fetchone()[0]
print(f"  Orphaned security_findings (missing parent run): {orphaned_sf_run}")

# Summary output as JSON
summary_out = {
    "db_path": db_path,
    "table_counts": table_counts,
    "total_records": total_records,
    "orphaned_records": {
        "incident_alerts_missing_incident": orphaned_ia_inc,
        "incident_risk_factors_missing_incident": orphaned_irf_inc,
        "incident_timeline_missing_incident": orphaned_it_inc,
        "ai_analyses_missing_incident": orphaned_ai_inc,
        "incident_status_history_missing_incident": orphaned_sh_inc,
        "security_findings_missing_run": orphaned_sf_run,
    }
}

conn.close()

with open("audit_sqlite_reconciliation.json", "w", encoding="utf-8") as f:
    json.dump(summary_out, f, indent=2)

print("\nWrote summary to audit_sqlite_reconciliation.json")

