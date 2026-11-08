import sqlite3
import json
import sys
import os

db_path = sys.argv[1] if len(sys.argv) > 1 else "data/aegis_incidents.db"
out_path = sys.argv[2] if len(sys.argv) > 2 else "data/vm_fenn_golden_dataset.json"

conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

tables = [
    "security_check_runs",
    "security_findings",
    "incidents",
    "incident_alerts",
    "incident_risk_factors",
    "incident_timeline",
    "ai_analyses",
    "incident_status_history",
]

dataset = {}
total = 0

for t in tables:
    cur.execute(f"SELECT * FROM \"{t}\";")
    rows = [dict(r) for r in cur.fetchall()]
    dataset[t] = rows
    total += len(rows)
    print(f"Exported {len(rows):4d} rows from {t}")

dataset["_meta"] = {
    "total_records": total,
    "source_db": db_path,
}

os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(dataset, f, indent=2)

print(f"\nSuccessfully exported {total} operational records to {out_path}")
conn.close()

