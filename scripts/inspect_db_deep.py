"""
Deep Inspection Script for SQLite and Supabase compatibility.
Examines data structures, constraints, formats, and relational mappings.
"""

import os
import sys
import json
import sqlite3
from typing import Dict, Any

db_path = os.getenv("AEGIS_SQLITE_PATH", "data/aegis_incidents.db")
if not os.path.exists(db_path):
    print(f"Error: {db_path} not found.")
    sys.exit(1)

conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

print("======================================================================")
print(f"DEEP SQLITE INSPECTION: {os.path.abspath(db_path)}")
print("======================================================================")

cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;")
tables = [r[0] for r in cur.fetchall()]

stats = {}

for tbl in tables:
    cur.execute(f"SELECT COUNT(*) FROM {tbl};")
    cnt = cur.fetchone()[0]

    cur.execute(f"PRAGMA table_info({tbl});")
    cols = [dict(c) for c in cur.fetchall()]

    cur.execute(f"PRAGMA foreign_key_list({tbl});")
    fks = [dict(f) for f in cur.fetchall()]

    cur.execute(f"PRAGMA index_list({tbl});")
    indexes = [dict(i) for i in cur.fetchall()]

    # Sample row
    sample = None
    if cnt > 0:
        cur.execute(f"SELECT * FROM {tbl} LIMIT 1;")
        sample = dict(cur.fetchone())

    stats[tbl] = {
        "count": cnt,
        "columns": cols,
        "foreign_keys": fks,
        "indexes": indexes,
        "sample": sample,
    }
    print(f"\n[+] Table: {tbl} | Rows: {cnt}")
    print(f"    Columns ({len(cols)}): {', '.join([c['name'] + ':' + c['type'] for c in cols])}")
    if fks:
        print(f"    FKs: {', '.join([f['from'] + ' -> ' + f['table'] + '(' + f['to'] + ')' for f in fks])}")
    if indexes:
        print(f"    Indexes: {', '.join([i['name'] + (' [UNIQUE]' if i['unique'] else '') for i in indexes])}")

conn.close()

with open("sqlite_deep_inspection.json", "w", encoding="utf-8") as f:
    json.dump(stats, f, indent=2)

print("\n[+] Full deep inspection written to sqlite_deep_inspection.json")
