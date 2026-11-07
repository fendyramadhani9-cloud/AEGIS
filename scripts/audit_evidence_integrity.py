"""
Audit Evidence Integrity and Referential Links in Supabase.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")
sys.path.insert(0, str(ROOT_DIR))

from aegis_backend.repository import SupabaseRepository

repo = SupabaseRepository()

print("=" * 65)
print(" AUDIT: EVIDENCE INTEGRITY & REFERENTIAL VALIDATION")
print("=" * 65)

# 1. Fetch all alerts
alerts_res = repo.client.table("alerts").select("*").execute()
alerts = alerts_res.data or []
print(f"[*] Total Alerts in Supabase: {len(alerts)}")

# 2. Fetch all alert_evidence
ev_res = repo.client.table("alert_evidence").select("*").execute()
all_ev = ev_res.data or []
print(f"[*] Total Evidence Links in Supabase: {len(all_ev)}")

# Map evidence by alert_id
ev_by_alert = {}
for e in all_ev:
    ev_by_alert.setdefault(e["alert_id"], []).append(e)

# 3. Fetch referenced telemetry_events to verify existence and host match
all_ev_event_ids = list({e["event_id"] for e in all_ev})
telemetry_res = repo.client.table("telemetry_events").select("id, host_id, event_type, event_timestamp").in_("id", all_ev_event_ids).execute()
telemetry_map = {t["id"]: t for t in (telemetry_res.data or [])}
print(f"[*] Referenced Telemetry Events Found in DB: {len(telemetry_map)} / {len(all_ev_event_ids)}")

audit_matrix = []

for a in alerts:
    a_id = a["id"]
    rule = a["rule_id"]
    h_id = a["host_id"]
    sev = a["severity"]
    
    links = ev_by_alert.get(a_id, [])
    has_evidence = len(links) > 0
    
    # Check all events exist and host matches
    all_events_exist = True
    hosts_match = True
    has_trigger = False
    
    for l in links:
        ev_id = l["event_id"]
        role = l["citation_role"]
        if role == "trigger":
            has_trigger = True
            
        t_event = telemetry_map.get(ev_id)
        if not t_event:
            all_events_exist = False
        else:
            if t_event.get("host_id") != h_id:
                hosts_match = False

    passed = has_evidence and all_events_exist and hosts_match and has_trigger
    audit_matrix.append({
        "alert_id": a_id,
        "rule_id": rule,
        "severity": sev,
        "evidence_count": len(links),
        "has_trigger": has_trigger,
        "all_events_exist": all_events_exist,
        "host_match": hosts_match,
        "status": "PASS" if passed else "FAIL"
    })
    
    print(f"\n[-] Alert {a_id} ({rule} | {sev}):")
    print(f"    Evidence Count: {len(links)} | Has Trigger: {has_trigger} | Events in DB: {all_events_exist} | Host Match: {hosts_match} -> {'PASS' if passed else 'FAIL'}")
    for l in links:
        t_event = telemetry_map.get(l['event_id'], {})
        print(f"    -> [Role: {l['citation_role']:10}] {l['event_id']} (Type: {t_event.get('event_type')}, Host: {t_event.get('host_id')})")

print("\n" + "=" * 65)
all_pass = all(m["status"] == "PASS" for m in audit_matrix)
print(f"EVIDENCE INTEGRITY AUDIT: {'ALL PASS (100%)' if all_pass else 'FAILURES DETECTED'}")
print("=" * 65)

