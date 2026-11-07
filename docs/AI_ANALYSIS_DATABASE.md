# AEGIS Incident Investigation Database Schema & Migration 004

## 1. Migration Specification
Database migration `004_incident_investigation.sql` introduces relational tables for incidents, alert junctions, timelines, AI analyses, and lifecycle history.

```mermaid
erDiagram
    hosts ||--o{ incidents : contains
    alerts ||--|| incidents : "primary alert"
    incidents ||--o{ incident_alerts : groups
    alerts ||--o{ incident_alerts : "member alert"
    incidents ||--o{ incident_timeline : logs
    incidents ||--o{ ai_analyses : investigates
    incidents ||--o{ incident_status_history : audits

    incidents {
        text id PK
        text host_id FK
        text alert_id FK
        text primary_alert_id
        text title
        text severity
        text status
        integer risk_score
        text risk_level
        jsonb risk_factors
        text attack_scenario
        timestamptz detected_at
        timestamptz resolved_at
    }

    ai_analyses {
        text analysis_id PK
        text incident_id FK
        text host_id FK
        text analysis_status
        text threat_classification
        text executive_summary
        text attack_scenario
        jsonb observed_behaviors
        jsonb timeline
        text risk_level
        integer risk_score
        text confidence_level
        text[] supporting_evidence
        text[] unknowns
        jsonb recommended_actions
        text provider
        text model
    }
```

## 2. Integrity Constraints & Rules
1. **Host Foreign Key:** Every incident must reference an existing host in `public.hosts(id)`.
2. **Alert Severity Match Trigger:** Maintained compatibility with `trg_incidents_severity_match` from Migration 001 by retaining `alert_id` matching primary alert severity.
3. **Status Check Constraint:** `status IN ('open', 'new', 'investigating', 'mitigated', 'confirmed', 'resolved', 'closed', 'false_positive')`.
4. **Cascade Deletion:** Deleting an incident cleanly cascades to junction tables, timelines, and status history, but NEVER deletes original alerts or telemetry events.

## 3. Verification & Safe Rollback Scripts
- Verification: `supabase/verify_migration_004.sql`
- Rollback: `supabase/rollback_migration_004.sql`
  The rollback drops `incident_status_history`, `ai_analyses`, `incident_timeline`, `incident_alerts`, and `incidents` in reverse dependency order, leaving historical alerts and baseline tables completely untouched.
- Tested locally via PostgreSQL engine (PGlite in `tests/verify_incident_migration.cjs`).
