# AEGIS Incident Investigation & AI Security Analysis API Reference

All endpoints are served under `/api` by the FastAPI gateway.

## 1. Endpoints Summary
| Method | Path | Summary | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/analysis/health` | AI Provider Health | Checks connectivity, model configuration, and key availability. |
| `GET` | `/api/incidents/summary` | Incident Summary | Returns metrics on open, investigating, resolved, and critical incidents. |
| `GET` | `/api/incidents` | List Incidents | Paginated, filtered list of correlated incidents (`status`, `severity`, `host_id`). |
| `POST` | `/api/incidents` | Correlate Alerts | Triggers automated clustering of unassigned alerts into incidents. |
| `GET` | `/api/incidents/{id}` | Incident Detail | Full incident details with primary alert, correlated alerts, and AI analysis. |
| `PATCH` | `/api/incidents/{id}/status` | Update Status | Transitions lifecycle state (`open` $\to$ `investigating` $\to$ `mitigated` $\to$ `resolved`). |
| `GET` | `/api/incidents/{id}/timeline` | Incident Timeline | Unified chronological activity stream for the incident. |
| `GET` | `/api/incidents/{id}/evidence` | Grounded Evidence | Returns concrete normalized events supporting the incident. |
| `POST` | `/api/incidents/{id}/analyze` | Trigger AI Investigation | Synthesizes forensic context and runs AI analysis (Gemini/Mock). |
| `GET` | `/api/incidents/{id}/analysis` | Get AI Analysis | Retrieves the latest persisted AI analysis report for an incident. |
| `GET` | `/api/alerts/{id}/analysis` | Alert AI Analysis | Retrieves or triggers AI analysis scoped to an individual alert. |
| `GET` | `/api/analysis/summary` | Analysis Summary Alias | Alias endpoint for backward compatibility with monitoring systems. |

## 2. Selected Payloads & Schemas

### `POST /api/incidents/{id}/analyze` Request
```json
{
  "force": true
}
```

### `AIAnalysisItem` Response Object
```json
{
  "analysis_id": "ANL-INC-host-fenn-ubuntu-771f6d1f7346-1731000000",
  "incident_id": "INC-host-fenn-ubuntu-771f6d1f7346",
  "host_id": "host-fenn-ubuntu",
  "analysis_status": "completed",
  "threat_classification": "Multi-Stage Attack Chain: Brute-Force to Privileged Root Shell",
  "executive_summary": "Adversary successfully conducted an automated brute-force campaign against SSH, authenticated as user 'ubuntu', and escalated privileges via sudo.",
  "attack_scenario": "Initial failed logins from 192.168.1.100 followed by valid credential presentation and sudo root command.",
  "observed_behaviors": [
    {
      "evidence_id": "EVT-host-fenn-ubuntu-AUTH-FAIL-89651",
      "fact": "Failed password for invalid user admin",
      "timestamp": "2026-11-07T16:05:00Z"
    }
  ],
  "supporting_evidence": ["EVT-host-fenn-ubuntu-AUTH-FAIL-89651"],
  "unknowns": ["Whether persistence was established via cron or systemd."],
  "recommended_actions": [
    {
      "priority": "immediate",
      "action": "Revoke active SSH sessions and change user ubuntu password."
    }
  ],
  "risk_score": 85,
  "risk_level": "critical",
  "provider": "gemini",
  "model": "gemini-3.5-flash-lite"
}
```
