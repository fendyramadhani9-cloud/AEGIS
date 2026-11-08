# AEGIS Incident Investigation User Guide

## 1. Navigating the Incidents Screen
From the primary navigation menu, click **Incidents** (Flame icon) to open the incident monitoring overview.

### Features
- **Summary KPI Cards:** Instantly view Total Correlated Incidents, Active Investigations (Open + Investigating), Critical/High Risk Incidents, and Average Risk Score.
- **AI Health Status Banner:** Displays live AI provider connectivity (Google Gemini `gemini-3.5-flash-lite` or Offline Mock Fallback) and database storage backend.
- **Correlate Alerts Action:** Click **Correlate Alerts** to scan alerts across monitored hosts and automatically cluster multi-stage attack chains.
- **Status & Risk Filters:** Filter incidents by status (`Open`, `Investigating`, `Mitigated`, `Resolved`) or risk level (`Critical`, `High`, `Medium`, `Low`).
- **Search Bar:** Real-time search across incident IDs, hostnames, scenarios, and descriptions.

## 2. Investigating an Incident
Click on any incident card to view its comprehensive investigation dossier:

### A. Incident Hero & Lifecycle Controls
- **Risk Score Meter:** Displays composite risk score (e.g. 88/100 CRITICAL) and breakdown of scoring factors (Base severity, Multi-alert clustering, Kill chain sequence, Posture penalty).
- **Status Transition Modal:** Click **Update Status** to transition lifecycle states with audit-logged analyst notes.

### B. AI Incident Investigation Report
- **Executive Summary:** High-level narrative summarizing attacker intent and progress.
- **Threat Classification:** Explicit categorization (e.g., *Privilege Escalation via SSH Credential Stuffing*).
- **Grounded Key Observations:** Verified observations with clickable evidence citations (`#EVT-...`). Clicking an evidence citation jumps directly to the corresponding raw telemetry log line in the evidence section.
- **Prioritized Recommendations:** Actionable steps prioritized 1, 2, 3 with explicit security rationales.
- **Anti-Hallucination Limits:** Transparent list of unobserved telemetry variables (e.g., process lineage outside auditd).

### C. Correlated Alerts & Grounded Evidence
- Review each alert linked to this incident with rule ID, severity, and reason.
- Review raw normalized telemetry logs providing concrete ground-truth verification.

