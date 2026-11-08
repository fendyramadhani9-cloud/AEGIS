# AEGIS Incident Investigation Operations & Production Runbook

## 1. Systemd Service Management on VM fenn
The backend runs as a managed systemd service on Ubuntu VM `fenn`:

```bash
# Check backend status
sudo systemctl status aegis-backend

# Restart backend service
sudo systemctl restart aegis-backend

# View real-time service logs
sudo journalctl -u aegis-backend -f -n 100
```

## 2. Monitoring AI Health & Latency
Administrators can check provider status via curl or dashboard:
```bash
# Internal VM check
curl -s http://127.0.0.1:8000/api/analysis/health | jq .

# Public domain check
curl -s https://aegis.diazz.web.id/api/analysis/health | jq .
```
Expected output:
```json
{
  "status": "ok",
  "provider": "gemini",
  "model": "gemini-3.5-flash-lite",
  "configured": true,
  "reachable": true,
  "message": "Connected to Google Gemini API (model: gemini-3.5-flash-lite)."
}
```

## 3. Incident Triage Workflow & SLA
1. **Detection & Correlation:** When an attack chain occurs, the rules engine detects individual events and the correlator creates an incident within 30 minutes.
2. **AI Analysis Trigger:** SOC analysts or automated pipelines trigger `POST /api/incidents/{id}/analyze`.
3. **Analyst Review:** Review executive summary, attack narrative, and grounded evidence.
4. **Containment:** Apply recommended actions (e.g., firewall block `ufw deny from <IP>`).
5. **Status Update:** Update incident lifecycle status to `mitigated` and then `resolved`.

