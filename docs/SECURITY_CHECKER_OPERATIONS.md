# AEGIS Security Checker: Operational Runbook

## 1. Routine Auditing Cadence

Security audits can be performed in two modes:
1. **Periodic Automation**: Via `cron` or `systemd.timer` once every 6 hours or daily at midnight.
2. **On-Demand**: Triggered via the Web Dashboard or CLI upon system deployment or configuration updates.

---

## 2. Setting Up Automated Periodic Audits

### Using Systemd Timer (Recommended for Ubuntu LTS)

1. Create `/etc/systemd/system/aegis-security-checker.service`:
   ```ini
   [Unit]
   Description=AEGIS Security Checker Scheduled Run
   After=network.target aegis-backend.service

   [Service]
   Type=oneshot
   User=ubuntu
   WorkingDirectory=/home/ubuntu/aegis
   ExecStart=/home/ubuntu/aegis/.venv/bin/python3 -m aegis_agent.security_checker --submit
   StandardOutput=journal
   StandardError=journal
   ```

2. Create `/etc/systemd/system/aegis-security-checker.timer`:
   ```ini
   [Unit]
   Description=Run AEGIS Security Checker every 6 hours

   [Timer]
   OnBootSec=5min
   OnUnitActiveSec=6h
   Persistent=true

   [Install]
   WantedBy=timers.target
   ```

3. Enable and start timer:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now aegis-security-checker.timer
   ```

---

## 3. Monitoring & Health Verification

1. Verify backend health endpoint:
   ```bash
   curl -s http://127.0.0.1:8000/api/security-checker/health
   ```
2. Verify latest host summary:
   ```bash
   curl -s http://127.0.0.1:8000/api/security-checker/summary?host_id=host-fenn-ubuntu
   ```
3. Inspect agent execution in journal:
   ```bash
   journalctl -u aegis-security-checker.service -n 50 --no-pager
   ```

---

## 4. Remediation Procedure Guidelines

When a check reports `FAIL`:
1. Navigate to `https://aegis.diazz.web.id/detections?tab=checks&status=fail`.
2. Click on the finding to open the Finding Detail screen.
3. Review **Observed Configuration vs. Standard** and **Security Impact**.
4. Copy the recommended bash command from **Remediation Guidance**.
5. Log into the affected host via SSH and run the remediation commands.
6. Trigger a new check run from the dashboard or CLI:
   ```bash
   python3 -m aegis_agent.security_checker --submit
   ```
7. Refresh the dashboard to verify the finding transitions from `FAIL` to `PASS`.
