# AEGIS Security Operations Runbook

**Document Version:** 1.0.0  
**Target Audience:** Security Operations Engineers, Sysadmins, Site Reliability Engineers (SRE)  
**System:** AEGIS (AI-Powered Linux Security Monitoring & Incident Response)  
**Classification:** Internal Operational Security Runbook

---

## 1. Daily Security Health Checklist & Verification

Run these verification commands from an administrative terminal to confirm operational integrity without disrupting services.

### 1.1 Backend & Database Readiness Check
```bash
# Check FastAPI service readiness & Supabase Cloud SSoT state
curl -s http://127.0.0.1/api/health/ready | jq .

# Expected Output:
# {
#   "status": "ready",
#   "database_mode": "cloud_ssot",
#   "cloud_connected": true,
#   "mirror_queue_depth": 0
# }
```

### 1.2 Systemd Daemon Status & Resource Bounds
```bash
# Verify systemd service status for backend and collector
systemctl status aegis-backend aegis-collector --no-pager

# Confirm process memory limits are respected (Collector < 100MB)
systemd-cgtop -n 1 | grep aegis
```

### 1.3 Telemetry Ingestion Activity
```bash
# Verify real-time event flow in collector journal
journalctl -u aegis-collector.service -n 20 --no-pager
```

---

## 2. Fail-Closed Outage & Degradation Response Runbook

When Supabase Cloud experiences connectivity loss or latency spikes, AEGIS enters the fail-closed protection state to prevent split-brain database corruption.

### 2.1 Symptom Identification
- Backend logs report: `Cloud database mutation failed: [PostgrestError / Timeout]`.
- API endpoints return: `HTTP 503 Service Unavailable` with message: `"Database mutations temporarily suspended (fail-closed)"`.
- Dashboard alerts: Status shows `DEGRADED` or `FAILOVER_RECOVERY`.

### 2.2 Operational Action Plan
1. **DO NOT switch backend back to SQLite manually:**  
   Switching back to SQLite creates divergent split-brain records that will overwrite or corrupt SSoT data upon reconnection.
2. **Verify Network Connectivity to Supabase Cloud:**
   ```bash
   # Test HTTPS connectivity and DNS resolution
   curl -I https://hiwfbmwgnpnwaszltqwb.supabase.co/rest/v1/
   ```
3. **Inspect Active State Machine:**
   ```bash
   curl -s http://127.0.0.1/api/database/state | jq .
   ```
4. **Monitor Automatic Recovery:**  
   The backend state machine continuously probes Supabase health every 15 seconds. Once 3 consecutive healthy pings succeed, the state machine automatically transitions back to `CLOUD_SSoT`, and the fail-closed mutation gate re-opens automatically without requiring process restarts.
5. **Verify Catch-Up Watermark Parity:**
   ```bash
   journalctl -u aegis-backend.service -n 50 --no-pager | grep -i "catch-up"
   ```

---

## 3. Credential & Secret Rotation Procedures

To adhere to security best practices, rotate credentials every 90 days or immediately following any suspected operational compromise.

### 3.1 Supabase Service Role Key Rotation
1. Log in to the Supabase Cloud Management Dashboard: `https://supabase.com/dashboard/project/hiwfbmwgnpnwaszltqwb/settings/api`.
2. Generate a new `service_role` secret key.
3. Update `/home/ubuntu/aegis/.env` on the host:
   ```bash
   nano /home/ubuntu/aegis/.env
   # Replace SUPABASE_SERVICE_KEY="<new_key>"
   ```
4. Ensure file permissions remain restricted:
   ```bash
   chmod 0600 /home/ubuntu/aegis/.env
   ```
5. Gracefully restart the backend gateway:
   ```bash
   sudo systemctl restart aegis-backend.service
   ```
6. Revoke the old key in Supabase Dashboard after verifying `GET /api/health/ready` returns HTTP 200.

### 3.2 Agent Telemetry Ingestion Token Rotation
1. Generate a new 64-character high-entropy secret token:
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```
2. Update `AEGIS_AGENT_TOKEN` in `/home/ubuntu/aegis/.env`.
3. Restart both services:
   ```bash
   sudo systemctl restart aegis-backend.service
   sudo systemctl restart aegis-collector.service
   ```
4. Verify telemetry ingestion:
   ```bash
   journalctl -u aegis-collector.service -n 10 --no-pager | grep -i "ingested"
   ```

### 3.3 Session Authentication Secret (`AEGIS_AUTH_SECRET`) Rotation
1. Generate a new secret:
   ```bash
   python3 -c "import secrets; print(secrets.token_urlsafe(48))"
   ```
2. Update `AEGIS_AUTH_SECRET` in `/home/ubuntu/aegis/.env`.
3. Restart `aegis-backend.service`.
4. *Note:* Rotating this secret invalidates all active browser session tokens. Users will be required to log in again.

---

## 4. Host Hardening & Production Configuration Guide

### 4.1 Apache TLS / HTTPS Configuration (Let's Encrypt / Certbot)
To transition from staging (Port 80 HTTP) to public production (Port 443 HTTPS):

1. **Install Certbot:**
   ```bash
   sudo apt-get update
   sudo apt-get install -y certbot python3-certbot-apache
   ```
2. **Obtain and Install SSL Certificate:**
   ```bash
   sudo certbot --apache -d aegis.yourdomain.com
   ```
3. **Verify Apache VirtualHost Configuration (`/etc/apache2/sites-available/000-default-le-ssl.conf`):**
   ```apache
   <IfModule mod_ssl.c>
   <VirtualHost *:443>
       ServerName aegis.yourdomain.com
       ServerAdmin webmaster@localhost
       DocumentRoot /var/www/html

       SSLEngine on
       SSLCertificateFile /etc/letsencrypt/live/aegis.yourdomain.com/fullchain.pem
       SSLCertificateKeyFile /etc/letsencrypt/live/aegis.yourdomain.com/privkey.pem
       Include /etc/letsencrypt/options-ssl-apache.conf

       # Security Headers
       Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
       Header always set X-Content-Type-Options "nosniff"
       Header always set X-Frame-Options "DENY"

       # Reverse Proxy to FastAPI Backend
       ProxyPreserveHost On
       ProxyPass /api/ http://127.0.0.1:8000/api/
       ProxyPassReverse /api/ http://127.0.0.1:8000/api/

       <Directory /var/www/html>
           Options -Indexes +FollowSymLinks
           AllowOverride All
           Require all granted
           FallbackResource /index.html
       </Directory>

       ErrorLog ${APACHE_LOG_DIR}/aegis_ssl_error.log
       CustomLog ${APACHE_LOG_DIR}/aegis_ssl_access.log combined
   </VirtualHost>
   </IfModule>
   ```
4. **Reload Apache:**
   ```bash
   sudo systemctl reload apache2
   ```

### 4.2 Systemd Sandboxing for `aegis-backend.service`
Update `/etc/systemd/system/aegis-backend.service` during scheduled maintenance to apply kernel namespace isolation:

```ini
[Unit]
Description=AEGIS Security Monitoring Backend Gateway
After=network.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/home/ubuntu/aegis
EnvironmentFile=/home/ubuntu/aegis/.env
ExecStart=/home/ubuntu/aegis/.venv/bin/uvicorn aegis_backend.main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5s
LimitNOFILE=65536

# Security Hardening
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/home/ubuntu/aegis
PrivateTmp=true

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```
Apply changes:
```bash
sudo systemctl daemon-reload
sudo systemctl restart aegis-backend.service
```

### 4.3 Directory Permissions Enforcement
To remediate `SEC-FIND-005` without affecting running services:
```bash
chmod 0750 /home/ubuntu/aegis
chmod 0750 /home/ubuntu/aegis/aegis_agent
chmod 0750 /home/ubuntu/aegis/aegis_backend
chmod 0750 /home/ubuntu/aegis/docs
chmod 0750 /home/ubuntu/aegis/scripts
chmod 0750 /home/ubuntu/aegis/supabase
chmod 0750 /home/ubuntu/aegis/tests
```

### 4.4 Host Firewall (UFW) Configuration
```bash
# Enable UFW and allow SSH and Web traffic only
sudo apt-get install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw allow 80/tcp comment 'HTTP Reverse Proxy'
sudo ufw allow 443/tcp comment 'HTTPS Reverse Proxy'
sudo ufw enable
sudo ufw status verbose
```

---

## 5. Security Incident Response & Escalation Workflow

When an alert or incident reaches `High` or `Critical` severity:

1. **Review Incident Timeline:** Navigate to Dashboard `/incidents/{id}` or execute:
   ```bash
   curl -s -H "Authorization: Bearer <token>" http://127.0.0.1/api/incidents/{id}/timeline | jq .
   ```
2. **Review AI Forensic Handoff Document:**
   Inspect the AI Investigation panel. The prompt separates **Confirmed Facts** (grounded in telemetry) from **Unverified Hypotheses** and lists read-only verification commands.
3. **Execute Non-Destructive Verification Commands:**
   Run the specific investigation commands recommended in the handoff document (e.g. `ss -tulpn`, `ps aux | grep <process>`, `last -n 10`).
4. **Contain Threat via Authorized Human Action:**
   Apply targeted host containment (e.g. isolate compromised user credentials, block malicious source IP via firewall, terminate unauthorized process).
5. **Update Incident Status:**
   Transition incident status through official API (`investigating` -> `contained` -> `resolved`):
   ```bash
   curl -X PATCH -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"status": "contained", "notes": "Host quarantined from network; suspicious session terminated."}' \
     http://127.0.0.1/api/incidents/{id}/status
   ```
6. **Archive Signed Evidence Bundle:**
   Download the cryptographically hashed incident evidence bundle and PDF report for compliance and audit preservation.

