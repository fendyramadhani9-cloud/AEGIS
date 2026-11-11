# AEGIS — HTTPS & Cloudflare Tunnel Verification Report

**Document Version:** 1.0.0  
**Inspection Date:** November 2026  
**Auditor:** AEGIS Security Assurance Team (Lead: Apri)  
**System:** AEGIS (AI-Powered Linux Security Monitoring & Incident Response)  
**Production Host:** `fenn` (`192.168.193.129`)  
**Audit Scope:** End-to-end transport encryption, Cloudflare Tunnel ingress, Apache origin configuration, loopback bindings, and network exposure.

---

## 1. Executive Summary & Verdict

This assessment inspected the live transport encryption topology, DNS routing, Cloudflare Tunnel daemon, and web server bindings for AEGIS. 

### Key Findings:
1. **Cloudflare Tunnel Daemon Active:** `cloudflared.service` (PID 811) is active on VM `fenn`, running with `--token-file /etc/cloudflared/token`. It maintains redundant outbound QUIC connections to Cloudflare Edge Points of Presence (`cgk01` in Jakarta, `sin11` in Singapore).
2. **DNS Subdomain Unrouted:** Public DNS queries for `aegis.diazz.web.id` return `NXDOMAIN` / `No address associated with hostname`. The hostname has not yet been routed in the Cloudflare Zero Trust public DNS dashboard to point to the active tunnel.
3. **Origin Network Exposure:** Apache 2.4 on VM `fenn` listens on `*:80` across all interfaces (`0.0.0.0`). Requests directly addressed to `http://192.168.193.129:80` are accepted and reverse-proxied to FastAPI. The origin is **not isolated to localhost-only connections**, allowing local LAN clients to bypass Cloudflare Tunnel.
4. **Backend Loopback Isolation Verified:** The FastAPI backend gateway (`uvicorn` PID 807) binds strictly to `127.0.0.1:8000` (loopback only) and cannot be reached directly from outside the VM.

**Public Release Gate Verdict:** **`PARTIAL / PENDING PREREQUISITES`**  
Staging and internal LAN operations are functional. Public internet access is blocked pending DNS record mapping and origin binding restrictions.

---

## 2. Actual vs. Target Architecture

### Target Architecture (Desired for Public Release)
```
[ External User / Public Browser ]
                 │
                 ▼ HTTPS (Port 443 - Public Internet)
┌─────────────────────────────────────────────────────────────┐
│ Cloudflare Edge (aegis.diazz.web.id)                        │
│ - Managed Public TLS Certificate (Edge Termination)         │
│ - Cloudflare Zero Trust Access Policy (SSO / MFA)           │
│ - Cloudflare WAF & DDoS Protection                          │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼ Outbound QUIC/TLS Tunnel (Encrypted)
┌─────────────────────────────────────────────────────────────┐
│ Host VM `fenn` (192.168.193.129)                            │
│                                                             │
│   ┌──────────────────────────────────────────────────────┐  │
│   │ cloudflared daemon (PID 811)                         │  │
│   │ - Outbound UDP/QUIC to Cloudflare Edge               │  │
│   │ - No inbound public ports required                   │  │
│   └──────────────────────────┬───────────────────────────┘  │
│                              │ Local HTTP (127.0.0.1:80)     │
│                              ▼                              │
│   ┌──────────────────────────────────────────────────────┐  │
│   │ Apache 2.4 Reverse Proxy                             │  │
│   │ - Bound EXCLUSIVELY to 127.0.0.1:80                  │  │
│   │ - External LAN access dropped by packet filter       │  │
│   │ - Serves /var/www/html (Static Frontend)             │  │
│   │ - ProxyPass /api/ -> http://127.0.0.1:8000/api/      │  │
│   └──────────────────────────┬───────────────────────────┘  │
│                              │ Loopback (127.0.0.1:8000)    │
│                              ▼                              │
│   ┌──────────────────────────────────────────────────────┐  │
│   │ aegis-backend.service (FastAPI Gateway - PID 807)     │  │
│   │ - Bound to 127.0.0.1:8000 (Loopback Only)            │  │
│   └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Actual Verified Architecture (Current Staging State)
```
[ Workstation / LAN Client ]              [ Public Internet ]
           │                                       │
           │ HTTP (Port 80)                        │ DNS: aegis.diazz.web.id
           │ (Direct LAN Access)                   │ (Returns NXDOMAIN)
           ▼                                       ▼
┌─────────────────────────────────────────────────────────────┐
│ Host VM `fenn` (192.168.193.129)                            │
│                                                             │
│   Apache 2.4 listens on *:80 (Exposed to LAN)               │
│   cloudflared (PID 811) connected outbound to Cloudflare     │
│   FastAPI (PID 807) bound to 127.0.0.1:8000 (Loopback OK)   │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Detailed Verification Items

| Verification Item | Command / Method | Expected State | Actual Verified State | Status | Evidence Label |
|---|---|---|---|:---:|:---:|
| **1. DNS Hostname `aegis.diazz.web.id`** | `python3 socket.gethostbyname("aegis.diazz.web.id")` | Resolves to Cloudflare Anycast IPs | `[Errno -5] No address associated with hostname` (NXDOMAIN) | **FAIL** | `[VERIFIED]` |
| **2. Cloudflare Tunnel Daemon** | `systemctl status cloudflared.service` | Active (running) | Active (running) since Nov 11 06:53 (PID 811) | **PASS** | `[VERIFIED]` |
| **3. Tunnel Ingress Protocol** | `journalctl -u cloudflared -n 50` | Connected via QUIC | Registered connections to `cgk01`, `cgk02`, `sin11` via QUIC | **PASS** | `[VERIFIED]` |
| **4. Apache Listening Binding** | `ss -tulpn \| grep apache2` | Bound to `127.0.0.1:80` | Bound to `*:80` (all interfaces) | **PARTIAL** | `[VERIFIED]` |
| **5. Apache VirtualHost Definition** | `cat /etc/apache2/sites-enabled/000-default.conf` | `ServerName aegis.diazz.web.id` with proxy | Default vhost `<VirtualHost *:80>` without specific ServerName | **PARTIAL** | `[VERIFIED]` |
| **6. Direct LAN Access to Apache** | `curl -I http://192.168.193.129/` | Blocked or restricted | Returns HTTP 200 OK (access log shows direct LAN hits) | **FAIL (Origin Exposed)** | `[VERIFIED]` |
| **7. Backend Loopback Binding** | `ss -tulpn \| grep 8000` | Bound to `127.0.0.1:8000` | `tcp LISTEN 127.0.0.1:8000` (PID 807 `uvicorn`) | **PASS** | `[VERIFIED]` |
| **8. Direct External Access to Backend** | `curl http://192.168.193.129:8000/` | Connection refused | Connection refused (port 8000 unexposed) | **PASS** | `[VERIFIED]` |
| **9. Mixed Content Vulnerability** | Static scan of React bundle | Relative URLs (`/api`) | Relative URLs used (`VITE_API_BASE_URL=`); 0 mixed content | **PASS** | `[VERIFIED]` |
| **10. Cloudflare Access Enforcement** | HTTP request through tunnel | Protected by Access | Not testable until DNS CNAME is routed in Cloudflare | **BLOCKED** | `[BLOCKED]` |

---

## 4. Encryption Boundary & Residual Risk Analysis

### Is a Public Certificate on Apache Mandatory?
**Answer: NO, not when origin traffic is strictly encapsulated within Cloudflare Tunnel.**

In a standard Cloudflare Tunnel deployment:
1. The visitor's browser connects to Cloudflare Edge using **HTTPS** (protected by Cloudflare's managed TLS certificate).
2. Cloudflare Edge routes the traffic through an **encrypted tunnel** (QUIC/TLS) directly to the `cloudflared` process on VM `fenn`.
3. `cloudflared` forwards the decrypted request over **local loopback (`127.0.0.1`)** to Apache.
4. Because the loopback interface (`lo`) never leaves the VM's memory/kernel boundary, local HTTP communication between `cloudflared` and Apache is safe from external eavesdropping.

### The Real Security Vulnerability: Origin Bypass
The critical security issue is **not** that Apache uses HTTP internally; it is that **Apache listens on `*:80` instead of `127.0.0.1:80`**.
- Because Apache is listening on `0.0.0.0:80`, an attacker on the same local network (`192.168.193.0/24`) or anyone with network connectivity to VM `fenn` can navigate to `http://192.168.193.129/` directly.
- By accessing Apache directly, the attacker completely bypasses Cloudflare Edge, Cloudflare Access authentication, Cloudflare WAF, and DDoS mitigation.

---

## 5. Public Release Prerequisites & Deployment Plan

To achieve full compliance for Gate 4 (Public Exposure), the following changes must be performed under an authorized maintenance window:

### Step 1: Configure Public DNS in Cloudflare Zero Trust Dashboard
1. Open Cloudflare Zero Trust Dashboard -> Networks -> Tunnels.
2. Select the active tunnel (`275471d6-...`).
3. Add a Public Hostname:
   - **Public Hostname:** `aegis.diazz.web.id`
   - **Service Type:** `HTTP`
   - **URL:** `127.0.0.1:80`
   - **Additional Settings:** Enable HTTP-to-HTTPS redirect at Cloudflare Edge.
4. Verify DNS resolution: `nslookup aegis.diazz.web.id` must return Cloudflare Anycast IP addresses.

### Step 2: Configure Cloudflare Access Policy (Optional / Recommended)
1. In Cloudflare Zero Trust -> Access -> Applications, create a self-hosted application for `aegis.diazz.web.id`.
2. Configure authentication rules (e.g. require One-Time PIN via authorized company email or Google OAuth).

### Step 3: Restrict Apache to Loopback Only (Origin Isolation)
Update `/etc/apache2/ports.conf` on VM `fenn`:
```apache
# Replace Listen 80 with:
Listen 127.0.0.1:80
```
This guarantees that Apache only accepts connections originating from `cloudflared` (or local curl commands), completely blocking direct LAN access on `192.168.193.129:80`.
