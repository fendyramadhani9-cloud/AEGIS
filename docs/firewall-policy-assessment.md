# AEGIS — Host Firewall Policy & Network Isolation Assessment

**Document Version:** 1.0.0  
**Assessment Date:** November 2026  
**Auditor / Engineer:** AEGIS Security Assurance Team (Lead: Apri)  
**System:** AEGIS (AI-Powered Linux Security Monitoring & Incident Response)  
**Target Host:** Production VM `fenn` (`192.168.193.129`), Ubuntu 24.04 LTS

---

## 1. Executive Summary & Safety Declaration

This assessment reviews the host-level network exposure on VM `fenn` and designs a least-privilege packet filtering policy. The design prioritizes preserving authorized administrative SSH access and Cloudflare Tunnel operations while eliminating direct exposure of the Apache web server and FastAPI backend.

**CRITICAL PRODUCTION SAFETY CONFIRMATION:**  
In strict compliance with the audit constraints, **NO firewall changes were executed on production VM `fenn`**. `ufw` was neither installed nor enabled. The proposed ruleset is documented as an authorized reference deployment plan requiring an explicit maintenance window.

---

## 2. Live Network & Socket Inventory

Live inspection (`ss -tulpn` and `ip route`) on VM `fenn` revealed the following active socket bindings:

| Protocol | Local Binding | Process / Service | PID | Network Scope | Security Assessment |
|---|---|---|:---:|---|---|
| **TCP** | `0.0.0.0:22` | OpenSSH Server (`sshd`) | System | **Exposed to all interfaces** | Administration gateway. Requires restriction to authorized subnets. |
| **TCP** | `*:80` | Apache 2.4 (`apache2`) | System | **Exposed to all interfaces** | **HIGH EXPOSURE RISK:** Allows LAN clients to bypass Cloudflare Tunnel and Access. |
| **TCP** | `127.0.0.1:8000` | FastAPI Backend (`uvicorn`) | 807 | **Loopback Only** | **SECURE:** Unreachable from external network interfaces. |
| **TCP** | `127.0.0.1:20241` | Cloudflare Tunnel Metrics | 811 | **Loopback Only** | **SECURE:** Internal diagnostic socket. |
| **UDP** | Ephemeral / `*:51356` | Cloudflare Tunnel (`cloudflared`) | 811 | **Outbound QUIC** | Outbound tunnel streams to Cloudflare Edge (`cgk01`, `sin11`). |
| **UDP** | `127.0.0.53%lo:53` | `systemd-resolved` | System | **Loopback Only** | Local DNS resolver. |

---

## 3. Cloudflare Tunnel Connectivity Architecture

A critical architectural distinction must guide the firewall policy:

```
[ Public User / Internet ] 
            │
            ▼ HTTPS
┌───────────────────────────────────────┐
│ Cloudflare Edge (Anycast Network)     │
└──────────────────┬────────────────────┘
                   │
                   ▲ Inbound HTTP requests transported inside 
                   │ established outbound QUIC/UDP streams
                   │
┌──────────────────┴────────────────────┐
│ Host VM `fenn`                        │
│                                       │
│   cloudflared (PID 811)               │
│   Initiates OUTBOUND connection to    │
│   Cloudflare Edge (Port 7844 / QUIC)  │
│   ===> ZERO INBOUND PORTS NEEDED!     │
└───────────────────────────────────────┘
```

### Key Principles:
1. **Cloudflare Tunnel is Outbound-Only:** `cloudflared` initiates outbound UDP connections to Cloudflare Edge IPs (`198.41.192.0/24`, `198.41.200.0/24`). It requires **zero open inbound ports** on the public interface.
2. **Inbound HTTP Port 80 is NOT Needed from the Internet:** Because `cloudflared` forwards requests locally over loopback to Apache, port 80 **must not** be exposed to the outside network.
3. **Preventing Origin Bypass:** Leaving port 80 open on `ens33` allows attackers on the network to bypass Cloudflare DDoS protection, Cloudflare WAF, and Cloudflare Access policies entirely.

---

## 4. Proposed Target Firewall Policy

The recommended firewall policy enforces a **Default Deny Inbound** posture with explicit whitelist rules:

### Inbound Rules (Traffic entering VM `fenn`):
1. **Loopback (`lo`):** `ALLOW ALL` (Required for `cloudflared` -> Apache -> FastAPI backend communication).
2. **Established & Related Connections:** `ALLOW ALL` (Required for responses to outbound requests).
3. **SSH Administration (`22/tcp`):** `ALLOW` from the authorized management subnet only (`192.168.193.0/24` or specific administrator IP `192.168.193.1`).
4. **All Other Inbound Traffic (`80/tcp`, `443/tcp`, `8000/tcp`):** **DROP / DENY**.

### Outbound Rules (Traffic leaving VM `fenn`):
1. **DNS (`53/udp, 53/tcp`):** `ALLOW` (Domain name resolution).
2. **Cloudflare Tunnel (`7844/udp` and dynamic QUIC):** `ALLOW` (Tunnel connection to Cloudflare Edge).
3. **HTTPS (`443/tcp`):** `ALLOW` (Supabase Cloud PostgreSQL API and Google Gemini AI API).
4. **NTP (`123/udp`):** `ALLOW` (System clock synchronization).

---

## 5. Step-by-Step Implementation & Validation Plan

### Phase A: Rebind Apache to Loopback (Recommended First Step)
Before touching firewall packet filters, restrict Apache to listen only on loopback:
```bash
# Edit /etc/apache2/ports.conf
sudo sed -i 's/Listen 80/Listen 127.0.0.1:80/' /etc/apache2/ports.conf
sudo systemctl restart apache2
```
*Verification:* `ss -tulpn | grep 80` must show `127.0.0.1:80`, not `*:80`.

### Phase B: Configure UFW (During Authorized Maintenance Window)
```bash
# 1. Install UFW
sudo apt-get update && sudo apt-get install -y ufw

# 2. Set default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# 3. Allow loopback traffic completely
sudo ufw allow in on lo

# 4. Allow SSH strictly from the administrator subnet
sudo ufw allow from 192.168.193.0/24 to any port 22 proto tcp comment 'Authorized LAN SSH'

# 5. Review staged rules BEFORE enabling
sudo ufw show added

# 6. Enable UFW (Ensure an active secondary SSH session is open!)
sudo ufw --force enable
sudo ufw status verbose
```

### Phase C: Emergency Rollback Procedure
If SSH connectivity behaves unexpectedly or tunnel fails:
```bash
# Run from console / existing terminal session
sudo ufw disable
```
If console access is required via VMware vSphere / Workstation console:
```bash
sudo systemctl stop ufw
sudo systemctl disable ufw
```

---

## 6. Pre-Implementation Verification Checklist

- [x] Confirmed `cloudflared` uses outbound QUIC (zero inbound ports required).
- [x] Confirmed backend binds to `127.0.0.1:8000` (loopback only).
- [x] Identified administrator workstation IP (`192.168.193.1` / `192.168.193.0/24`).
- [x] Confirmed UFW is currently **NOT active** on production VM.
- [ ] Staging test on secondary VM before applying to production `fenn`.
- [ ] Maintenance window scheduled and approved by Project Owner.
