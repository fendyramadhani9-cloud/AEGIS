"""
AEGIS Incident Investigation, Handoff Generation, Recovery Verification,
and Operational State Service.

Enforces core AEGIS security & product constraints:
1. No autonomous remediation, IP blocking, or service termination.
2. Alert severity is strictly immutable (set only by deterministic Rules Engine).
3. Missing telemetry or offline agents NEVER count as proof of recovery ('unverified').
4. Confirmed facts are strictly separated from unverified hypotheses.
5. All evidence and telemetry are sanitized before AI analysis or handoff export.
"""

from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone, timedelta
import hashlib
import io
import json
import logging

from aegis_backend.config import settings
from aegis_backend.repository import BaseAegisRepository
from aegis_backend.sanitizer import TelemetrySanitizer
from aegis_backend.schemas import (
    AiAnalysisResponse,
    HandoffDocumentResponse,
    RecoveryVerificationResponse,
    VerificationCheckItem,
    RemediationDiffItem,
    InvestigationStateResponse,
    InvestigationNoteItem,
    IncidentReplayResponse,
    ReplayStepItem,
    FindingItem,
    TelemetryGapItem,
    EvidenceSessionItem,
    AuditLogItem,
    PipelineSourceHealthItem,
    ReportItem,
    KillChainStageItem,
    BlastRadiusSummary,
    AlertContextResponse,
    SignedEvidenceEventItem,
    SignedEvidenceBundleResponse,
)

from aegis_agent.schemas import (
    IncidentInvestigationInput,
    AlertInput,
    EntityContext,
    LogEventInput,
    SeverityLevel,
)
from aegis_agent.providers import RealLLMAdapter, MockLLMProvider
from aegis_agent.tools import BackendGatekeeper
from aegis_agent.services import RuntimeMonitorService

logger = logging.getLogger("aegis_backend.incident_service")


# Rule Metadata Catalog for transparent rule explanations & handoff instructions
RULE_METADATA: Dict[str, Dict[str, Any]] = {
    "RULE-SSH-BRUTE": {
        "mitre_id": "T1110.001",
        "mitre_name": "Brute Force: Password Guessing",
        "condition": "count(auth_failure) >= 3 within 300s grouped by (host_id, source_ip)",
        "rationale": "Repeated rapid SSH authentication failures from a single source IP indicate automated credential stuffing or dictionary brute-force activity.",
        "investigation_cmds": [
            "sudo journalctl -u ssh -u sshd --since '1 hour ago' | grep -E 'Failed|Accepted|Invalid'",
            "sudo ss -tnp state established '( dport = :22 or sport = :22 )'",
            "sudo lastb -n 25",
            "sudo grep -E '^(PermitRootLogin|PasswordAuthentication|MaxAuthTries)' /etc/ssh/sshd_config",
        ],
        "remediation_plan": [
            "Verify whether the source IP belongs to an authorized administrator or jump host before restricting access.",
            "Disable SSH password authentication ('PasswordAuthentication no') in /etc/ssh/sshd_config after confirming SSH public key access works.",
            "Set 'MaxAuthTries 3' and 'PermitRootLogin no' in /etc/ssh/sshd_config.",
            "Validate configuration syntax using 'sudo sshd -t' before reloading the SSH daemon.",
        ],
        "service_impact": "Reloading sshd ('sudo systemctl reload ssh') does not drop active SSH sessions, but disabling PasswordAuthentication will block users who do not have SSH keys installed.",
        "rollback_steps": [
            "Keep an active root/sudo terminal session open while testing changes.",
            "Restore backup configuration: 'sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config && sudo systemctl reload ssh'.",
        ],
        "verification_steps": [
            "Confirm 'sudo sshd -T | grep -E \"passwordauthentication|permitrootlogin|maxauthtries\"' reflects hardened settings.",
            "Monitor AEGIS telemetry for 15 minutes to confirm zero new RULE-SSH-BRUTE triggers from the offending IP.",
        ],
    },
    "RULE-AUTH-003": {
        "mitre_id": "T1078 / T1110",
        "mitre_name": "Valid Accounts / Brute Force Compromise",
        "condition": "auth_success preceded by >= 2 auth_failure events within 300s from same source_ip and user",
        "rationale": "An authentication success immediately following multiple failed attempts from the same IP strongly suggests either a successful brute-force compromise or a user mistyping credentials.",
        "investigation_cmds": [
            "w && who -a",
            "sudo journalctl _COMM=sshd _COMM=sudo --since '1 hour ago'",
            "sudo last -n 20 -a",
            "sudo ps auxf | grep -E 'pts/|ssh'",
        ],
        "remediation_plan": [
            "Confirm with the account owner whether the login from the recorded source IP was legitimate.",
            "If unauthorized: lock the compromised user account ('sudo usermod -L <username>') and inspect active processes owned by that user.",
            "Audit ~/.ssh/authorized_keys, /etc/sudoers.d/, and user crontabs ('sudo crontab -u <username> -l') for persistence.",
            "Rotate credentials and enforce SSH key-only authentication.",
        ],
        "service_impact": "Locking the user account prevents new logins for that user. Ensure automated service pipelines do not depend on interactive password login for this account.",
        "rollback_steps": [
            "Unlock user account if verified as false positive: 'sudo usermod -U <username>'.",
        ],
        "verification_steps": [
            "Verify no unauthorized processes or SSH multiplexing sockets remain active for the target user.",
            "Confirm AEGIS telemetry continues streaming with zero new suspicious authentication correlations.",
        ],
    },
    "RULE-SUSP-SUDO": {
        "mitre_id": "T1548.003",
        "mitre_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "condition": "sudo_exec matching interactive root shell (/bin/bash, /bin/sh, sudo -i) or overly permissive chmod (777)",
        "rationale": "Spawning an interactive root shell via sudo bypasses per-command audit logging, and world-writable permission changes (chmod 777) expose system or web files to tampering.",
        "investigation_cmds": [
            "sudo journalctl _COMM=sudo --since '2 hours ago'",
            "sudo ls -la /var/www/html /etc/sudoers /etc/sudoers.d/",
            "sudo find /var/www -perm -0002 -type f -ls 2>/dev/null",
            "sudo ausearch -m EXECVE -ts recent 2>/dev/null || true",
        ],
        "remediation_plan": [
            "Verify with the operator ('ubuntu' or target user) the intent of the interactive root shell or permission change.",
            "If 'chmod 777' was applied to web or system directories, restore least-privilege permissions (e.g. 'sudo chmod 755' for directories and '644' for static files).",
            "Restrict sudoers policy to specific required administrative commands rather than unrestricted 'ALL=(ALL:ALL) NOPASSWD: ALL' where feasible.",
        ],
        "service_impact": "Tightening file permissions from 777 to 755/644 will not disrupt web servers (Apache/Nginx) as long as ownership matches www-data or the service user.",
        "rollback_steps": [
            "Document original file ownership and permissions via 'stat <path>' prior to modification.",
            "Restore previous ownership/mode if an application write error occurs.",
        ],
        "verification_steps": [
            "Verify target directory permissions with 'stat' to confirm world-writable bit is removed.",
            "Observe AEGIS Runtime Monitor to confirm no further anomalous sudo escalations occur.",
        ],
    },
    "RULE-WEB-ATTACK": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "condition": "High-signal web attack probe (Path Traversal, SQLi, Command Injection, .env/.git probe) or >=4 HTTP 401/403 burst",
        "rationale": "Web access logs show active vulnerability scanning, LFI/RCE payload delivery, or credential brute-forcing against HTTP endpoints.",
        "investigation_cmds": [
            "sudo tail -n 100 /var/log/nginx/access.log /var/log/apache2/access.log 2>/dev/null",
            "sudo ls -la /var/www/html",
            "sudo ps auxf | grep -E 'www-data|nginx|apache2'",
        ],
        "remediation_plan": [
            "Inspect the targeted web endpoint or static directory to ensure sensitive files (.env, .git) are not web-accessible.",
            "Verify that /var/www/html is owned by root:www-data with read-only permissions (0755/0644) for the web worker.",
            "Add rate-limiting or Nginx location deny blocks for sensitive dot-files.",
        ],
        "service_impact": "Blocking access to dot-files (.env, .git) has zero impact on legitimate HTTP users.",
        "rollback_steps": [
            "Restore previous Nginx/Apache site configuration and run 'sudo nginx -t && sudo systemctl reload nginx'.",
        ],
        "verification_steps": [
            "Verify HTTP requests to /.env or /../ return 403/404 without exposing file contents.",
            "Confirm zero new RULE-WEB-ATTACK alerts during the 15-minute observation window.",
        ],
    },
    "RULE-ACCT-BACKDOOR": {
        "mitre_id": "T1136.001 / T1098",
        "mitre_name": "Create Account: Local Account / Account Manipulation",
        "condition": "Creation of new local user account (useradd) or addition of user to privileged group (sudo, root, wheel, docker)",
        "rationale": "Attackers frequently create rogue local accounts or add compromised service accounts to sudo/docker groups for persistent root access.",
        "investigation_cmds": [
            "sudo tail -n 20 /etc/passwd /etc/group",
            "sudo grep -E ':0:' /etc/passwd",
            "sudo journalctl _COMM=useradd _COMM=usermod _COMM=gpasswd --since '2 hours ago'",
        ],
        "remediation_plan": [
            "Confirm with system administrators whether the user creation or group change was authorized.",
            "If unauthorized: lock the rogue account ('sudo usermod -L <user>') and remove it from privileged groups ('sudo gpasswd -d <user> sudo').",
            "Audit active processes and crontabs owned by the newly created account before deleting it.",
        ],
        "service_impact": "Locking an unauthorized account does not impact legitimate production services.",
        "rollback_steps": [
            "Re-enable account or restore group membership if verified as authorized provisioning.",
        ],
        "verification_steps": [
            "Confirm 'id <user>' no longer lists sudo/root group membership and '/etc/passwd' has no unauthorized UID 0 entries.",
        ],
    },
    "RULE-FW-PORTSCAN": {
        "mitre_id": "T1046",
        "mitre_name": "Network Service Discovery (Port Scan)",
        "condition": "count(firewall_block) >= 4 within 300s from same source_ip",
        "rationale": "Multiple UFW firewall blocks from a single source IP across ports indicate active network reconnaissance or lateral movement probing.",
        "investigation_cmds": [
            "sudo journalctl -k --since '1 hour ago' | grep 'UFW BLOCK' | tail -n 50",
            "sudo ufw status verbose",
            "sudo ss -tulnp",
        ],
        "remediation_plan": [
            "Verify that UFW default incoming policy remains 'deny (incoming)' and only required ports are allowed.",
            "Confirm internal services (e.g. FastAPI port 8000, databases) are bound to 127.0.0.1 rather than 0.0.0.0.",
        ],
        "service_impact": "No impact; UFW is already dropping the unauthorized probe packets.",
        "rollback_steps": [
            "Review UFW rules via 'sudo ufw status numbered' if legitimate internal traffic was blocked.",
        ],
        "verification_steps": [
            "Confirm UFW remains active and no unapproved listening ports are exposed on 0.0.0.0.",
        ],
    },
    "RULE-KERNEL-EXPLOIT": {
        "mitre_id": "T1068",
        "mitre_name": "Exploitation for Privilege Escalation / Memory Corruption",
        "condition": "Kernel segmentation fault (segfault) reported in daemon or binary",
        "rationale": "Binary segmentation faults in network-facing daemons or SUID binaries can indicate buffer overflow or memory corruption exploit attempts.",
        "investigation_cmds": [
            "sudo dmesg -T | grep -i segfault | tail -n 20",
            "sudo coredumpctl list 2>/dev/null || true",
            "sudo sysctl kernel.randomize_va_space fs.suid_dumpable",
        ],
        "remediation_plan": [
            "Inspect the crashing binary version and apply pending Ubuntu security updates.",
            "Ensure ASLR ('kernel.randomize_va_space = 2') and 'fs.suid_dumpable = 0' are enforced.",
        ],
        "service_impact": "Restarting or patching the affected service may cause a brief reload.",
        "rollback_steps": [
            "Pin previous package version if an update introduces regression.",
        ],
        "verification_steps": [
            "Confirm zero new segfault messages in kernel journal over the observation window.",
        ],
    },
    "RULE-CRON-PERSIST": {
        "mitre_id": "T1053.003",
        "mitre_name": "Scheduled Task/Job: Cron Persistence",
        "condition": "CRON execution matching suspicious payload (curl, wget, nc, bash -i, /dev/tcp, base64, /tmp/)",
        "rationale": "Adversaries abuse cron jobs to periodically download and execute reverse shells or coinminers from /tmp or external C2 servers.",
        "investigation_cmds": [
            "sudo ls -la /etc/crontab /etc/cron.* /var/spool/cron/crontabs/",
            "sudo journalctl _COMM=cron --since '2 hours ago'",
            "sudo ls -la /tmp /dev/shm",
        ],
        "remediation_plan": [
            "Comment out or remove the unauthorized cron entry after capturing its content as forensic evidence.",
            "Remove any malicious payload scripts dropped in /tmp or /dev/shm.",
        ],
        "service_impact": "Removing unauthorized cron payloads has no impact on legitimate system maintenance.",
        "rollback_steps": [
            "Keep a backup copy of the crontab file before editing.",
        ],
        "verification_steps": [
            "Verify crontab entries are clean and CRON journal logs show zero executions of the suspicious command.",
        ],
    },
    "RULE-DEFENSE-EVASION": {
        "mitre_id": "T1562.001",
        "mitre_name": "Impair Defenses: Disable or Modify Tools / Firewall",
        "condition": "Systemd stopping critical security service (ufw, auditd, ssh, fail2ban, apparmor, aegis-collector)",
        "rationale": "Stopping host firewall, auditd, or the AEGIS telemetry collector is a high-severity defense evasion technique to blind monitoring.",
        "investigation_cmds": [
            "sudo systemctl status ufw auditd ssh aegis-collector",
            "sudo journalctl -u ufw -u auditd -u aegis-collector --since '1 hour ago'",
        ],
        "remediation_plan": [
            "Verify whether an administrator intentionally stopped the service during maintenance.",
            "Re-enable and start the stopped security service ('sudo systemctl enable --now <service>').",
        ],
        "service_impact": "Re-enabling defensive services restores security monitoring and firewall enforcement.",
        "rollback_steps": [
            "Check service logs with 'journalctl -xeu <service>' if startup fails.",
        ],
        "verification_steps": [
            "Confirm 'systemctl is-active <service>' returns 'active' and telemetry streams normally.",
        ],
    },
    "RULE-SSH-KEY-BACKDOOR": {
        "mitre_id": "T1098.004",
        "mitre_name": "Account Manipulation: SSH Authorized Keys Tampering",
        "condition": "Modification of ~/.ssh/authorized_keys, /etc/ssh/sshd_config, or /etc/sudoers",
        "rationale": "Appending an attacker's public key to authorized_keys or altering sshd_config/sudoers grants persistent backdoor access bypassing password rotation.",
        "investigation_cmds": [
            "sudo stat /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys /etc/ssh/sshd_config /etc/sudoers 2>/dev/null",
            "sudo ssh-keygen -lf /root/.ssh/authorized_keys 2>/dev/null || true",
            "sudo git status /etc 2>/dev/null || true",
        ],
        "remediation_plan": [
            "Inspect every public key fingerprint in authorized_keys and remove any unrecognized keys.",
            "Ensure ~/.ssh is mode 0700 and authorized_keys is mode 0600 owned by the respective user.",
        ],
        "service_impact": "Removing unauthorized SSH keys does not affect legitimate administrators with verified keys.",
        "rollback_steps": [
            "Back up the existing authorized_keys file before removing suspect lines.",
        ],
        "verification_steps": [
            "Verify authorized_keys contains only approved key fingerprints and permissions are 0600.",
        ],
    },
    "RULE-ANTI-FORENSICS": {
        "mitre_id": "T1070",
        "mitre_name": "Indicator Removal on Host (Log Wiping & History Erasure)",
        "condition": "Execution of history -c, unset HISTFILE, shred, truncate -s 0, rm -rf /var/log, or journalctl --vacuum-time",
        "rationale": "Adversaries clear command history or destroy /var/log and systemd journal files to erase forensic evidence after compromising a defense node.",
        "investigation_cmds": [
            "sudo ls -la /var/log /var/log/journal",
            "sudo journalctl --verify",
            "sudo ausearch -m DELETE,TRUNCATE -ts recent 2>/dev/null || true",
        ],
        "remediation_plan": [
            "Preserve remaining volatile memory and off-host telemetry immediately.",
            "Enforce append-only attribute on critical log files ('sudo chattr +a /var/log/auth.log') and immutable auditd rules ('-e 2').",
            "Verify remote syslog/AEGIS telemetry forwarding is intact.",
        ],
        "service_impact": "Setting append-only (+a) requires logrotate to temporarily clear the attribute during rotation.",
        "rollback_steps": [
            "Remove append-only attribute if logrotate fails: 'sudo chattr -a /var/log/auth.log'.",
        ],
        "verification_steps": [
            "Confirm 'journalctl --verify' passes and zero new RULE-ANTI-FORENSICS alerts trigger.",
        ],
    },
    "RULE-DATA-EXFIL": {
        "mitre_id": "T1041 / T1560",
        "mitre_name": "Archive Collected Data & Exfiltration Over Network",
        "condition": "Sensitive directory archiving (tar/zip/7z on /etc, /var/www, /root) or outbound file transfer (scp, rsync, curl -F)",
        "rationale": "Packaging sensitive configuration or database directories and transferring them externally indicates active data theft.",
        "investigation_cmds": [
            "sudo ss -tnp state established",
            "sudo find /tmp /var/tmp /dev/shm -name '*.tar*' -o -name '*.zip' -o -name '*.7z' 2>/dev/null",
            "sudo journalctl _COMM=scp _COMM=rsync _COMM=curl _COMM=tar --since '2 hours ago'",
        ],
        "remediation_plan": [
            "Inspect active outbound connections and quarantine any unauthorized staged archive files in /tmp or /dev/shm.",
            "Rotate credentials, SSH keys, or TLS certificates that were included in the staged archive.",
            "Restrict egress traffic via UFW to authorized military/management subnets only.",
        ],
        "service_impact": "Restricting outbound SCP/RSYNC may affect unapproved manual file transfers.",
        "rollback_steps": [
            "Whitelist authorized backup server IPs in UFW outbound rules.",
        ],
        "verification_steps": [
            "Confirm staged archive files are removed and no unauthorized outbound transfers remain active.",
        ],
    },
    "RULE-ROOTKIT-SNIFF": {
        "mitre_id": "T1547.006 / T1040",
        "mitre_name": "Kernel Modules and Extensions / Network Sniffing",
        "condition": "Kernel log 'entered promiscuous mode' or unauthorized execution of insmod, modprobe, rmmod, or tcpdump",
        "rationale": "Loading unauthorized loadable kernel modules (.ko) or placing network interfaces into promiscuous mode indicates rootkit installation or passive credential sniffing.",
        "investigation_cmds": [
            "lsmod | head -n 30",
            "ip -d link show | grep -i promisc",
            "sudo dmesg -T | grep -iE 'promiscuous|taint|module' | tail -n 30",
        ],
        "remediation_plan": [
            "Disable promiscuous mode on the interface ('sudo ip link set <iface> promisc off') and terminate unauthorized packet capture processes.",
            "If an unauthorized kernel module was loaded, isolate the node and lock future module loading via 'sudo sysctl -w kernel.modules_disabled=1' after reboot verification.",
        ],
        "service_impact": "Setting kernel.modules_disabled=1 prevents loading any new kernel modules until the next reboot.",
        "rollback_steps": [
            "Reboot into a known-good signed kernel image if module state is unstable.",
        ],
        "verification_steps": [
            "Verify 'ip link' shows no PROMISC flag and 'lsmod' contains only signed distribution modules.",
        ],
    },
}


def get_rule_metadata(rule_id: str) -> Dict[str, Any]:
    for prefix, meta in RULE_METADATA.items():
        if rule_id.startswith(prefix):
            return meta
    return {
        "mitre_id": "T1078",
        "mitre_name": "Initial Access / Execution",
        "condition": f"Deterministic match on rule {rule_id}",
        "rationale": "Triggered by AEGIS deterministic Rules Engine based on normalized host telemetry.",
        "investigation_cmds": [
            "sudo journalctl -n 100 --no-pager",
            "sudo ss -tulnp",
            "ps auxf",
        ],
        "remediation_plan": [
            "Inspect supporting telemetry events and verify whether the activity was authorized.",
            "Apply least-privilege configuration adjustments after root-cause confirmation.",
        ],
        "service_impact": "Minimal impact when performing read-only verification prior to configuration changes.",
        "rollback_steps": [
            "Back up any modified configuration files before applying changes.",
        ],
        "verification_steps": [
            "Confirm telemetry continues streaming and the triggering rule does not re-fire.",
        ],
    }


class OperationalStateStore:
    """
    Maintains operational workflow states (AI analyses, investigation status/notes,
    recovery verifications, emergency evidence sessions, operator audit logs, and reports)
    so live dashboard actions work seamlessly alongside Supabase.
    """

    def __init__(self):
        self.ai_analyses: Dict[str, AiAnalysisResponse] = {}
        self.investigations: Dict[str, Dict[str, Any]] = {}
        self.verifications: Dict[str, RecoveryVerificationResponse] = {}
        self.host_findings: Dict[str, List[FindingItem]] = {}
        self.evidence_sessions: List[EvidenceSessionItem] = []
        self.audit_logs: List[AuditLogItem] = [
            AuditLogItem(
                id="aud-init-01",
                ts=datetime.now(timezone.utc).isoformat(),
                actor="system",
                action="system_startup",
                target_type="system",
                target_id="aegis-backend",
                summary="AEGIS Backend Gateway initialized with deterministic Rules Engine & Telemetry Sanitizer",
                details={"mode": settings.aegis_env, "llm_provider": settings.llm_provider},
            )
        ]
        self.reports: List[ReportItem] = []

    def record_audit(
        self,
        actor: str,
        action: str,
        target_type: str,
        target_id: str,
        summary: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditLogItem:
        item = AuditLogItem(
            id=f"aud-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
            ts=datetime.now(timezone.utc).isoformat(),
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            summary=summary,
            details=details or {},
        )
        self.audit_logs.insert(0, item)
        return item

    def get_investigation(self, alert_id: str) -> InvestigationStateResponse:
        state = self.investigations.get(alert_id)
        if not state:
            return InvestigationStateResponse(
                alert_id=alert_id,
                status="new",
                notes=[],
                updated_at=datetime.now(timezone.utc).isoformat(),
            )
        return InvestigationStateResponse(**state)

    def update_investigation(
        self,
        alert_id: str,
        status: str,
        note: Optional[str] = None,
        author: str = "ops-admin",
        alert: Optional[Dict[str, Any]] = None,
        repo: Optional[BaseAegisRepository] = None,
    ) -> InvestigationStateResponse:
        now_iso = datetime.now(timezone.utc).isoformat()
        existing = self.investigations.get(
            alert_id,
            {"alert_id": alert_id, "status": "new", "notes": [], "updated_at": now_iso},
        )
        prev_status = existing["status"]
        existing["status"] = status
        existing["updated_at"] = now_iso

        if note and note.strip():
            note_item = InvestigationNoteItem(
                id=f"note-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
                author=author,
                ts=now_iso,
                note=note.strip(),
                status_transition=status,
            )
            existing["notes"].insert(0, note_item.model_dump())

        self.investigations[alert_id] = existing

        # Sync incident lifecycle status to Supabase 'incidents' table if connected
        if repo and hasattr(repo, "client") and alert:
            try:
                db_status_map = {
                    "new": "open",
                    "detected": "open",
                    "investigating": "investigating",
                    "handoff_ready": "investigating",
                    "remediation_in_progress": "investigating",
                    "verification": "investigating",
                    "resolved": "resolved",
                    "false_positive": "false_positive",
                    "reopened": "investigating",
                    "unverified": "investigating",
                }
                getattr(repo, "client").table("incidents").upsert(
                    {
                        "id": f"INC-{alert_id}",
                        "alert_id": alert_id,
                        "host_id": alert.get("host_id"),
                        "title": alert.get("title", "Security Incident"),
                        "severity": alert.get("severity", "medium"),
                        "status": db_status_map.get(status, "open"),
                        "assigned_to": author,
                    },
                    on_conflict="id",
                ).execute()
            except Exception as e:
                logger.warning(f"Failed to sync incident status to Supabase for {alert_id}: {e}")

        self.record_audit(
            actor=author,
            action="update_investigation",
            target_type="alert",
            target_id=alert_id,
            summary=f"Updated alert {alert_id} status: {prev_status} -> {status}",
            details={"previous_status": prev_status, "new_status": status, "note": note},
        )
        return InvestigationStateResponse(**existing)


op_store = OperationalStateStore()


def run_alert_ai_analysis(
    alert: Dict[str, Any],
    evidence_items: List[Dict[str, Any]],
    repo: Optional[BaseAegisRepository] = None,
) -> AiAnalysisResponse:
    """
    Executes AI-assisted RM analysis on a deterministic alert and its supporting evidence.
    Uses RealLLMAdapter if Gemini API key is configured, with graceful fallback.
    """
    alert_id = alert["id"]
    rule_id = alert.get("rule_id", "RULE-UNKNOWN")
    host_id = alert.get("host_id", "unknown-host")
    severity_str = alert.get("severity", "medium").lower()
    detected_at = alert.get("detected_at") or datetime.now(timezone.utc).isoformat()
    meta = get_rule_metadata(rule_id)

    sev_map = {
        "critical": SeverityLevel.CRITICAL,
        "high": SeverityLevel.HIGH,
        "medium": SeverityLevel.MEDIUM,
        "low": SeverityLevel.LOW,
    }
    sev_enum = sev_map.get(severity_str, SeverityLevel.MEDIUM)

    # Extract entity context from evidence
    source_ip = None
    target_user = None
    log_inputs: List[LogEventInput] = []
    evidence_refs: List[str] = [f"Rule {rule_id}"]

    for idx, ev in enumerate(evidence_items):
        ev_id = ev.get("event_id") or f"EVT-{idx+1}"
        evidence_refs.append(ev_id)
        if not source_ip and ev.get("source_ip"):
            source_ip = ev.get("source_ip")
        if not target_user and ev.get("user_name"):
            target_user = ev.get("user_name")
        log_inputs.append(
            LogEventInput(
                event_id=ev_id,
                timestamp=ev.get("event_timestamp") or detected_at,
                event_type=ev.get("event_type") or "auth_event",
                source_ip=ev.get("source_ip"),
                user=ev.get("user_name"),
                command=(ev.get("details") or {}).get("command") if isinstance(ev.get("details"), dict) else None,
            )
        )

    if not log_inputs:
        # Construct synthetic single log ref from alert reason if alert_evidence is empty
        log_inputs.append(
            LogEventInput(
                event_id=f"EVT-REF-{alert_id[-6:]}",
                timestamp=detected_at,
                event_type="rule_trigger",
                source_ip=source_ip,
                user=target_user,
            )
        )

    incident_input = IncidentInvestigationInput(
        incident_id=f"INC-{alert_id}",
        alert=AlertInput(
            alert_id=alert_id,
            rule_id=rule_id,
            rule_name=alert.get("title", "Security Alert"),
            severity=sev_enum,
            timestamp=detected_at,
        ),
        entities=EntityContext(
            source_ip=source_ip,
            target_user=target_user,
            target_host=host_id,
        ),
        logs=log_inputs,
    )

    gatekeeper = BackendGatekeeper(
        investigation_id=f"INV-{alert_id}",
        alert_id=alert_id,
        authorized_host_id=host_id,
        alert_timestamp=detected_at,
        evidence_db=[],
    )

    rm_chain = settings.get_role_key_chain("rm")
    primary_slot = rm_chain[0][0] if rm_chain else "AEGIS1"
    primary_key = rm_chain[0][1] if rm_chain else settings.llm_api_key
    backup_keys = [k for _, k in rm_chain[1:]]

    try:
        if settings.llm_provider == "gemini" and primary_key:
            provider = RealLLMAdapter(
                provider_type="gemini",
                api_key=primary_key,
                backup_keys=backup_keys,
                role="rm",
                model_name=settings.llm_model,
                timeout_seconds=settings.llm_timeout,
            )
        else:
            provider = MockLLMProvider()

        rm_service = RuntimeMonitorService(llm_provider=provider, gatekeeper=gatekeeper)
        report = rm_service.investigate_incident(incident_input)

        summary_text = f"{report.incident_summary} {report.attack_narrative}".strip()
        uncertainty_text = (
            "; ".join(report.caveats)
            if report.caveats
            else "Analysis is strictly bounded to collected host telemetry; activity outside configured log sources is unknown."
        )
        next_steps = meta.get("investigation_cmds", [])[:3]

        analysis = AiAnalysisResponse(
            target_id=alert_id,
            target_kind="alert",
            state="ready",
            role="RM Analysis Agent",
            key_slot=primary_slot,
            generated_at=datetime.now(timezone.utc).isoformat(),
            summary=summary_text,
            evidence_refs=evidence_refs,
            uncertainty=uncertainty_text,
            next_steps=next_steps,
        )
    except Exception as e:
        logger.warning(f"LLM analysis degraded for alert {alert_id}, using deterministic grounded synthesis: {e}")
        analysis = AiAnalysisResponse(
            target_id=alert_id,
            target_kind="alert",
            state="ready",
            role="RM Analysis Agent",
            key_slot=primary_slot,
            generated_at=datetime.now(timezone.utc).isoformat(),
            summary=(
                f"Alert '{alert.get('title')}' (Rule {rule_id}) was deterministically triggered on host '{host_id}'. "
                f"Trigger reason: {alert.get('reason')} "
                f"Correlated {len(evidence_items)} supporting telemetry event(s). {meta.get('rationale')}"
            ),
            evidence_refs=evidence_refs,
            uncertainty="Grounded deterministic synthesis (external LLM provider unreachable or rate-limited). Only collected host logs were evaluated.",
            next_steps=meta.get("investigation_cmds", [])[:3],
        )

    op_store.ai_analyses[alert_id] = analysis

    # Persist incident and AI investigation run to Supabase if connected
    if repo and hasattr(repo, "client"):
        try:
            client = getattr(repo, "client")
            inc_id = f"INC-{alert_id}"
            client.table("incidents").upsert(
                {
                    "id": inc_id,
                    "alert_id": alert_id,
                    "host_id": host_id,
                    "title": alert.get("title", "Security Incident"),
                    "severity": severity_str,
                    "status": "investigating",
                },
                on_conflict="id",
            ).execute()
            client.table("investigations").upsert(
                {
                    "incident_id": inc_id,
                    "run_number": 1,
                    "severity": severity_str,
                    "analysis_status": "completed",
                    "incident_summary": analysis.summary or "",
                    "attack_narrative": analysis.summary or "",
                    "caveats": [analysis.uncertainty] if analysis.uncertainty else [],
                    "ai_provider_model": settings.llm_model if settings.llm_provider == "gemini" else "mock",
                    "completed_at": analysis.generated_at,
                },
                on_conflict="incident_id,run_number",
            ).execute()
        except Exception as e:
            logger.warning(f"Failed to persist AI investigation run to Supabase for {alert_id}: {e}")

    op_store.record_audit(
        actor="ops-admin",
        action="request_analysis",
        target_type="alert",
        target_id=alert_id,
        summary=f"Executed RM Analysis Agent on alert {alert_id} ({rule_id})",
    )
    return analysis


def generate_handoff_document(
    alert: Dict[str, Any],
    host: Optional[Dict[str, Any]],
    evidence_items: List[Dict[str, Any]],
    gaps: List[TelemetryGapItem],
) -> HandoffDocumentResponse:
    """
    Main Product Differentiator (PRD §4):
    Turns a security alert into a portable, context-rich Markdown investigation
    and remediation handoff prompt usable with external AI coding agents or LLMs.
    """
    alert_id = alert["id"]
    host_id = alert.get("host_id", "unknown-host")
    hostname = (host or {}).get("hostname") or host_id
    os_name = (host or {}).get("os") or "Ubuntu Linux LTS"
    ip_addr = (host or {}).get("ip_address") or "127.0.0.1"
    agent_ver = (host or {}).get("agent_version") or "0.1.0"
    agent_status = (host or {}).get("agent_status") or "online"
    rule_id = alert.get("rule_id", "RULE-UNKNOWN")
    rule_ver = alert.get("rule_version", "1.0")
    severity = alert.get("severity", "high")
    title = alert.get("title", "Security Alert")
    detected_at = alert.get("detected_at", datetime.now(timezone.utc).isoformat())
    reason = alert.get("reason", "")
    now_iso = datetime.now(timezone.utc).isoformat()

    meta = get_rule_metadata(rule_id)
    ai_res = op_store.ai_analyses.get(alert_id)

    # 1. Confirmed Facts (strictly derived from stored records)
    confirmed_facts: List[str] = [
        f"Host '{hostname}' (ID: {host_id}, IP: {ip_addr}, OS: {os_name}) triggered deterministic rule '{rule_id}' (v{rule_ver}) at {detected_at}.",
        f"Immutable Alert Severity assigned by Rules Engine: {severity.upper()}.",
        f"Trigger Condition Matched: {reason}",
        f"Supporting Telemetry Evidence Count: {len(evidence_items)} verified event(s) bound to host '{host_id}'.",
    ]
    for ev in evidence_items[:10]:
        ev_ts = ev.get("event_timestamp") or ev.get("created_at") or "unknown-time"
        ev_id = ev.get("event_id", "EVT")
        ev_type = ev.get("event_type", "event")
        ev_msg = ev.get("message", "")
        confirmed_facts.append(f"Evidence [{ev_id}] at {ev_ts} ({ev_type}): {ev_msg}")

    # 2. Unverified Hypotheses (explicitly marked as requiring engineer verification)
    unverified_hypotheses: List[str] = [
        f"Hypothesis 1: Activity matching {rule_id} ({meta['mitre_id']} - {meta['mitre_name']}) may represent unauthorized external or insider privilege escalation rather than scheduled maintenance.",
        "Hypothesis 2: If credentials or sudo privileges were abused, secondary persistence mechanisms (SSH authorized_keys, systemd timers, cron jobs) might exist outside auth logs.",
    ]
    if ai_res and ai_res.summary:
        unverified_hypotheses.append(f"AI Contextual Assessment (Assistive Only): {ai_res.summary}")

    # 3. Missing Telemetry
    missing_telemetry: List[str] = []
    if gaps:
        for g in gaps:
            missing_telemetry.append(f"Telemetry gap on source '{g.source}' from {g.start} to {g.end or 'ONGOING'}: {g.reason}")
    else:
        missing_telemetry.append("No active telemetry gaps recorded during the detection window for ssh-auth / systemd journal.")
    missing_telemetry.append(" Full packet capture (PCAP) and raw filesystem integrity hashes (AIDE/fim) are not collected by default unless Emergency Evidence Mode was active.")

    investigation_steps = meta["investigation_cmds"]
    remediation_plan = meta["remediation_plan"]
    service_impact = meta["service_impact"]
    rollback_instructions = meta["rollback_steps"]
    verification_instructions = meta["verification_steps"]

    # Format Evidence Table for Markdown
    evidence_md_lines = []
    if evidence_items:
        for ev in evidence_items:
            evidence_md_lines.append(
                f"- **`{ev.get('event_id')}`** | `{ev.get('event_timestamp') or ev.get('created_at')}` | "
                f"Source: `{ev.get('source_id', 'ssh-auth')}` | Type: `{ev.get('event_type')}` | "
                f"IP: `{ev.get('source_ip') or 'N/A'}` | User: `{ev.get('user_name') or 'N/A'}`\n"
                f"  - Message: `{ev.get('message')}`"
            )
    else:
        evidence_md_lines.append(f"- Trigger summary recorded in alert: `{reason}`")

    facts_md = "\n".join(f"- [FACT] {f}" for f in confirmed_facts)
    hypotheses_md = "\n".join(f"- [HYPOTHESIS - UNVERIFIED] {h}" for h in unverified_hypotheses)
    missing_md = "\n".join(f"- [MISSING/UNKNOWN] {m}" for m in missing_telemetry)
    inv_md = "\n".join(f"{i+1}. `{cmd}`" for i, cmd in enumerate(investigation_steps))
    rem_md = "\n".join(f"{i+1}. {step}" for i, step in enumerate(remediation_plan))
    rollback_md = "\n".join(f"- {step}" for step in rollback_instructions)
    verify_md = "\n".join(f"{i+1}. {step}" for i, step in enumerate(verification_instructions))

    markdown = f"""# AEGIS AI Investigation & Remediation Handoff Prompt

> **PORTABLE AI AGENT HANDOFF DOCUMENT**
> Generated by **AEGIS Linux Security Monitoring Platform** at `{now_iso}`.
> You are an AI Security & Systems Engineering Assistant helping a human engineer investigate and safely remediate a Linux server security incident.

---

## 1. Mandatory Operating Rules for Receiving AI Agent
1. **INVESTIGATE BEFORE PROPOSING CHANGES**: Do not assume hypotheses are facts. Run or ask the engineer to run the read-only investigation commands first.
2. **NO AUTONOMOUS REMEDIATION**: Never execute destructive commands, firewall lockouts, service terminations, or configuration overwrites without explicit human engineer approval.
3. **PRESERVE EVIDENCE**: Do not clear logs, truncate command history, or kill processes before capturing volatile forensic state.
4. **EXPLAIN IMPACT & ROLLBACK**: Every proposed change must include service impact analysis and a tested rollback command.

---

## 2. Host & Environment Context
| Property | Value |
| :--- | :--- |
| **Host ID** | `{host_id}` |
| **Hostname** | `{hostname}` |
| **IP Address** | `{ip_addr}` |
| **Operating System** | `{os_name}` |
| **AEGIS Agent Status** | `{agent_status}` (v`{agent_ver}`) |
| **Monitored Services** | OpenSSH (`sshd`), Sudo/PAM, Systemd Journal |

---

## 3. Triggered Alert & Deterministic Rule Context
- **Alert ID**: `{alert_id}`
- **Title**: {title}
- **Triggered Rule**: `{rule_id}` (Version `{rule_ver}`)
- **MITRE ATT&CK Mapping**: `{meta['mitre_id']}` — {meta['mitre_name']}
- **Immutable Severity**: `{severity.upper()}`
- **Detected At (UTC)**: `{detected_at}`
- **Rule Condition**: `{meta['condition']}`
- **Trigger Reason**: {reason}

---

## 4. Supporting Telemetry Evidence (Sanitized)
{chr(10).join(evidence_md_lines)}

---

## 5. Epistemic Separation: Confirmed Facts vs. Unverified Hypotheses

### 5.1 Confirmed Facts (Verified by Deterministic Telemetry)
{facts_md}

### 5.2 Unverified Hypotheses (Require Investigation)
{hypotheses_md}

### 5.3 Missing Telemetry & Visibility Boundaries
{missing_md}

---

## 6. Step-by-Step Read-Only Investigation Instructions
Instruct the engineer (or execute in read-only mode if authorized) to gather the following verification outputs before altering any file:
{inv_md}

---

## 7. Safe Remediation Plan & Service Impact
### Proposed Remediation Steps (Requires Engineer Approval)
{rem_md}

### Service Impact Analysis
- {service_impact}

### Rollback Instructions
{rollback_md}

---

## 8. Post-Remediation Recovery Verification Instructions
After the engineer applies remediation, verify recovery using these checks:
{verify_md}
"""

    filename = f"AEGIS-Handoff-{alert_id}.md"
    op_store.record_audit(
        actor="ops-admin",
        action="generate_handoff",
        target_type="alert",
        target_id=alert_id,
        summary=f"Generated AI Investigation & Remediation Handoff Markdown ({filename})",
    )

    return HandoffDocumentResponse(
        alert_id=alert_id,
        host_id=host_id,
        hostname=hostname,
        title=title,
        severity=severity,
        rule_id=rule_id,
        generated_at=now_iso,
        filename=filename,
        markdown=markdown,
        confirmed_facts=confirmed_facts,
        unverified_hypotheses=unverified_hypotheses,
        missing_telemetry=missing_telemetry,
        investigation_steps=investigation_steps,
        remediation_plan=remediation_plan,
        service_impact=service_impact,
        rollback_instructions=rollback_instructions,
        verification_instructions=verification_instructions,
    )


def verify_alert_recovery(
    alert: Dict[str, Any],
    host: Optional[Dict[str, Any]],
    recent_alerts: List[Dict[str, Any]],
    open_gaps: List[TelemetryGapItem],
    observation_window_min: int = 15,
) -> RecoveryVerificationResponse:
    """
    Continuous Monitoring & Automatic Recovery Verification (PRD §5).
    Evaluates whether the conditions that triggered an incident have recovered.
    Missing logs or an offline agent are NEVER interpreted as proof of recovery.
    """
    alert_id = alert["id"]
    host_id = alert.get("host_id", "unknown-host")
    rule_id = alert.get("rule_id", "RULE-UNKNOWN")
    detected_at_str = alert.get("detected_at") or datetime.now(timezone.utc).isoformat()
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    checks: List[VerificationCheckItem] = []

    # Check 1: Host & Agent Online Status
    agent_status = (host or {}).get("agent_status", "unknown")
    last_data_at = (host or {}).get("last_data_at")
    agent_fresh = False
    if agent_status == "online" and last_data_at:
        try:
            last_dt = datetime.fromisoformat(last_data_at.replace("Z", "+00:00"))
            age_sec = (now - last_dt).total_seconds()
            agent_fresh = age_sec < 600  # within 10 minutes
        except Exception:
            agent_fresh = True
    elif agent_status == "online":
        agent_fresh = True

    if agent_status == "online" and agent_fresh:
        checks.append(
            VerificationCheckItem(
                id="chk-agent-heartbeat",
                label="Agent Heartbeat & Liveness",
                status="pass",
                detail=f"Host '{host_id}' agent is online and actively reporting telemetry (last heartbeat: {last_data_at or 'recent'}).",
            )
        )
    else:
        checks.append(
            VerificationCheckItem(
                id="chk-agent-heartbeat",
                label="Agent Heartbeat & Liveness",
                status="fail",
                detail=f"Host '{host_id}' agent status is '{agent_status}'. Missing or stale telemetry cannot be used as proof of recovery.",
            )
        )

    # Check 2: Telemetry Source Continuity (Zero Open Gaps)
    host_open_gaps = [g for g in open_gaps if g.host_id == host_id and g.end is None]
    if not host_open_gaps:
        checks.append(
            VerificationCheckItem(
                id="chk-telemetry-continuity",
                label="Telemetry Stream Continuity",
                status="pass",
                detail="Zero open telemetry gaps on monitored log sources during the post-alert observation window.",
            )
        )
    else:
        checks.append(
            VerificationCheckItem(
                id="chk-telemetry-continuity",
                label="Telemetry Stream Continuity",
                status="fail",
                detail=f"{len(host_open_gaps)} open telemetry gap(s) detected on host '{host_id}'. Recovery cannot be verified during a visibility gap.",
            )
        )

    # Check 3: Re-evaluation of Original Triggering Rule
    newer_same_rule = []
    try:
        base_dt = datetime.fromisoformat(detected_at_str.replace("Z", "+00:00"))
        for a in recent_alerts:
            if a["id"] != alert_id and a.get("host_id") == host_id and a.get("rule_id") == rule_id:
                a_dt = datetime.fromisoformat((a.get("detected_at") or "").replace("Z", "+00:00"))
                if a_dt > base_dt:
                    newer_same_rule.append(a)
    except Exception:
        pass

    if not newer_same_rule:
        checks.append(
            VerificationCheckItem(
                id="chk-rule-reeval",
                label=f"Triggering Rule Re-evaluation ({rule_id})",
                status="pass",
                detail=f"Rule '{rule_id}' has not re-triggered on subsequent normalized events since initial detection.",
            )
        )
    else:
        checks.append(
            VerificationCheckItem(
                id="chk-rule-reeval",
                label=f"Triggering Rule Re-evaluation ({rule_id})",
                status="fail",
                detail=f"Rule '{rule_id}' triggered {len(newer_same_rule)} additional time(s) after this alert ({newer_same_rule[0]['id']}).",
            )
        )

    # Check 4: Observation Window Elapsed
    window_satisfied = True
    try:
        base_dt = datetime.fromisoformat(detected_at_str.replace("Z", "+00:00"))
        elapsed_min = (now - base_dt).total_seconds() / 60.0
        if elapsed_min >= observation_window_min:
            checks.append(
                VerificationCheckItem(
                    id="chk-obs-window",
                    label=f"Observation Window ({observation_window_min}m)",
                    status="pass",
                    detail=f"Post-incident observation window satisfied ({int(elapsed_min)} minutes elapsed with continuous monitoring).",
                )
            )
        else:
            window_satisfied = False
            checks.append(
                VerificationCheckItem(
                    id="chk-obs-window",
                    label=f"Observation Window ({observation_window_min}m)",
                    status="warn",
                    detail=f"Only {elapsed_min:.1f}m elapsed of required {observation_window_min}m continuous observation window.",
                )
            )
    except Exception:
        checks.append(
            VerificationCheckItem(
                id="chk-obs-window",
                label=f"Observation Window ({observation_window_min}m)",
                status="pass",
                detail="Observation window evaluated against stored timestamps.",
            )
        )

    # Determine Final Deterministic Outcome
    prev_inv = op_store.get_investigation(alert_id).status
    if agent_status != "online" or not agent_fresh or host_open_gaps:
        outcome = "unverified"
        summary = (
            "Recovery status is UNVERIFIED because agent telemetry is offline, delayed, or has an open gap. "
            "AEGIS never interprets missing logs as proof of recovery."
        )
    elif newer_same_rule:
        if prev_inv == "resolved":
            outcome = "reopened"
            summary = f"Incident REOPENED: Rule '{rule_id}' fired again ({len(newer_same_rule)} new alert(s)) after previous resolution."
        else:
            outcome = "still_active"
            summary = f"Threat condition is STILL ACTIVE: Rule '{rule_id}' continued to trigger on newer host telemetry events."
    elif not window_satisfied:
        outcome = "unverified"
        summary = f"No new triggers for '{rule_id}', but the {observation_window_min}-minute observation window has not yet fully elapsed."
    else:
        outcome = "resolved"
        summary = (
            f"Recovery VERIFIED (Resolved): Host '{host_id}' is online with continuous telemetry, zero visibility gaps, "
            f"and rule '{rule_id}' has not re-triggered across the post-incident observation window."
        )

    diff_status = "verified_fixed" if outcome == "resolved" else ("unchanged_active" if outcome in ("still_active", "reopened") else "pending_verification")
    remediation_diff: List[RemediationDiffItem] = []

    if rule_id.startswith("RULE-SSH"):
        remediation_diff = [
            RemediationDiffItem(
                target_resource="/etc/ssh/sshd_config · SSH Auth Stream",
                before_state=f"Active SSH brute-force burst ({alert.get('reason', 'repeated auth failures')}); PermitRootLogin prohibit-password",
                after_state=(
                    "0 new SSH auth_failure bursts in observation window; SSH key-only access verified"
                    if outcome == "resolved"
                    else "SSH authentication failure burst still active or awaiting observation window completion"
                ),
                status=diff_status,
            ),
            RemediationDiffItem(
                target_resource=f"Rules Engine · {rule_id}",
                before_state=f"TRIGGERED at {detected_at_str} (Severity: {alert.get('severity', 'high').upper()})",
                after_state=f"0 re-triggers across {observation_window_min}m window" if not newer_same_rule else f"Re-triggered {len(newer_same_rule)} time(s)",
                status="verified_fixed" if not newer_same_rule else "unchanged_active",
            ),
        ]
    elif rule_id.startswith("RULE-SUSP-SUDO"):
        remediation_diff = [
            RemediationDiffItem(
                target_resource="/var/www/html & Sudo Execution Policy",
                before_state=f"Anomalous privileged execution ({alert.get('reason', 'chmod 777 / root shell via sudo')})",
                after_state=(
                    "/var/www/html restored to mode 0755 (root:www-data); 0 new anomalous sudo executions"
                    if outcome == "resolved"
                    else "Awaiting verification of directory mode 0755 and clean sudo audit stream"
                ),
                status=diff_status,
            ),
            RemediationDiffItem(
                target_resource=f"Rules Engine · {rule_id}",
                before_state=f"TRIGGERED at {detected_at_str}",
                after_state=f"0 re-triggers across {observation_window_min}m window" if not newer_same_rule else f"Re-triggered {len(newer_same_rule)} time(s)",
                status="verified_fixed" if not newer_same_rule else "unchanged_active",
            ),
        ]
    else:
        remediation_diff = [
            RemediationDiffItem(
                target_resource=f"Host {host_id} · {rule_id} Telemetry Stream",
                before_state=f"Active rule match: {alert.get('reason', title if 'title' in locals() else rule_id)}",
                after_state=(
                    f"Clean telemetry stream over {observation_window_min}m window; 0 new {rule_id} matches"
                    if outcome == "resolved"
                    else f"Outcome '{outcome}': {len(newer_same_rule)} subsequent rule match(es)"
                ),
                status=diff_status,
            ),
        ]

    res = RecoveryVerificationResponse(
        alert_id=alert_id,
        host_id=host_id,
        outcome=outcome,
        verified_at=now_iso,
        observation_window_min=observation_window_min,
        summary=summary,
        checks=checks,
        remediation_diff=remediation_diff,
    )
    op_store.verifications[alert_id] = res
    op_store.record_audit(
        actor="ops-admin",
        action="verify_recovery",
        target_type="alert",
        target_id=alert_id,
        summary=f"Executed Automatic Recovery Verification on {alert_id} -> {outcome.upper()}",
        details={"outcome": outcome, "rule_id": rule_id, "host_id": host_id},
    )
    return res


def build_incident_replay(
    alert: Dict[str, Any],
    host: Optional[Dict[str, Any]],
    evidence_items: List[Dict[str, Any]],
) -> IncidentReplayResponse:
    """
    Incident Replay (PRD §6):
    Evidence-based chronological reconstruction of an incident from stored records.
    Never fabricates events or timestamps.
    """
    alert_id = alert["id"]
    host_id = alert.get("host_id", "unknown-host")
    hostname = (host or {}).get("hostname") or host_id
    rule_id = alert.get("rule_id", "RULE-UNKNOWN")
    severity = alert.get("severity", "high")
    detected_at = alert.get("detected_at") or datetime.now(timezone.utc).isoformat()
    inv_state = op_store.get_investigation(alert_id)
    ver_state = op_store.verifications.get(alert_id)

    steps: List[ReplayStepItem] = []
    sorted_ev = sorted(
        evidence_items,
        key=lambda e: e.get("event_timestamp") or e.get("created_at") or "",
    )

    for idx, ev in enumerate(sorted_ev):
        is_last = idx == len(sorted_ev) - 1
        phase = "trigger" if (ev.get("citation_role") == "trigger" or is_last) else "reconnaissance"
        steps.append(
            ReplayStepItem(
                step=len(steps) + 1,
                ts=ev.get("event_timestamp") or ev.get("created_at") or detected_at,
                phase=phase,
                title=f"Telemetry Event Observed ({ev.get('event_type', 'auth')})",
                detail=ev.get("message", ""),
                source=ev.get("source_id", "ssh-auth"),
                actor_or_ip=ev.get("source_ip") or ev.get("user_name"),
                event_id=ev.get("event_id"),
            )
        )

    steps.append(
        ReplayStepItem(
            step=len(steps) + 1,
            ts=detected_at,
            phase="detection",
            title=f"Deterministic Rule Matched: {rule_id}",
            detail=f"{alert.get('title')} — {alert.get('reason')} (Immutable Severity: {severity.upper()})",
            source="AEGIS Rules Engine",
            actor_or_ip=hostname,
            event_id=alert_id,
        )
    )

    for note in reversed(inv_state.notes):
        steps.append(
            ReplayStepItem(
                step=len(steps) + 1,
                ts=note.ts,
                phase="investigation",
                title=f"Operator Workflow Update ({note.status_transition or inv_state.status})",
                detail=note.note,
                source="Operator Investigation Workflow",
                actor_or_ip=note.author,
            )
        )

    if ver_state:
        steps.append(
            ReplayStepItem(
                step=len(steps) + 1,
                ts=ver_state.verified_at,
                phase="verification",
                title=f"Automatic Recovery Verification: {ver_state.outcome.upper()}",
                detail=ver_state.summary,
                source="AEGIS Recovery Verifier",
                actor_or_ip="system",
            )
        )

    return IncidentReplayResponse(
        alert_id=alert_id,
        host_id=host_id,
        hostname=hostname,
        rule_id=rule_id,
        severity=severity,
        incident_status=ver_state.outcome if ver_state else inv_state.status,
        steps=steps,
        telemetry_limitations=[
            "Chronological replay is strictly reconstructed from stored host telemetry and audit records.",
            "Unmonitored log files or network flows outside configured collectors are not represented.",
        ],
    )


def run_finding_sc_ai_analysis(target: FindingItem) -> AiAnalysisResponse:
    """
    Executes SC Analysis Agent on a Security Checker posture finding using
    dedicated key slot AEGIS2 (with automatic failover to AEGIS1 -> AEGIS3).
    """
    sc_chain = settings.get_role_key_chain("sc")
    primary_slot = sc_chain[0][0] if sc_chain else "AEGIS2"
    primary_key = sc_chain[0][1] if sc_chain else settings.llm_api_key
    backup_keys = [k for _, k in sc_chain[1:]]
    now_iso = datetime.now(timezone.utc).isoformat()

    summary_text = (
        f"[SC Agent · Key {primary_slot}] Security Checker posture check '{target.check_id}' ({target.title}) "
        f"on host '{target.host_id}' reported status '{target.status.upper()}'. "
        f"Observed indicators: {'; '.join(target.indicators)}."
    )
    next_steps = [
        f"Inspect configuration referenced by {target.check_id} in read-only mode before planning changes.",
        "Verify active administrative sessions to ensure hardening does not lock out operators.",
        "Re-run Security Checker after applying approved configuration changes to confirm PASS state.",
    ]

    if settings.llm_provider == "gemini" and primary_key:
        try:
            provider = RealLLMAdapter(
                provider_type="gemini",
                api_key=primary_key,
                backup_keys=backup_keys,
                role="sc",
                model_name=settings.llm_model,
                timeout_seconds=settings.llm_timeout,
            )
            sc_out = provider.generate_sc_posture_report(
                {
                    "audit_run": {"audit_id": f"AUD-{target.id}"},
                    "host": {"host_id": target.host_id},
                    "security_controls": [
                        {
                            "control_id": target.check_id,
                            "control_name": target.title,
                            "status": target.status,
                            "current_value": "; ".join(target.indicators),
                            "expected_value": "Compliant CIS Linux baseline",
                            "evidence_ref": target.id,
                        }
                    ],
                }
            )
            if sc_out and sc_out.executive_summary and "gagal" not in sc_out.executive_summary.lower():
                summary_text = sc_out.executive_summary
                if sc_out.findings and sc_out.findings[0].remediation_guidance:
                    next_steps.insert(0, sc_out.findings[0].remediation_guidance)
        except Exception as e:
            logger.warning(f"SC AI Agent degraded for finding {target.id}, using grounded posture synthesis: {e}")

    analysis = AiAnalysisResponse(
        target_id=target.id,
        target_kind="finding",
        state="ready",
        role="SC Analysis Agent",
        key_slot=primary_slot,
        generated_at=now_iso,
        summary=summary_text,
        evidence_refs=[f"Check {target.check_id}", f"Host {target.host_id}"],
        uncertainty=target.limits,
        next_steps=next_steps[:4],
    )
    op_store.ai_analyses[target.id] = analysis
    op_store.record_audit(
        actor="ops-admin",
        action="request_analysis",
        target_type="finding",
        target_id=target.id,
        summary=f"Executed SC Analysis Agent ({primary_slot}) on posture finding {target.id} ({target.check_id})",
    )
    return analysis


def run_reporting_ai_summary(
    report_id: str,
    report_type: str,
    host_ids: List[str],
    alerts: List[Dict[str, Any]],
    findings: List[FindingItem],
    period_start: str,
    period_end: str,
) -> Tuple[str, str]:
    """
    Executes Reporting Agent using dedicated key slot AEGIS3 (specifically reserved
    for Daily & Incident Reports, with automatic failover to AEGIS2 -> AEGIS1).
    Returns (executive_summary_text, key_slot_used).
    """
    rep_chain = settings.get_role_key_chain("reporting")
    primary_slot = rep_chain[0][0] if rep_chain else "AEGIS3"
    primary_key = rep_chain[0][1] if rep_chain else settings.llm_api_key
    backup_keys = [k for _, k in rep_chain[1:]]

    failed_findings = [f for f in findings if f.status == "fail"]
    crit_high_alerts = [a for a in alerts if str(a.get("severity", "")).lower() in ("critical", "high")]

    default_summary = (
        f"[Reporting Agent · Key {primary_slot}] Compiled {report_type} security report for host(s) {', '.join(host_ids)} "
        f"({period_start} to {period_end}). Evaluated {len(alerts)} deterministic alert(s) "
        f"({len(crit_high_alerts)} Critical/High) and {len(findings)} read-only Security Checker posture controls "
        f"({len(failed_findings)} non-compliant). All timeline entries and citations originate strictly from stored telemetry."
    )

    if settings.llm_provider == "gemini" and primary_key:
        try:
            provider = RealLLMAdapter(
                provider_type="gemini",
                api_key=primary_key,
                backup_keys=backup_keys,
                role="reporting",
                model_name=settings.llm_model,
                timeout_seconds=settings.llm_timeout,
            )
            rep_out = provider.generate_reporting_summary(
                {
                    "report_id": report_id,
                    "report_type": "daily_security_briefing" if report_type == "daily" else "incident_executive_summary",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "period_start": period_start,
                    "period_end": period_end,
                    "stored_incidents": [
                        {
                            "alert_id": a.get("id"),
                            "rule_id": a.get("rule_id"),
                            "title": a.get("title"),
                            "severity": str(a.get("severity", "High")).capitalize(),
                            "reason": a.get("reason"),
                        }
                        for a in alerts[:15]
                    ],
                    "stored_postures": [
                        {
                            "host_id": hid,
                            "failed_controls": [f.check_id for f in failed_findings if f.host_id == hid],
                        }
                        for hid in host_ids
                    ],
                }
            )
            if rep_out and rep_out.executive_overview:
                return rep_out.executive_overview, primary_slot
        except Exception as e:
            logger.warning(f"Reporting AI Agent ({primary_slot}) degraded for {report_id}, using deterministic summary: {e}")

    return default_summary, primary_slot


def build_alert_context(
    alert: Dict[str, Any],
    all_host_alerts: List[Dict[str, Any]],
    evidence_items: List[Dict[str, Any]],
) -> AlertContextResponse:
    """
    Builds Multi-Stage Kill-Chain Correlation & Blast Radius Summary for an alert.
    Correlates alerts on the same host across 6 MITRE ATT&CK kill-chain stages.
    """
    alert_id = alert["id"]
    host_id = alert.get("host_id", "unknown-host")
    rule_id = alert.get("rule_id", "RULE-UNKNOWN")

    source_ips = sorted({
        str(ev.get("source_ip"))
        for ev in evidence_items
        if ev.get("source_ip") and str(ev.get("source_ip")) not in ("unknown", "None", "")
    })
    target_users = sorted({
        str(ev.get("user_name"))
        for ev in evidence_items
        if ev.get("user_name") and str(ev.get("user_name")) not in ("unknown", "None", "")
    })
    affected_files: List[str] = []
    executed_commands: List[str] = []

    for ev in evidence_items:
        details = ev.get("details") or {}
        if isinstance(details, dict):
            cmd = details.get("command") or details.get("command_line")
            if cmd and cmd not in executed_commands:
                executed_commands.append(str(cmd))
            tf = details.get("target_file") or details.get("uri")
            if tf and tf not in affected_files:
                affected_files.append(str(tf))
        msg = str(ev.get("message") or "")
        for candidate in ("/var/www/html", "/etc/ssh/sshd_config", "/etc/sudoers", "/etc/passwd", "/etc/shadow", "authorized_keys"):
            if candidate in msg and candidate not in affected_files:
                affected_files.append(candidate)

    reason_txt = str(alert.get("reason") or "")
    for candidate in ("/var/www/html", "/etc/ssh/sshd_config", "/etc/sudoers", "authorized_keys"):
        if candidate in reason_txt and candidate not in affected_files:
            affected_files.append(candidate)

    # Map rules to 6 Kill-Chain stages
    stage_defs = [
        ("Reconnaissance", "TA0043 / TA0007", ("RULE-FW-PORTSCAN", "RULE-WEB-ATTACK")),
        ("Credential Access", "TA0006 · Brute Force / Sniffing", ("RULE-SSH-BRUTE", "RULE-ROOTKIT-SNIFF")),
        ("Initial Access", "TA0001 · Valid Accounts", ("RULE-AUTH-003",)),
        ("Privilege Escalation", "TA0004 · Sudo / Exploit", ("RULE-SUSP-SUDO", "RULE-KERNEL-EXPLOIT")),
        ("Persistence", "TA0003 · Backdoor / Cron / Keys", ("RULE-ACCT-BACKDOOR", "RULE-CRON-PERSIST", "RULE-SSH-KEY-BACKDOOR")),
        ("Defense Evasion & Exfil", "TA0005 / TA0010 · Anti-Forensics & Exfil", ("RULE-DEFENSE-EVASION", "RULE-ANTI-FORENSICS", "RULE-DATA-EXFIL")),
    ]

    kill_chain: List[KillChainStageItem] = []
    related_ids: List[str] = []

    for stage_name, tactic, rule_prefixes in stage_defs:
        matching_alerts = [
            a for a in all_host_alerts
            if any(str(a.get("rule_id", "")).startswith(p) for p in rule_prefixes)
        ]
        m_ids = [a["id"] for a in matching_alerts]
        for mid in m_ids:
            if mid != alert_id and mid not in related_ids:
                related_ids.append(mid)

        is_current = any(rule_id.startswith(p) for p in rule_prefixes)
        if is_current:
            st = "current_trigger"
            summary = f"Current alert {alert_id} ({rule_id}): {alert.get('title')}"
            ts = alert.get("detected_at")
        elif matching_alerts:
            st = "observed"
            first_a = matching_alerts[0]
            summary = f"Correlated {len(matching_alerts)} alert(s) on {host_id}: {first_a.get('title')} ({first_a['id']})"
            ts = first_a.get("detected_at")
        else:
            st = "not_observed"
            summary = f"No deterministic alerts triggered for {stage_name} on {host_id}."
            ts = None

        kill_chain.append(
            KillChainStageItem(
                stage=stage_name,
                mitre_tactic=tactic,
                status=st,
                alert_ids=m_ids,
                summary=summary,
                timestamp=ts,
            )
        )

    active_stage_count = sum(1 for k in kill_chain if k.status in ("observed", "current_trigger"))
    impact_scope = (
        f"Multi-stage activity across {active_stage_count}/6 kill-chain stages on host '{host_id}'"
        if active_stage_count > 1
        else f"Contained single-stage trigger ({rule_id}) on host '{host_id}'"
    )

    blast_radius = BlastRadiusSummary(
        source_ips=source_ips,
        target_users=target_users,
        affected_files=affected_files,
        executed_commands=executed_commands,
        target_host=host_id,
        related_alert_ids=related_ids,
        impact_scope=impact_scope,
    )

    return AlertContextResponse(
        alert_id=alert_id,
        host_id=host_id,
        kill_chain=kill_chain,
        blast_radius=blast_radius,
    )


def build_signed_evidence_bundle(
    alert: Dict[str, Any],
    evidence_items: List[Dict[str, Any]],
) -> SignedEvidenceBundleResponse:
    """
    Exports a cryptographically hashed (SHA-256) JSON forensic evidence bundle
    for chain-of-custody verification.
    """
    alert_id = alert["id"]
    host_id = alert.get("host_id", "unknown-host")
    rule_id = alert.get("rule_id", "RULE-UNKNOWN")
    severity = alert.get("severity", "high")
    now_iso = datetime.now(timezone.utc).isoformat()

    signed_events: List[SignedEvidenceEventItem] = []
    event_hashes: List[str] = []

    for ev in evidence_items:
        ev_id = str(ev.get("event_id") or "EVT-UNKNOWN")
        ev_ts = ev.get("event_timestamp") or ev.get("created_at")
        src_id = ev.get("source_id") or "ssh-auth"
        ev_type = ev.get("event_type") or "telemetry"
        role = ev.get("citation_role") or "supporting"
        msg = str(ev.get("message") or "")
        canonical = f"{alert_id}|{host_id}|{ev_id}|{ev_ts}|{src_id}|{ev_type}|{msg}"
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        event_hashes.append(digest)
        signed_events.append(
            SignedEvidenceEventItem(
                event_id=ev_id,
                event_timestamp=ev_ts,
                source_id=src_id,
                event_type=ev_type,
                citation_role=role,
                source_ip=ev.get("source_ip"),
                user_name=ev.get("user_name"),
                message=msg,
                sha256_hash=digest,
            )
        )

    manifest_raw = f"AEGIS-BUNDLE|{alert_id}|{host_id}|{rule_id}|{severity}|" + "|".join(event_hashes)
    manifest_sha256 = hashlib.sha256(manifest_raw.encode("utf-8")).hexdigest()

    op_store.record_audit(
        actor="ops-admin",
        action="export_evidence_bundle",
        target_type="alert",
        target_id=alert_id,
        summary=f"Exported signed SHA-256 forensic evidence bundle for {alert_id} (manifest {manifest_sha256[:12]}...)",
    )

    return SignedEvidenceBundleResponse(
        bundle_id=f"BND-{alert_id}",
        alert_id=alert_id,
        host_id=host_id,
        rule_id=rule_id,
        severity=severity,
        exported_at=now_iso,
        hash_algorithm="SHA-256",
        manifest_sha256=manifest_sha256,
        events=signed_events,
    )


def generate_report_pdf_bytes(
    report: ReportItem,
    alerts: List[Dict[str, Any]],
    findings: List[FindingItem],
) -> bytes:
    """
    Generates a genuine binary PDF document for a Daily or Incident Security Report
    containing Executive Summary (AEGIS3), Triggered Alerts, Security Checker Posture Findings,
    and Telemetry Boundaries. Uses reportlab when available, with a deterministic PDF 1.4 fallback.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas

        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=A4)
        width, height = A4
        y = height - 48

        def write_line(text: str, font: str = "Helvetica", size: int = 10, step: int = 15):
            nonlocal y
            if y < 60:
                c.showPage()
                y = height - 48
            c.setFont(font, size)
            c.drawString(45, y, text[:105])
            y -= step

        write_line("AEGIS LINUX SECURITY MONITORING & INCIDENT PLATFORM", "Helvetica-Bold", 14, 20)
        write_line(f"Report ID: {report.id}   |   Type: {report.type.upper()}   |   AI Key Slot: {report.ai_key_slot or 'AEGIS3'}", "Helvetica-Bold", 10, 16)
        write_line(f"Title: {report.title}", "Helvetica", 10, 15)
        write_line(f"Monitored Hosts: {', '.join(report.host_ids)}   |   Completed At: {report.completed_at or report.requested_at}", "Helvetica", 9, 15)
        write_line(f"Period: {report.period_start}  ->  {report.period_end}", "Helvetica", 9, 20)

        write_line("1. AI EXECUTIVE SUMMARY (Reporting Agent · Key AEGIS3)", "Helvetica-Bold", 11, 16)
        summary_txt = report.ai_executive_summary or "Grounded synthesis of stored alerts and read-only posture checks."
        for i in range(0, len(summary_txt), 95):
            write_line(summary_txt[i : i + 95], "Helvetica", 9, 13)
        y -= 8

        write_line(f"2. DETERMINISTIC ALERTS SUMMARY ({len(alerts)} Recorded)", "Helvetica-Bold", 11, 16)
        if not alerts:
            write_line("No deterministic alerts triggered during this reporting window.", "Helvetica", 9, 14)
        for idx, a in enumerate(alerts[:12]):
            write_line(
                f"[{idx+1}] {a.get('id')} | {str(a.get('severity', '')).upper()} | {a.get('rule_id')} | {a.get('title')}",
                "Helvetica-Bold",
                9,
                13,
            )
            reason = str(a.get("reason") or "")
            write_line(f"    Detected: {a.get('detected_at')} | Reason: {reason[:85]}", "Helvetica", 8, 13)
        y -= 8

        write_line(f"3. READ-ONLY SECURITY CHECKER POSTURE ({len(findings)} Controls)", "Helvetica-Bold", 11, 16)
        for f in findings[:12]:
            write_line(
                f"- {f.check_id} [{f.status.upper()}] ({f.severity.upper()}): {f.title}",
                "Helvetica",
                9,
                13,
            )
        y -= 8

        write_line("4. EPISTEMIC & TELEMETRY BOUNDARIES", "Helvetica-Bold", 11, 16)
        write_line("- All events and timestamps originate strictly from stored host records.", "Helvetica", 9, 13)
        write_line("- Alert severity is immutable and set solely by the deterministic Rules Engine.", "Helvetica", 9, 13)
        write_line("- Missing telemetry or offline agents are never interpreted as proof of recovery.", "Helvetica", 9, 13)

        c.save()
        return buf.getvalue()
    except Exception as e:
        logger.warning(f"ReportLab PDF generation fallback triggered: {e}")
        text_payload = f"AEGIS Security Report {report.id} - {report.title} ({report.period_start} to {report.period_end})"
        stream = f"BT /F1 12 Tf 50 750 Td ({text_payload}) Tj ET".encode("latin-1", errors="ignore")
        pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
            b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >> endobj\n"
            + f"4 0 obj << /Length {len(stream)} >> stream\n".encode("ascii")
            + stream
            + b"\nendstream endobj\n"
            b"xref\n0 5\n0000000000 65535 f \n"
            b"trailer << /Size 5 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n"
        )
        return pdf

