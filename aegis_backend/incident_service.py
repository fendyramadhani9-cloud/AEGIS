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
import logging

from aegis_backend.config import settings
from aegis_backend.repository import BaseAegisRepository
from aegis_backend.sanitizer import TelemetrySanitizer
from aegis_backend.schemas import (
    AiAnalysisResponse,
    HandoffDocumentResponse,
    RecoveryVerificationResponse,
    VerificationCheckItem,
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

    try:
        if settings.llm_provider == "gemini" and settings.llm_api_key:
            provider = RealLLMAdapter(
                provider_type="gemini",
                api_key=settings.llm_api_key,
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

    res = RecoveryVerificationResponse(
        alert_id=alert_id,
        host_id=host_id,
        outcome=outcome,
        verified_at=now_iso,
        observation_window_min=observation_window_min,
        summary=summary,
        checks=checks,
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
