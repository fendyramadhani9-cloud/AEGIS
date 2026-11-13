"""
Telemetry Ingestion Endpoint for AEGIS Backend.
Handles authenticated batch log submission from Linux agent nodes (Ubuntu LTS).
Enforces constant-time token authentication, pre-parsing secret redaction,
schema normalization, host upsert, and duplicate-safe storage.
"""

from fastapi import APIRouter, Depends, Header, HTTPException, status
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import hmac
import logging

from aegis_backend.config import settings
from aegis_backend.schemas import (
    TelemetryIngestRequest,
    TelemetryIngestResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    PostureIngestRequest,
    PostureIngestResponse,
    FindingItem,
    ErrorResponse,
)
from aegis_backend.incident_service import op_store
from aegis_backend.repository import BaseAegisRepository, get_repository
from aegis_backend.tenancy import authenticate_agent_token, claim_host_for_agent
from aegis_backend.sanitizer import TelemetrySanitizer
from aegis_backend.guardian import guardian_engine
from aegis_agent.pipeline_adapter import LinuxLogPipelineAdapter
from aegis_backend.rules_engine import RulesEngine

logger = logging.getLogger("aegis_backend.telemetry")

router = APIRouter(prefix="/api/telemetry", tags=["Telemetry Ingestion"])


def verify_agent_token(
    x_agent_token: Optional[str] = Header(None, alias="X-Agent-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    """
    Validates the agent ingestion token (constant-time) and returns the tenant it belongs to.
    - Tenant-scoped tokens (scripts/manage_auth.py) map to their own tenant.
    - The legacy global AGENT_INGEST_TOKEN maps to the default tenant.
    Supports either X-Agent-Token header or Authorization: Bearer <token>.
    Never logs or echoes the raw token.
    """
    token = x_agent_token
    if not token and authorization:
        parts = authorization.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1].strip()
        else:
            token = authorization.strip()
    return authenticate_agent_token(token)


def _build_safe_event_message(ev_type: str, user: Optional[str], src_ip: Optional[str], details: Dict[str, Any]) -> str:
    """Constructs a clean, non-sensitive human-readable message for telemetry_events."""
    u = user or "unknown"
    ip = src_ip or "unknown"
    if ev_type == "auth_failure":
        port = details.get("source_port", "")
        return f"Failed SSH authentication for user '{u}' from {ip}{f':{port}' if port else ''}."
    if ev_type == "auth_success":
        method = details.get("auth_method", "password")
        return f"Accepted SSH login ({method}) for user '{u}' from {ip}."
    if ev_type == "session_opened":
        return f"PAM session opened for user '{u}'."
    if ev_type == "session_closed":
        return f"PAM session closed for user '{u}'."
    if ev_type == "process_execution":
        proc = details.get("process_name", "unknown")
        pid = details.get("pid", "unknown")
        return f"Process executed: {proc} (pid: {pid})."
    if ev_type == "process_cmdline":
        cmd = details.get("command_line", "unknown")
        return f"Command line arguments: {cmd}"
    if ev_type == "network_connection":
        state = details.get("connection_state", "ESTAB")
        r_port = details.get("remote_port", "")
        return f"TCP network connection {state} with {ip}{f':{r_port}' if r_port else ''}."
    if ev_type in ("sudo_execution", "sudo_auth_failure"):
        cmd = details.get("command", "unknown")
        return f"Sudo event ({ev_type}) for user '{u}': {cmd}"
    if ev_type in ("account_created", "privilege_group_added", "password_changed"):
        grp = details.get("group", "")
        return f"Account management event ({ev_type}) for user '{u}'{f' (group: {grp})' if grp else ''}."
    if ev_type == "firewall_block":
        dport = details.get("dest_port", "unknown")
        proto = details.get("protocol", "TCP")
        return f"UFW blocked inbound {proto} packet from {ip} to port {dport}."
    if ev_type == "kernel_segfault":
        proc = details.get("process_name", "unknown")
        lib = details.get("library", "unknown")
        return f"Kernel segmentation fault in process '{proc}' ({lib})."
    if ev_type == "cron_execution":
        cmd = details.get("command", "unknown")
        return f"Scheduled cron job executed under '{u}': {cmd}"
    if ev_type == "service_stopped":
        unit = details.get("unit") or details.get("unit_description") or "service"
        return f"Systemd service '{unit}' stopped or deactivated."
    if ev_type in ("web_attack_probe", "web_http_error"):
        method = details.get("method", "GET")
        uri = details.get("uri", "/")
        sc = details.get("status_code", 0)
        cat = details.get("attack_category", "http_error")
        return f"Web {cat} from {ip}: {method} {uri} (HTTP {sc})."
    if ev_type == "critical_file_modified":
        target = details.get("target_file", "critical file")
        return f"Critical security file '{target}' modified by user '{u}'."
    if ev_type == "anti_forensics_execution":
        ind = details.get("matched_indicator", "log tampering")
        return f"Anti-forensics indicator '{ind}' executed by user '{u}'."
    if ev_type == "data_exfiltration_attempt":
        stage = details.get("exfil_stage", "data_exfiltration")
        dst = details.get("destination_ip") or ip
        return f"Data exfiltration ({stage}) by user '{u}' targeting {dst}."
    if ev_type == "rootkit_or_sniff_activity":
        act = details.get("activity_type", "kernel_or_sniff")
        return f"Rootkit / promiscuous network activity ({act}) under '{u}'."
    return f"Security telemetry event '{ev_type}' observed."


def _resolve_source_id(details: Dict[str, Any], event_type: str) -> str:
    """Maps event details to valid source_id column in database."""
    service = str(details.get("service", "")).lower()
    if event_type in ("web_attack_probe", "web_http_error") or service in ("nginx", "apache2"):
        return "nginx-access"
    if service in ["sshd", "pam_unix", "sudo", "useradd", "adduser", "usermod", "gpasswd", "passwd"] or "auth" in event_type or "session" in event_type or "sudo" in event_type or event_type in ("account_created", "privilege_group_added", "password_changed"):
        return "ssh-auth"
    if "audit_msg_id" in details or "process" in event_type or event_type in ("critical_file_modified", "anti_forensics_execution", "data_exfiltration_attempt", "rootkit_or_sniff_activity"):
        return "auditd"
    if "connection_state" in details or "network" in event_type:
        return "network-conn"
    return "systemd"


@router.post(
    "/ingest",
    response_model=TelemetryIngestResponse,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
    summary="Ingest Telemetry Batch from Linux Agent",
)
def ingest_telemetry(
    payload: TelemetryIngestRequest,
    agent_tenant: str = Depends(verify_agent_token),
    repo: BaseAegisRepository = Depends(get_repository),
):
    """
    Ingests raw log lines from a monitored Linux host:
    1. Pre-parsing secret redaction and quarantine.
    2. Parsing via LinuxTelemetryParser and deduplication.
    3. Host registration / upsert (to satisfy foreign key constraints).
    4. Storage into telemetry_events with duplicate suppression.
    """
    # Tenant isolation: an agent may only write for hosts owned by its own tenant (first claim binds the host)
    claim_host_for_agent(payload.host_id, agent_tenant, repo)

    now_iso = datetime.now(timezone.utc).isoformat()
    total_received = len(payload.raw_logs)

    # -------------------------------------------------------------
    # Step 1: Pre-Parsing Security Sanitization
    # Any line containing private keys, tokens, or hashes is quarantined.
    # -------------------------------------------------------------
    clean_lines: List[str] = []
    sanitized_quarantined = 0

    for line in payload.raw_logs:
        is_safe, violation = TelemetrySanitizer.inspect_line(line)
        if not is_safe:
            sanitized_quarantined += 1
            logger.warning(
                f"Quarantined unsafe log line from host '{payload.host_id}': violation='{violation}'"
            )
            continue
        clean_lines.append(line)

    # -------------------------------------------------------------
    # Step 2: Parsing via Existing LinuxLogPipelineAdapter
    # -------------------------------------------------------------
    adapter = LinuxLogPipelineAdapter()
    parsed_events, malformed_lines = adapter.process_raw_logs(
        clean_lines,
        prefix=f"EVT-{payload.host_id}",
        deduplicate=True,
    )
    malformed_quarantined = len(malformed_lines)

    # -------------------------------------------------------------
    # Step 3: Secondary Pre-Storage Sanitization on Parsed Details
    # -------------------------------------------------------------
    safe_parsed_events = []
    for ev in parsed_events:
        if ev.details:
            is_safe, violation = TelemetrySanitizer.inspect_dict(ev.details)
            if not is_safe:
                sanitized_quarantined += 1
                logger.warning(
                    f"Quarantined parsed event '{ev.event_id}' due to sensitive detail: violation='{violation}'"
                )
                continue
        safe_parsed_events.append(ev)

    parsed_count = len(safe_parsed_events)

    # -------------------------------------------------------------
    # Step 4: Upsert Host Record FIRST (Mandatory for Foreign Key)
    # -------------------------------------------------------------
    host_record = {
        "id": payload.host_id,
        "hostname": payload.hostname,
        "ip_address": payload.ip_address,
        "os": payload.os,
        "agent_version": payload.agent_version,
        "agent_status": "online",
        "last_data_at": now_iso,
        "is_archived": False,
    }

    try:
        repo.upsert_host(host_record)
    except Exception as e:
        logger.error(f"Failed to upsert host '{payload.host_id}': {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register or update host record.",
        )

    # -------------------------------------------------------------
    # Step 5: Insert Normalized Telemetry Events + AEGIS4 Prompt Injection Guardrail
    # -------------------------------------------------------------
    db_events: List[Dict[str, Any]] = []
    guardian_injection_alerts: List[Dict[str, Any]] = []
    guardian_injection_evidences: List[Dict[str, Any]] = []

    for ev in safe_parsed_events:
        details_dict = dict(ev.details or {})
        raw_msg = _build_safe_event_message(ev.event_type, ev.user, ev.source_ip, details_dict)
        inspect_res = guardian_engine.inspect_text(
            f"{ev.user or ''} {raw_msg}",
            context_label=f"telemetry:{payload.host_id}",
            use_ai_on_trigger=False,
        )
        safe_msg = inspect_res["neutralized_text"] if inspect_res["is_malicious"] else raw_msg
        safe_user = ev.user
        if inspect_res["is_malicious"]:
            details_dict["prompt_injection_blocked"] = True
            details_dict["guardian_matched_rules"] = inspect_res["matched_rules"]
            if safe_user:
                safe_user = guardian_engine.inspect_text(
                    safe_user, context_label=f"user:{payload.host_id}", use_ai_on_trigger=False
                )["neutralized_text"]

        event_row = {
            "id": ev.event_id,
            "host_id": payload.host_id,
            "source_id": _resolve_source_id(details_dict, ev.event_type),
            "event_type": ev.event_type,
            "event_timestamp": ev.timestamp or now_iso,
            "message": safe_msg,
            "source_ip": ev.source_ip,
            "user_name": safe_user,
            "details": details_dict,
            "created_at": now_iso,
        }
        db_events.append(event_row)

        if inspect_res["is_malicious"]:
            inj_alert_id = f"alt-gd-{ev.event_id[:12]}"
            guardian_injection_alerts.append({
                "id": inj_alert_id,
                "host_id": payload.host_id,
                "rule_id": "RULE-AEGIS-PROMPT-INJECTION",
                "title": "Indirect Prompt Injection / Log Poisoning Blocked by AEGIS4",
                "severity": "high",
                "reason": f"AEGIS4 neutralized adversarial AI instruction payload ({', '.join(inspect_res['matched_rules'])}).",
                "detected_at": ev.timestamp or now_iso,
                "investigation_status": "new",
                "source_ip": ev.source_ip,
                "user_name": safe_user,
                "evidence_count": 1,
            })
            guardian_injection_evidences.append({
                "alert_id": inj_alert_id,
                "event_id": ev.event_id,
                "role": "trigger",
            })

    inserted_count = 0
    duplicates_count = 0

    if db_events:
        try:
            inserted_count, duplicates_count = repo.insert_telemetry_events(db_events)
        except Exception as e:
            logger.error(f"Failed to insert telemetry events for host '{payload.host_id}': {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to save normalized telemetry events.",
            )

    # -------------------------------------------------------------
    # Step 6: Rules Engine Evaluation
    # Deterministic evaluation of normalized events against active rules.
    # -------------------------------------------------------------
    alerts_evaluated = 0
    if db_events:
        try:
            rules_engine = RulesEngine()
            alerts, alert_evidences = rules_engine.evaluate_events(db_events)
            if guardian_injection_alerts:
                alerts.extend(guardian_injection_alerts)
                alert_evidences.extend(guardian_injection_evidences)
            if alerts:
                repo.insert_alerts(alerts, alert_evidences)
                logger.info(
                    f"Rules Engine generated {len(alerts)} alerts with {len(alert_evidences)} evidence links for host '{payload.host_id}'."
                )
            alerts_evaluated = len(alerts)
        except Exception as e:
            logger.error(f"Error during Rules Engine evaluation for host '{payload.host_id}': {e}")


    # Determine response status
    if inserted_count > 0 and sanitized_quarantined == 0 and malformed_quarantined == 0:
        resp_status = "ok"
        msg = f"Successfully ingested {inserted_count} telemetry events."
    elif inserted_count > 0:
        resp_status = "partial"
        msg = f"Ingested {inserted_count} events ({sanitized_quarantined} secret-quarantined, {malformed_quarantined} malformed)."
    else:
        resp_status = "rejected"
        msg = "No valid events were accepted from the submitted batch."

    return TelemetryIngestResponse(
        status=resp_status,
        host_id=payload.host_id,
        total_received=total_received,
        sanitized_quarantined=sanitized_quarantined,
        malformed_quarantined=malformed_quarantined,
        parsed_events=parsed_count,
        inserted_events=inserted_count,
        duplicates_ignored=duplicates_count,
        alerts_evaluated=alerts_evaluated,
        message=msg,
    )


@router.post(
    "/heartbeat",
    response_model=HeartbeatResponse,
    responses={401: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    summary="Agent Heartbeat",
)
def register_heartbeat(
    payload: HeartbeatRequest,
    agent_tenant: str = Depends(verify_agent_token),
    repo: BaseAegisRepository = Depends(get_repository),
):
    """
    Registers a periodic heartbeat from a monitored Linux agent node.
    Updates host last_data_at timestamp and maintains online status.
    """
    # Heartbeat is strictly rejected for unregistered hosts to prevent spoofing
    existing_host = repo.get_host_by_id(payload.host_id)
    if not existing_host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host '{payload.host_id}' is not registered. Cannot record heartbeat for unknown host.",
        )
    claim_host_for_agent(payload.host_id, agent_tenant, repo)

    now_iso = datetime.now(timezone.utc).isoformat()
    host_record = {
        "id": payload.host_id,
        "hostname": payload.hostname,
        "ip_address": payload.ip_address,
        "os": payload.os,
        "agent_version": payload.agent_version,
        "agent_status": "online",
        "last_data_at": now_iso,
        "is_archived": False,
    }
    try:
        repo.upsert_host(host_record)
    except Exception as e:
        logger.error(f"Failed to record heartbeat for host '{payload.host_id}': {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register host heartbeat.",
        )

    return HeartbeatResponse(
        status="ok",
        host_id=payload.host_id,
        agent_status="online",
        timestamp=now_iso,
        message="Heartbeat registered successfully.",
    )


@router.post(
    "/posture",
    response_model=PostureIngestResponse,
    responses={401: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    summary="Ingest Read-Only Security Checker Posture Findings from Linux Agent",
)
def ingest_posture(
    payload: PostureIngestRequest,
    agent_tenant: str = Depends(verify_agent_token),
    repo: BaseAegisRepository = Depends(get_repository),
):
    """
    Receives live read-only 12-control (8 CIS + 4 DISA STIG) Security Checker
    posture scan results from a monitored Linux host agent.
    """
    claim_host_for_agent(payload.host_id, agent_tenant, repo)

    now_iso = datetime.now(timezone.utc).isoformat()
    validated_findings: List[FindingItem] = []

    for idx, raw in enumerate(payload.findings):
        check_id = str(raw.get("check_id") or f"CIS-CHK-{idx+1}")
        fid = str(raw.get("id") or f"fnd-{check_id.lower()}-{payload.host_id}")
        status_val = str(raw.get("status") or "pass").lower()
        if status_val not in ("pass", "fail", "not_checked"):
            status_val = "pass"
        sev_val = str(raw.get("severity") or "low").lower()
        if sev_val not in ("critical", "high", "medium", "low"):
            sev_val = "low"
        validated_findings.append(
            FindingItem(
                id=fid,
                host_id=payload.host_id,
                check_id=check_id,
                title=str(raw.get("title") or check_id),
                status=status_val,
                severity=sev_val,
                checked_at=str(raw.get("checked_at") or now_iso),
                indicators=[str(x) for x in (raw.get("indicators") or [])],
                limits=str(raw.get("limits") or "Read-only inspection."),
            )
        )

    op_store.host_findings[payload.host_id] = validated_findings

    existing_host = repo.get_host_by_id(payload.host_id)
    if existing_host:
        existing_host["last_sc_run_at"] = now_iso
        try:
            repo.upsert_host(existing_host)
        except Exception as e:
            logger.warning(f"Could not update last_sc_run_at for host '{payload.host_id}': {e}")

    op_store.record_audit(
        actor=f"agent:{payload.host_id}",
        action="ingest_posture",
        target_type="host",
        target_id=payload.host_id,
        summary=f"Ingested {len(validated_findings)} live CIS/DISA-STIG Security Checker posture controls for '{payload.host_id}'",
    )

    return PostureIngestResponse(
        status="ok",
        host_id=payload.host_id,
        updated_controls=len(validated_findings),
        timestamp=now_iso,
        message=f"Updated {len(validated_findings)} Security Checker posture findings for host '{payload.host_id}'.",
    )


