"""
Live / Test runner to test Real LLM Provider with Mock Evidence.
Requires .env with AEGIS_LLM_API_KEY.
"""

import os
import json
from dotenv import load_dotenv

# Load local environment
load_dotenv()

from aegis_agent.providers import RealLLMAdapter, MockLLMProvider
from aegis_agent.schemas import (
    IncidentInvestigationInput,
    AlertInput,
    EntityContext,
    LogEventInput,
    SeverityLevel,
    EnrichedContextInput,
    AuditRunMetadata,
    HostContext,
    NetworkExposure,
    SecurityControl,
    ControlStatus,
    ReferenceContext,
)
from aegis_agent.services import (
    RuntimeMonitorService,
    SecurityCheckerService,
)
from aegis_agent.tools import BackendGatekeeper


def test_real_llm_connection():
    api_key = os.getenv("AEGIS_LLM_API_KEY") or os.getenv("AEGIS1")
    provider_type = os.getenv("AEGIS_LLM_PROVIDER", "gemini")
    model_name = os.getenv("AEGIS_LLM_MODEL", "gemini-2.5-flash")

    print("=" * 60)
    print("  AEGIS REAL LLM PROVIDER TEST (MOCK EVIDENCE)")
    print("=" * 60)
    print(f"Provider Type: {provider_type}")
    print(f"Model Name   : {model_name}")
    print(f"API Key Found: {'YES (Safe/Redacted)' if api_key else 'NO'}")

    if not api_key or "your_" in api_key:
        print("\n[!] WARNING: Valid API Key not found in .env.")
        print("    Skipping live API call. Please verify .env configuration.")
        return

    adapter = RealLLMAdapter(
        provider_type=provider_type,
        api_key=api_key,
        model_name=model_name,
    )

    # 1. Test Runtime Monitor with Real LLM + Mock Evidence
    print("\n--- 1. Testing Runtime Monitor with Real LLM ---")
    gatekeeper = BackendGatekeeper(
        investigation_id="INV-LIVE-01",
        alert_id="ALT-LIVE-01",
        authorized_host_id="srv-prod-auth",
        alert_timestamp="2026-11-01T10:00:00Z",
        evidence_db=[
            {
                "evidence_id": "EVT-AUTH-201",
                "source_type": "authentication_log",
                "source_ref": "auth_collector",
                "host_id": "srv-prod-auth",
                "observed_at": "2026-11-01T10:02:15Z",
                "collected_at": "2026-11-01T10:02:20Z",
                "event_type": "auth_success",
                "data": {"source_ip": "198.51.100.24", "user": "admin"},
            }
        ],
    )

    incident = IncidentInvestigationInput(
        incident_id="INC-LIVE-01",
        alert=AlertInput(
            alert_id="ALT-LIVE-01",
            rule_id="RULE-AUTH-003",
            rule_name="Multiple Failed Logins Followed by Success",
            severity=SeverityLevel.HIGH,
            timestamp="2026-11-01T10:00:00Z",
        ),
        entities=EntityContext(
            source_ip="198.51.100.24",
            target_user="admin",
            target_host="srv-prod-auth",
        ),
        logs=[
            LogEventInput(
                event_id="EVT-AUTH-101",
                timestamp="2026-11-01T10:00:05Z",
                event_type="auth_failure",
                source_ip="198.51.100.24",
                user="admin",
            )
        ],
    )

    rm_service = RuntimeMonitorService(provider=adapter)
    try:
        report = rm_service.investigate_incident(incident, gatekeeper)
        print("[+] RM Investigation completed via Real LLM:")
        print(f"    Status   : {report.analysis_status.value}")
        print(f"    Severity : {report.severity.value} (Immutable)")
        print(f"    Summary  : {report.incident_summary}")
    except Exception as e:
        print(f"[-] RM Investigation error: {e}")

    # 2. Test Security Checker with Real LLM + Mock Evidence
    print("\n--- 2. Testing Security Checker with Real LLM ---")
    sc_context = EnrichedContextInput(
        audit_run=AuditRunMetadata(audit_id="AUD-LIVE-01", timestamp="2026-11-01T08:00:00Z"),
        host=HostContext(host_id="srv-prod-auth", hostname="core-auth-srv01", os_version="Ubuntu 24.04 LTS"),
        network_exposure=NetworkExposure(listening_ports=[22, 443], firewall_profile="strict"),
        security_controls=[
            SecurityControl(
                control_id="CIS-SSH-5.2.1",
                control_name="Disable root login",
                category="access_control",
                status=ControlStatus.FAIL,
                current_value="PermitRootLogin yes",
                expected_value="PermitRootLogin no",
            )
        ],
        reference_context=ReferenceContext(benchmark="CIS Ubuntu 24.04", baseline_profile="L1"),
    )

    sc_service = SecurityCheckerService(provider=adapter)
    try:
        sc_out = sc_service.evaluate_posture(sc_context)
        print("[+] SC Posture evaluation completed via Real LLM:")
        print(f"    Status   : {sc_out.analysis_status.value}")
        print(f"    Executive: {sc_out.executive_summary}")
    except Exception as e:
        print(f"[-] SC Posture evaluation error: {e}")


if __name__ == "__main__":
    test_real_llm_connection()

