"""
LLM Provider Abstraction layer.
Supports:
1. BaseLLMProvider (Abstract interface)
2. MockLLMProvider (Deterministic offline provider for fast, 0-cost testing)
3. OpenAICompatibleLLMProvider (Direct adapter for OpenAI / Nine Router / Local Gateway)
4. GeminiLLMProvider (Direct REST adapter for Google Gemini API)
"""

import os
import re
import json
import requests
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from aegis_agent.schemas import (
    IncidentReportOutput,
    AnalysisStatus,
    ConfidenceScore,
    TimelineEntry,
    GroundedClaim,
    ClaimType,
    HypothesisItem,
    RecommendedAction,
    SeverityLevel,
    SCAnalysisOutput,
    StructuredReportOutput,
)


class BaseLLMProvider(ABC):
    @abstractmethod
    def generate_investigation_report(
        self,
        incident_id: str,
        alert_info: Dict[str, Any],
        evidence_items: List[Dict[str, Any]],
        context_data: Dict[str, Any],
    ) -> IncidentReportOutput:
        pass

    @abstractmethod
    def generate_sc_posture_report(
        self,
        enriched_context: Dict[str, Any],
    ) -> SCAnalysisOutput:
        pass

    @abstractmethod
    def generate_reporting_summary(
        self,
        reporting_input: Dict[str, Any],
    ) -> StructuredReportOutput:
        pass


class MockLLMProvider(BaseLLMProvider):
    """
    Deterministic mock provider mapping test scenarios directly to compliant report outputs.
    Allows 100% offline, zero-token, zero-latency unit testing.
    """

    def generate_investigation_report(
        self,
        incident_id: str,
        alert_info: Dict[str, Any],
        evidence_items: List[Dict[str, Any]],
        context_data: Dict[str, Any],
    ) -> IncidentReportOutput:
        severity = SeverityLevel(alert_info.get("severity", "High"))

        # Scenario: Empty evidence / insufficient data
        if not evidence_items:
            return IncidentReportOutput(
                incident_id=incident_id,
                analysis_status=AnalysisStatus.INSUFFICIENT_DATA,
                incident_summary="Alert diterima, tetapi tidak ada log pendukung yang tersedia untuk investigasi.",
                severity=severity,
                timeline=[],
                evidence=[],
                hypotheses=[],
                confidence=ConfidenceScore(level="low", reason="Tidak ada data log pendukung."),
                recommended_actions=[
                    RecommendedAction(
                        action_type="investigative",
                        description="Periksa ketersediaan kolektor log untuk host terkait.",
                        priority="high",
                    )
                ],
                missing_information=["Related authentication logs", "Network activity logs"],
                limitations=["Investigasi tidak dapat dilanjutkan tanpa bukti telemetri."],
            )

        event_types = [e.get("event_type") for e in evidence_items]
        evidence_ids = [e.get("evidence_id") for e in evidence_items]

        # Scenario: Normal login (T03)
        if all(et == "auth_success" for et in event_types) and len(evidence_items) == 1:
            return IncidentReportOutput(
                incident_id=incident_id,
                analysis_status=AnalysisStatus.COMPLETED,
                incident_summary="Berdasarkan log yang tersedia, aktivitas autentikasi konsisten dengan pola normal.",
                severity=severity,
                timeline=[
                    TimelineEntry(
                        timestamp=evidence_items[0].get("observed_at"),
                        event_id=evidence_ids[0],
                        event_summary="Login berhasil.",
                        ai_interpretation="Aktivitas login tunggal dari pengguna terdaftar.",
                    )
                ],
                evidence=[
                    GroundedClaim(
                        claim="Aktivitas login berhasil pada jam kerja.",
                        claim_type=ClaimType.OBSERVATION,
                        evidence_ids=evidence_ids,
                    )
                ],
                hypotheses=[
                    HypothesisItem(
                        hypothesis="Aktivitas administratif sah (bukan serangan).",
                        supporting_evidence_ids=evidence_ids,
                        gaps_or_uncertainties="Tidak ada anomali lain yang dilaporkan.",
                    )
                ],
                confidence=ConfidenceScore(level="high", reason="Hanya ada 1 sesi login valid."),
                recommended_actions=[
                    RecommendedAction(
                        action_type="verification",
                        description="Evaluasi threshold alert Rules Engine jika kejadian ini memicu alarm palsu.",
                        priority="low",
                    )
                ],
                missing_information=[],
                limitations=["Analisis didasarkan pada telemetri log yang ada."],
            )

        # Scenario: Brute-Force with success (T01)
        has_fail = any(et == "auth_failure" for et in event_types)
        has_success = any(et == "auth_success" for et in event_types)

        if has_fail and has_success:
            return IncidentReportOutput(
                incident_id=incident_id,
                analysis_status=AnalysisStatus.COMPLETED,
                incident_summary="Terdeteksi beberapa kegagalan login yang diikuti oleh login berhasil dari IP sumber yang sama.",
                severity=severity,
                timeline=[
                    TimelineEntry(
                        timestamp=e.get("observed_at"),
                        event_id=e.get("evidence_id"),
                        event_summary=f"Event {e.get('event_type')}",
                        ai_interpretation="Percobaan akses beruntun." if "failure" in e.get("event_type") else "Akses berhasil dibuka.",
                    )
                    for e in evidence_items
                ],
                evidence=[
                    GroundedClaim(
                        claim="Terjadi upaya login berulang yang berakhir dengan keberhasilan autentikasi.",
                        claim_type=ClaimType.OBSERVATION,
                        evidence_ids=evidence_ids,
                    )
                ],
                hypotheses=[
                    HypothesisItem(
                        hypothesis="Kemungkinan serangan Brute-Force atau Kredensial yang berhasil ditebak.",
                        supporting_evidence_ids=evidence_ids,
                        gaps_or_uncertainties="Aktivitas sesi setelah login berhasil belum dapat diverifikasi sepenuhnya.",
                    )
                ],
                confidence=ConfidenceScore(
                    level="medium",
                    reason="Pola kegagalan diikuti keberhasilan sangat jelas, namun integritas sesi butuh inspeksi lanjutan.",
                ),
                recommended_actions=[
                    RecommendedAction(
                        action_type="investigative",
                        description="Lakukan verifikasi kepada pemilik akun terkait keabsahan sesi login.",
                        priority="immediate",
                    ),
                    RecommendedAction(
                        action_type="containment_advisory",
                        description="Pertimbangkan pemutusan sesi jika pemilik akun tidak mengonfirmasi aktivitas.",
                        priority="high",
                    ),
                ],
                missing_information=["Post-authentication process execution logs"],
                limitations=["Tidak membuktikan sistem telah dikompromikan secara penuh."],
            )

        # Default fallback
        return IncidentReportOutput(
            incident_id=incident_id,
            analysis_status=AnalysisStatus.PARTIAL,
            incident_summary="Pola aktivitas mencurigakan terdeteksi dalam investigasi runtime.",
            severity=severity,
            timeline=[],
            evidence=[
                GroundedClaim(
                    claim="Ditemukan telemetri mencurigakan.",
                    claim_type=ClaimType.OBSERVATION,
                    evidence_ids=evidence_ids,
                )
            ],
            hypotheses=[],
            confidence=ConfidenceScore(level="low", reason="Data parsial."),
            recommended_actions=[],
            missing_information=[],
            limitations=[],
        )

    def generate_sc_posture_report(
        self,
        enriched_context: Dict[str, Any],
    ) -> SCAnalysisOutput:
        from aegis_agent.schemas import SCFinding, CoverageSummary, ControlStatus
        audit_id = enriched_context.get("audit_run", {}).get("audit_id", "AUD-UNKNOWN")
        host_id = enriched_context.get("host", {}).get("host_id", "HOST-UNKNOWN")
        controls = enriched_context.get("security_controls", [])

        findings = []
        failed_count = 0
        passed_count = 0
        unknown_count = 0

        for ctrl in controls:
            st = ctrl.get("status")
            if st == "fail":
                failed_count += 1
                findings.append(
                    SCFinding(
                        finding_id=f"FND-{ctrl.get('control_id')}",
                        control_id=ctrl.get("control_id"),
                        title=f"Kelemahan konfigurasi pada {ctrl.get('control_name')}",
                        risk_level=SeverityLevel.HIGH,
                        status=ControlStatus.FAIL,
                        evidence_ids=[ctrl.get("evidence_ref")] if ctrl.get("evidence_ref") else [],
                        explanation=f"Nilai saat ini '{ctrl.get('current_value')}' tidak memenuhi standar.",
                        remediation_guidance=f"Sesuaikan konfigurasi menjadi '{ctrl.get('expected_value')}'.",
                    )
                )
            elif st == "pass":
                passed_count += 1
            else:
                unknown_count += 1

        return SCAnalysisOutput(
            audit_id=audit_id,
            host_id=host_id,
            analysis_status=AnalysisStatus.COMPLETED if controls else AnalysisStatus.INSUFFICIENT_DATA,
            executive_summary=f"Audit postur keamanan selesai. Ditemukan {failed_count} kelemahan konfigurasi.",
            findings=findings,
            coverage_summary=CoverageSummary(
                total_controls_evaluated=len(controls),
                passed=passed_count,
                failed=failed_count,
                unknown=unknown_count,
                not_applicable=0,
            ),
            limitations=[],
        )

    def generate_reporting_summary(
        self,
        reporting_input: Dict[str, Any],
    ) -> StructuredReportOutput:
        from aegis_agent.schemas import AggregatedMetric, ReportType
        incidents = reporting_input.get("stored_incidents", [])
        postures = reporting_input.get("stored_postures", [])

        crit_alerts = sum(1 for i in incidents if i.get("severity") == "Critical")
        high_alerts = sum(1 for i in incidents if i.get("severity") == "High")
        med_low_alerts = len(incidents) - (crit_alerts + high_alerts)
        failed_ctrls = sum(len(p.get("failed_controls", [])) for p in postures)

        action_items = []
        for inc in incidents:
            action_items.extend(inc.get("recommended_actions", []))

        return StructuredReportOutput(
            report_id=reporting_input.get("report_id", "RPT-001"),
            report_type=ReportType(reporting_input.get("report_type", "daily_security_briefing")),
            generated_at=reporting_input.get("generated_at", ""),
            reporting_window={
                "start": reporting_input.get("period_start", ""),
                "end": reporting_input.get("period_end", ""),
            },
            executive_overview=f"Laporan keamanan merangkum {len(incidents)} insiden aktif dan audit terhadap {len(postures)} host.",
            metrics=AggregatedMetric(
                total_alerts=len(incidents),
                critical_alerts=crit_alerts,
                high_alerts=high_alerts,
                medium_or_low_alerts=med_low_alerts,
                audited_hosts=len(postures),
                non_compliant_controls=failed_ctrls,
            ),
            incident_highlights=incidents,
            posture_highlights=postures,
            consolidated_action_items=action_items,
            data_provenance_summary={"sources": ["incident_store", "audit_store"]},
            limitations_and_uncertainties=["Data terbatas pada hasil telemetri yang disimpan sistem."],
        )


class RealLLMAdapter(BaseLLMProvider):
    """
    Direct HTTP client supporting Google Gemini and OpenAI-compatible endpoints (Nine Router / Proxies).
    Guarantees:
    - Never prints API key in logs, exceptions, or string outputs.
    - Strict timeout handling.
    - JSON parsing error resilience without falsifying severity or evidence.
    """

    def __init__(
        self,
        provider_type: str = "gemini",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout: int = 30,
        timeout_seconds: Optional[int] = None,
        backup_keys: Optional[List[str]] = None,
        role: str = "rm",
        session: Optional[requests.Session] = None,
    ):
        self.provider_type = provider_type.lower()
        self.role = role.lower()
        k1 = os.getenv("AEGIS1") or os.getenv("AEGIS_LLM_API_KEY") or ""
        k2 = os.getenv("AEGIS2") or k1
        k3 = os.getenv("AEGIS3") or k1
        default_role_key = k3 if self.role == "reporting" else (k2 if self.role == "sc" else k1)
        self.api_key = api_key if api_key is not None else default_role_key
        self.backup_keys = [k for k in (backup_keys or []) if k and k != self.api_key]
        self.base_url = base_url or os.getenv("AEGIS_LLM_BASE_URL", "")
        self.model_name = model_name or os.getenv("AEGIS_LLM_MODEL", "gemini-2.5-flash")
        self.timeout = timeout_seconds if timeout_seconds is not None else timeout
        self.session = session or requests.Session()

    def _sanitize_error_message(self, message: str) -> str:
        """Strips out API key from error messages or stack traces."""
        for k in [self.api_key] + getattr(self, "backup_keys", []):
            if k and k in message:
                message = message.replace(k, "[REDACTED_API_KEY]")
        return message

    def _call_http(self, prompt: str, system_instruction: str) -> str:
        if not self.api_key:
            raise ValueError("AEGIS_LLM_API_KEY is not set. Please provide a valid API key.")

        candidate_keys = [self.api_key] + getattr(self, "backup_keys", [])
        last_error: Optional[Exception] = None

        for idx, active_key in enumerate(candidate_keys):
            try:
                if self.provider_type == "gemini":
                    url = self.base_url or f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent"
                    headers = {
                        "Content-Type": "application/json",
                        "x-goog-api-key": active_key,
                    }
                    payload = {
                        "contents": [{"parts": [{"text": prompt}]}],
                        "systemInstruction": {"parts": [{"text": system_instruction}]},
                        "generationConfig": {
                            "responseMimeType": "application/json",
                            "temperature": 0.1,
                        },
                    }
                    resp = self.session.post(url, headers=headers, json=payload, timeout=self.timeout)
                    if resp.status_code != 200:
                        sanitized_err = self._sanitize_error_message(resp.text)
                        raise RuntimeError(f"Gemini API returned status {resp.status_code}: {sanitized_err}")

                    result_json = resp.json()
                    candidates = result_json.get("candidates", [])
                    if not candidates:
                        raise RuntimeError("Gemini API returned no candidates.")
                    text_content = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                    return text_content

                else:
                    base = self.base_url.rstrip("/") if self.base_url else "https://api.openai.com/v1"
                    url = f"{base}/chat/completions"
                    headers = {
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {active_key}",
                    }
                    payload = {
                        "model": self.model_name,
                        "messages": [
                            {"role": "system", "content": system_instruction},
                            {"role": "user", "content": prompt},
                        ],
                        "response_format": {"type": "json_object"},
                        "temperature": 0.1,
                    }
                    resp = self.session.post(url, headers=headers, json=payload, timeout=self.timeout)
                    if resp.status_code != 200:
                        sanitized_err = self._sanitize_error_message(resp.text)
                        raise RuntimeError(f"OpenAI-compatible API returned status {resp.status_code}: {sanitized_err}")

                    result_json = resp.json()
                    return result_json["choices"][0]["message"]["content"]

            except requests.exceptions.Timeout as e:
                last_error = TimeoutError("LLM Provider request timed out.")
                if idx == len(candidate_keys) - 1:
                    raise last_error
            except Exception as e:
                sanitized = self._sanitize_error_message(str(e))
                last_error = RuntimeError(f"LLM Provider invocation failed: {sanitized}")
                if idx == len(candidate_keys) - 1:
                    raise last_error

        raise last_error or RuntimeError("LLM Provider invocation failed.")

    def generate_investigation_report(
        self,
        incident_id: str,
        alert_info: Dict[str, Any],
        evidence_items: List[Dict[str, Any]],
        context_data: Dict[str, Any],
    ) -> IncidentReportOutput:
        schema_json = json.dumps(IncidentReportOutput.model_json_schema())
        system_prompt = (
            "You are AEGIS AI Incident Investigation Agent. Analyze the alert and telemetry evidence.\n"
            f"Strict Output JSON Schema:\n{schema_json}\n"
            "Rules:\n"
            "1. Output MUST be valid JSON adhering strictly to IncidentReportOutput schema above.\n"
            "2. 'analysis_status' MUST be one of: 'completed', 'partial', 'insufficient_data', 'failed'.\n"
            "3. EVIDENCE GROUNDING REQUIREMENT: Do NOT exaggerate event counts. If evidence has only 1 failed login, do NOT describe it as 'multiple failed logins'. Be precise to the exact event counts present in evidence.\n"
            "4. NEVER invent evidence IDs. Only cite evidence_ids provided in the prompt.\n"
            "5. DO NOT change severity from the alert.\n"
            "6. 'hypotheses' must be a list of objects with 'hypothesis', 'supporting_evidence_ids', and 'gaps_or_uncertainties'.\n"
            "7. 'confidence' must be an object with 'level' (high/medium/low) and 'reason'.\n"
            "8. 'incident_summary' string is required."
        )
        user_prompt = json.dumps({
            "incident_id": incident_id,
            "alert": alert_info,
            "evidence": evidence_items,
            "context": context_data,
        })

        try:
            raw_response = self._call_http(prompt=user_prompt, system_instruction=system_prompt)
            data = json.loads(raw_response)
            # Guarantee immutable severity binding
            data["severity"] = alert_info.get("severity", "High")
            return IncidentReportOutput(**data)
        except Exception as e:
            # Fallback gracefully without fabricating data or crashing
            sanitized = self._sanitize_error_message(str(e))
            return IncidentReportOutput(
                incident_id=incident_id,
                analysis_status=AnalysisStatus.FAILED,
                incident_summary=f"Investigasi gagal akibat kendala pemanggilan model AI: {sanitized}",
                severity=SeverityLevel(alert_info.get("severity", "High")),
                timeline=[],
                evidence=[],
                hypotheses=[],
                confidence=ConfidenceScore(level="low", reason="Kegagalan API provider."),
                recommended_actions=[],
                missing_information=[],
                limitations=["Kegagalan teknis pada provider LLM."],
            )

    def generate_sc_posture_report(
        self,
        enriched_context: Dict[str, Any],
    ) -> SCAnalysisOutput:
        schema_json = json.dumps(SCAnalysisOutput.model_json_schema())
        system_prompt = (
            "You are AEGIS Security Checker AI. Evaluate the provided enriched posture audit context.\n"
            f"Strict Output JSON Schema:\n{schema_json}\n"
            "Rules:\n"
            "1. Output MUST be valid JSON adhering strictly to SCAnalysisOutput schema above.\n"
            "2. 'analysis_status' MUST be one of: 'completed', 'partial', 'insufficient_data', 'failed'.\n"
            "3. 'executive_summary' string is required.\n"
            "4. 'coverage_summary' object with 'total_controls_evaluated', 'passed', 'failed', 'unknown', 'not_applicable' is required.\n"
            "5. Never mark unknown controls as pass.\n"
            "6. Only cite evidence IDs present in the audit evidence list."
        )
        user_prompt = json.dumps(enriched_context)

        try:
            raw_response = self._call_http(prompt=user_prompt, system_instruction=system_prompt)
            data = json.loads(raw_response)
            return SCAnalysisOutput(**data)
        except Exception as e:
            audit_id = enriched_context.get("audit_run", {}).get("audit_id", "AUD-UNKNOWN")
            host_id = enriched_context.get("host", {}).get("host_id", "HOST-UNKNOWN")
            sanitized = self._sanitize_error_message(str(e))
            from aegis_agent.schemas import CoverageSummary
            return SCAnalysisOutput(
                audit_id=audit_id,
                host_id=host_id,
                analysis_status=AnalysisStatus.FAILED,
                executive_summary=f"Evaluasi postur gagal akibat kendala provider AI: {sanitized}",
                findings=[],
                coverage_summary=CoverageSummary(
                    total_controls_evaluated=0, passed=0, failed=0, unknown=0, not_applicable=0
                ),
                limitations=["Kegagalan teknis pada provider LLM."],
            )

    def generate_reporting_summary(
        self,
        reporting_input: Dict[str, Any],
    ) -> StructuredReportOutput:
        system_prompt = (
            "You are AEGIS Reporting Agent. Synthesize pre-stored incident and posture results.\n"
            "Rules:\n"
            "1. Output MUST be valid JSON adhering strictly to StructuredReportOutput schema.\n"
            "2. Do not fabricate findings or alerts outside the provided stored records."
        )
        user_prompt = json.dumps(reporting_input)

        try:
            raw_response = self._call_http(prompt=user_prompt, system_instruction=system_prompt)
            data = json.loads(raw_response)
            return StructuredReportOutput(**data)
        except Exception as e:
            # Fallback to deterministic synthesis on provider error
            mock = MockLLMProvider()
            return mock.generate_reporting_summary(reporting_input)
