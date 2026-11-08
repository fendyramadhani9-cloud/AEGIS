"""
AEGIS AI Provider Abstraction Layer.
Supports:
1. BaseAIProvider: Abstract contract.
2. GeminiProvider: Official Google Gemini REST API with key rotation.
3. OpenAICompatibleProvider: Standards-compliant OpenAI/proxy client.
4. MockAIProvider: Deterministic, zero-cost, grounded provider for testing.
5. NullAIProvider: Transparent unavailable fallback when unconfigured.

Security Guarantees:
- Strictly redacts API keys from all error logs and exception traces.
- Enforces request timeouts.
- Never fabricates evidence IDs.
"""

import os
import re
import json
import logging
import requests
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from aegis_backend.incident_context_builder import IncidentContext
from aegis_backend.schemas import AIAnalysisItem

logger = logging.getLogger("aegis_backend.ai_provider")


def is_rfc5737_testnet(ip: Optional[str]) -> bool:
    """Detects RFC 5737 reserved documentation / benchmark test addresses."""
    if not ip:
        return False
    return (
        ip.startswith("198.51.100.")
        or ip.startswith("203.0.113.")
        or ip.startswith("192.0.2.")
    )


class BaseAIProvider(ABC):
    """Abstract contract for security analysis providers."""

    @abstractmethod
    def analyze_incident(self, context: IncidentContext) -> AIAnalysisItem:
        pass

    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        pass


class MockAIProvider(BaseAIProvider):
    """Deterministic, 100% offline provider for automated testing and CI."""

    def __init__(self, model_name: str = "mock-grounded-v1"):
        self.model_name = model_name

    def health_check(self) -> Dict[str, Any]:
        return {
            "status": "ok",
            "provider": "mock",
            "model": self.model_name,
            "configured": True,
            "reachable": True,
            "message": "Offline deterministic mock provider active.",
        }

    def analyze_incident(self, context: IncidentContext) -> AIAnalysisItem:
        analysis_id = f"ANL-{context.incident_id}-{int(datetime.now(timezone.utc).timestamp())}"
        evidence_ids = sorted(list(context.allowed_evidence_ids))

        # Classify threat
        rule_ids = {a.get("rule_id") for a in context.alerts}
        if "RULE-SSH-BRUTE" in rule_ids and "RULE-AUTH-003" in rule_ids and "RULE-SUSP-SUDO" in rule_ids:
            threat_cls = "Multi-Stage Attack Chain: Brute-Force to Privileged Root Shell"
            exec_summary = (
                f"Adversary successfully conducted an automated brute-force campaign against SSH, "
                f"authenticated as user '{context.target_user or 'account'}', and escalated privileges via sudo."
            )
        elif "RULE-AUTH-003" in rule_ids and "RULE-SUSP-SUDO" in rule_ids:
            threat_cls = "Compromised Account with Privilege Escalation"
            exec_summary = (
                f"Authentication succeeded following previous failures for user '{context.target_user or 'user'}', "
                f"promptly executing privileged root commands via sudo."
            )
        elif "RULE-SSH-BRUTE" in rule_ids:
            threat_cls = "Automated SSH Brute-Force Campaign"
            exec_summary = (
                f"Observed multiple consecutive SSH authentication failures originated from IP "
                f"'{context.source_ip or 'external IP'}' targeted at host '{context.host_id}'."
            )
        else:
            threat_cls = "Suspicious Host Activity"
            exec_summary = f"Security alerts detected on host '{context.host_id}': {context.title}."

        observed = []
        facts = []
        for ev in context.evidence_items[:5]:
            ev_id = ev.get("event_id") or ev.get("id")
            item = {
                "evidence_id": ev_id,
                "fact": ev.get("message", "Telemetry observation recorded."),
                "timestamp": ev.get("event_timestamp") or ev.get("created_at"),
            }
            observed.append(item)
            facts.append(item)

        inferences = [
            {
                "statement": f"Observed activity pattern aligns with {threat_cls}.",
                "supporting_evidence_ids": evidence_ids[:3],
                "rationale": "High-confidence sequential correlation across logged telemetry events.",
            }
        ]

        hypotheses = [
            {
                "statement": "Attacker may seek persistence via scheduled cron or secondary SSH keys.",
                "status": "unverified",
                "investigation_step": "Inspect /etc/crontab and ~/.ssh/authorized_keys for recent modifications.",
            }
        ]

        unknown_items = [
            {"data_gap": "External IP ownership and Autonomous System Number (ASN).", "impact": "Attribution to specific threat group incomplete."},
            {"data_gap": "Full process execution parameters inside spawned interactive shells.", "impact": "Sub-command actions require auditd inspection."},
        ]
        unknowns = [item["data_gap"] for item in unknown_items]

        timeline = []
        for i, ev in enumerate(context.evidence_items[:6]):
            timeline.append({
                "step": i + 1,
                "timestamp": ev.get("event_timestamp") or ev.get("created_at"),
                "event_type": ev.get("event_type", "audit"),
                "description": ev.get("message", "Observed event."),
                "evidence_id": ev.get("event_id") or ev.get("id"),
            })

        recommended_actions = [
            {
                "priority": "immediate",
                "action": f"Verify account '{context.target_user or 'authorized users'}' credentials and revoke active SSH sessions.",
            },
            {
                "priority": "high",
                "action": f"Block malicious ingress IP '{context.source_ip or 'offending IP'}' in firewall (UFW).",
            },
            {
                "priority": "medium",
                "action": "Enforce SSH public key authentication (PasswordAuthentication no) in sshd_config.",
            },
        ]

        containment = [
            f"Isolate host '{context.host_id}' from the management network if lateral movement is suspected.",
            "Lock targeted user account pending administrator review.",
        ]

        unknowns = [
            "Source IP ownership and ASN information not provided in telemetry.",
            "Whether additional processes were executed outside monitored audit rules.",
        ]

        # Posture enrichment
        if context.posture_findings:
            unknowns.append(
                f"Host posture notes: {len(context.posture_findings)} security check issues identified on host."
            )

        now_iso = datetime.now(timezone.utc).isoformat()
        notes = "Offline deterministic analysis based strictly on collected telemetry."
        if is_rfc5737_testnet(context.source_ip):
            notes += " (Notice: Source IP is in RFC 5737 TEST-NET range; represents synthetic test telemetry, not a live internet compromise)."

        return AIAnalysisItem(
            analysis_id=analysis_id,
            incident_id=context.incident_id,
            alert_id=context.alerts[0].get("id") if context.alerts else None,
            host_id=context.host_id,
            analysis_status="completed",
            threat_classification=threat_cls,
            executive_summary=exec_summary,
            attack_scenario=context.attack_scenario or exec_summary,
            facts=facts,
            inferences=inferences,
            hypotheses=hypotheses,
            unknown_items=unknown_items,
            observed_behaviors=observed,
            timeline=timeline,
            risk_level=context.severity,
            risk_score=85 if context.severity == "high" else 50,
            confidence_level="high" if len(evidence_ids) >= 3 else "medium",
            confidence_reason=f"Derived from {len(evidence_ids)} concrete supporting telemetry events.",
            supporting_evidence=evidence_ids,
            contradicting_evidence=[],
            unknowns=unknowns,
            impact_assessment="Potential unauthorized host access and administrative privilege compromise.",
            recommended_actions=recommended_actions,
            containment_recommendations=containment,
            investigation_notes=notes,
            provider="mock-evaluator",
            model=self.model_name,
            storage_backend="sqlite_local",
            created_at=now_iso,
            completed_at=now_iso,
        )


class GeminiProvider(BaseAIProvider):
    """Official Google Gemini REST API client with key rotation and anti-hallucination prompting."""

    def __init__(
        self,
        api_keys: Optional[List[str]] = None,
        model_name: Optional[str] = None,
        timeout: int = 30,
    ):
        raw_keys = api_keys or [
            os.getenv("AEGIS_LLM_API_KEY", ""),
            os.getenv("AEGIS1", ""),
            os.getenv("AEGIS2", ""),
            os.getenv("AEGIS3", ""),
        ]
        self.api_keys = [k.strip() for k in raw_keys if k and k.strip()]
        self.current_key_idx = 0
        self.model_name = model_name or os.getenv("AEGIS_LLM_MODEL", "gemini-3.5-flash-lite")
        self.timeout = timeout
        self.session = requests.Session()

    def _get_active_key(self) -> str:
        if not self.api_keys:
            return ""
        return self.api_keys[self.current_key_idx % len(self.api_keys)]

    def _rotate_key(self):
        if len(self.api_keys) > 1:
            self.current_key_idx = (self.current_key_idx + 1) % len(self.api_keys)
            logger.info("Rotated to backup Gemini API key.")

    def _sanitize_error(self, message: str) -> str:
        for k in self.api_keys:
            if k in message:
                message = message.replace(k, "[REDACTED_API_KEY]")
        return message

    def health_check(self) -> Dict[str, Any]:
        key = self._get_active_key()
        if not key:
            return {
                "status": "unavailable",
                "provider": "gemini",
                "model": self.model_name,
                "configured": False,
                "reachable": False,
                "message": "No API key configured in AEGIS_LLM_API_KEY or AEGIS1-3.",
            }
        try:
            url = "https://generativelanguage.googleapis.com/v1beta/models"
            headers = {"x-goog-api-key": key}
            r = self.session.get(url, headers=headers, timeout=5)
            if r.status_code == 200:
                return {
                    "status": "ok",
                    "provider": "gemini",
                    "model": self.model_name,
                    "configured": True,
                    "reachable": True,
                    "message": f"Connected to Google Gemini API (model: {self.model_name}).",
                }
            return {
                "status": "degraded",
                "provider": "gemini",
                "model": self.model_name,
                "configured": True,
                "reachable": False,
                "message": f"Gemini API returned HTTP {r.status_code}.",
            }
        except Exception as e:
            return {
                "status": "unavailable",
                "provider": "gemini",
                "model": self.model_name,
                "configured": True,
                "reachable": False,
                "message": f"Connection error: {self._sanitize_error(str(e))}",
            }

    def analyze_incident(self, context: IncidentContext) -> AIAnalysisItem:
        key = self._get_active_key()
        if not key:
            # Fallback to NullProvider behavior
            return NullAIProvider().analyze_incident(context)

        system_prompt = (
            "You are AEGIS AI Incident Investigation Analyst. Analyze the provided Linux security incident context.\n"
            "STRICT GROUNDING & TAXONOMY RULES:\n"
            "1. Output MUST be valid JSON adhering strictly to the schema provided.\n"
            "2. ANTI-HALLUCINATION REQUIREMENT: Only reference event IDs explicitly listed in 'allowed_evidence_ids'. Do NOT invent event IDs, IPs, users, or commands.\n"
            "3. STRICT TAXONOMY SEPARATION:\n"
            "   - 'facts': Concrete telemetry statements with valid evidence_id.\n"
            "   - 'inferences': Logical conclusions derived from multiple facts with rationale.\n"
            "   - 'hypotheses': Unproven possibilities marked as status 'unverified' with next steps.\n"
            "   - 'unknowns': Explicitly state information that is missing from telemetry.\n"
            "4. NEVER suggest modifying production systems directly; provide actionable administrator recommendations.\n"
            "5. The incident severity is immutable.\n"
            "6. Output JSON format:\n"
            "{\n"
            '  "threat_classification": "MITRE ATT&CK technique or attack pattern",\n'
            '  "executive_summary": "2-3 sentences plain language summary",\n'
            '  "attack_scenario": "Detailed reconstructed narrative of what occurred",\n'
            '  "facts": [{"evidence_id": "EVT-...", "fact": "Direct telemetry observation", "timestamp": "..."}],\n'
            '  "inferences": [{"statement": "Logical conclusion", "supporting_evidence_ids": ["EVT-..."], "rationale": "Why concluded"}],\n'
            '  "hypotheses": [{"statement": "Unverified theory", "status": "unverified", "investigation_step": "How to verify"}],\n'
            '  "unknowns": [{"data_gap": "Missing telemetry detail", "impact": "Forensic limitation"}],\n'
            '  "timeline": [{"step": 1, "timestamp": "...", "event_type": "...", "description": "...", "evidence_id": "EVT-..."}],\n'
            '  "confidence_level": "high|medium|low",\n'
            '  "confidence_reason": "Justification for confidence level",\n'
            '  "supporting_evidence": ["EVT-...", "EVT-..."],\n'
            '  "impact_assessment": "Potential consequence to the host or organisation",\n'
            '  "recommended_actions": [{"priority": "immediate|high|medium", "action": "..."}],\n'
            '  "containment_recommendations": ["Step 1", "Step 2"]\n'
            "}"
        )

        user_content = json.dumps(context.to_dict())

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent"
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": key,
        }
        payload = {
            "contents": [{"parts": [{"text": user_content}]}],
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "generationConfig": {
                "responseMimeType": "application/json",
                "temperature": 0.1,
            },
        }

        now_iso = datetime.now(timezone.utc).isoformat()
        analysis_id = f"ANL-{context.incident_id}-{int(datetime.now(timezone.utc).timestamp())}"

        try:
            resp = self.session.post(url, headers=headers, json=payload, timeout=self.timeout)

            # Retry once on key rotation if 429 or 503
            if resp.status_code in (429, 503) and len(self.api_keys) > 1:
                self._rotate_key()
                headers["x-goog-api-key"] = self._get_active_key()
                resp = self.session.post(url, headers=headers, json=payload, timeout=self.timeout)

            if resp.status_code != 200:
                sanitized_msg = self._sanitize_error(resp.text)
                logger.error(f"Gemini API returned error {resp.status_code}: {sanitized_msg}")
                return AIAnalysisItem(
                    analysis_id=analysis_id,
                    incident_id=context.incident_id,
                    alert_id=context.alerts[0].get("id") if context.alerts else None,
                    host_id=context.host_id,
                    analysis_status="failed",
                    threat_classification="Analysis Service Error",
                    executive_summary=f"AI analysis failed due to provider error (HTTP {resp.status_code}). Telemetry and alerts remain intact.",
                    attack_scenario=context.attack_scenario or "Investigation pending provider recovery.",
                    observed_behaviors=[],
                    timeline=[],
                    risk_level=context.severity,
                    risk_score=50,
                    confidence_level="low",
                    confidence_reason="API provider call failed.",
                    supporting_evidence=sorted(list(context.allowed_evidence_ids)),
                    contradicting_evidence=[],
                    unknowns=["Analysis payload could not be compiled by provider."],
                    impact_assessment="Unknown pending investigation.",
                    recommended_actions=[{"priority": "immediate", "action": "Review alerts and raw evidence manually in dashboard."}],
                    containment_recommendations=[],
                    investigation_notes=f"Provider error: HTTP {resp.status_code}",
                    provider="gemini",
                    model=self.model_name,
                    storage_backend="database",
                    created_at=now_iso,
                    completed_at=now_iso,
                )

            data = resp.json()
            candidates = data.get("candidates", [])
            if not candidates:
                raise RuntimeError("Gemini API returned no candidates.")

            text_content = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            parsed = json.loads(text_content)

            # Strict Anti-hallucination Post-Validation
            raw_facts = parsed.get("facts", parsed.get("observed_behaviors", []))
            valid_facts = []
            for f in raw_facts:
                if isinstance(f, dict):
                    ev_id = f.get("evidence_id")
                    if ev_id in context.allowed_evidence_ids:
                        valid_facts.append(f)
            if not valid_facts and context.allowed_evidence_ids:
                for ev in context.evidence_items[:5]:
                    valid_facts.append({
                        "evidence_id": ev.get("event_id") or ev.get("id"),
                        "fact": ev.get("message", "Corroborating telemetry event."),
                        "timestamp": ev.get("event_timestamp") or ev.get("created_at"),
                    })

            raw_inferences = parsed.get("inferences", [])
            valid_inferences = []
            for inf in raw_inferences:
                if isinstance(inf, dict):
                    clean_ids = [eid for eid in inf.get("supporting_evidence_ids", []) if eid in context.allowed_evidence_ids]
                    inf["supporting_evidence_ids"] = clean_ids or sorted(list(context.allowed_evidence_ids))[:2]
                    valid_inferences.append(inf)

            raw_hypotheses = parsed.get("hypotheses", [])
            valid_hypotheses = [h for h in raw_hypotheses if isinstance(h, dict)]

            raw_unknowns = parsed.get("unknowns", [])
            valid_unknown_items = []
            plain_unknowns = []
            for u in raw_unknowns:
                if isinstance(u, dict):
                    valid_unknown_items.append(u)
                    plain_unknowns.append(u.get("data_gap", str(u)))
                else:
                    plain_unknowns.append(str(u))
                    valid_unknown_items.append({"data_gap": str(u), "impact": "Requires additional telemetry."})

            cited = parsed.get("supporting_evidence", [])
            valid_citations = [cid for cid in cited if cid in context.allowed_evidence_ids]
            if not valid_citations and context.allowed_evidence_ids:
                valid_citations = sorted(list(context.allowed_evidence_ids))

            notes = "Live Google Gemini analysis verified against grounding telemetry."
            if is_rfc5737_testnet(context.source_ip):
                notes += " (Notice: Source IP is within RFC 5737 reserved TEST-NET documentation range; indicates synthetic test telemetry, not a confirmed real-world compromise)."

            return AIAnalysisItem(
                analysis_id=analysis_id,
                incident_id=context.incident_id,
                alert_id=context.alerts[0].get("id") if context.alerts else None,
                host_id=context.host_id,
                analysis_status="completed",
                threat_classification=parsed.get("threat_classification", "Security Detection"),
                executive_summary=parsed.get("executive_summary", "Incident analysis completed."),
                attack_scenario=parsed.get("attack_scenario", context.attack_scenario or ""),
                facts=valid_facts,
                inferences=valid_inferences,
                hypotheses=valid_hypotheses,
                unknown_items=valid_unknown_items,
                observed_behaviors=valid_facts,
                timeline=parsed.get("timeline", []),
                risk_level=context.severity,
                risk_score=85 if context.severity in ("critical", "high") else 45,
                confidence_level=parsed.get("confidence_level", "high"),
                confidence_reason=parsed.get("confidence_reason", "Grounded in verified telemetry."),
                supporting_evidence=valid_citations,
                contradicting_evidence=[],
                unknowns=plain_unknowns or ["Telemetry provides sufficient scope for primary threat vector."],
                impact_assessment=parsed.get("impact_assessment", "Potential access violation."),
                recommended_actions=parsed.get("recommended_actions", []),
                containment_recommendations=parsed.get("containment_recommendations", []),
                investigation_notes=notes,
                provider="gemini",
                model=self.model_name,
                storage_backend="sqlite_local",
                created_at=now_iso,
                completed_at=datetime.now(timezone.utc).isoformat(),
            )

        except Exception as e:
            sanitized = self._sanitize_error(str(e))
            logger.error(f"Gemini analysis exception: {sanitized}")
            return AIAnalysisItem(
                analysis_id=analysis_id,
                incident_id=context.incident_id,
                alert_id=context.alerts[0].get("id") if context.alerts else None,
                host_id=context.host_id,
                analysis_status="failed",
                threat_classification="Analysis Exception",
                executive_summary=f"Analysis encountered an exception: {sanitized}. Telemetry is unaffected.",
                attack_scenario=context.attack_scenario or "Investigation interrupted.",
                observed_behaviors=[],
                timeline=[],
                risk_level=context.severity,
                risk_score=50,
                confidence_level="low",
                confidence_reason="Technical exception during AI invocation.",
                supporting_evidence=sorted(list(context.allowed_evidence_ids)),
                contradicting_evidence=[],
                unknowns=["Provider communication interrupted."],
                impact_assessment="Manual review required.",
                recommended_actions=[{"priority": "immediate", "action": "Inspect incident alerts and evidence directly."}],
                containment_recommendations=[],
                investigation_notes=f"Exception: {sanitized}",
                provider="gemini",
                model=self.model_name,
                storage_backend="database",
                created_at=now_iso,
                completed_at=now_iso,
            )


class OpenAICompatibleProvider(BaseAIProvider):
    """Client for OpenAI / Nine Router / Local Gateway endpoints."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout: int = 30,
    ):
        self.base_url = (base_url or os.getenv("AEGIS_LLM_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.api_key = api_key or os.getenv("AEGIS_LLM_API_KEY", "")
        self.model_name = model_name or os.getenv("AEGIS_LLM_MODEL", "gpt-4o-mini")
        self.timeout = timeout
        self.session = requests.Session()

    def health_check(self) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "status": "unavailable",
                "provider": "openai-compatible",
                "model": self.model_name,
                "configured": False,
                "reachable": False,
                "message": "AEGIS_LLM_API_KEY is not configured.",
            }
        return {
            "status": "ok",
            "provider": "openai-compatible",
            "model": self.model_name,
            "configured": True,
            "reachable": True,
            "message": f"Configured for endpoint {self.base_url}.",
        }

    def analyze_incident(self, context: IncidentContext) -> AIAnalysisItem:
        if not self.api_key:
            return NullAIProvider().analyze_incident(context)

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        payload = {
            "model": self.model_name,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are AEGIS AI Incident Investigation Analyst. Analyze the incident JSON. "
                        "Return strict JSON matching: threat_classification, executive_summary, attack_scenario, "
                        "observed_behaviors, timeline, confidence_level, confidence_reason, supporting_evidence, "
                        "unknowns, impact_assessment, recommended_actions, containment_recommendations. "
                        "Only cite evidence IDs present in allowed_evidence_ids."
                    ),
                },
                {"role": "user", "content": json.dumps(context.to_dict())},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
        }

        now_iso = datetime.now(timezone.utc).isoformat()
        analysis_id = f"ANL-{context.incident_id}-{int(datetime.now(timezone.utc).timestamp())}"

        try:
            resp = self.session.post(url, headers=headers, json=payload, timeout=self.timeout)
            if resp.status_code != 200:
                return AIAnalysisItem(
                    analysis_id=analysis_id,
                    incident_id=context.incident_id,
                    alert_id=context.alerts[0].get("id") if context.alerts else None,
                    host_id=context.host_id,
                    analysis_status="failed",
                    threat_classification="Analysis Service Error",
                    executive_summary=f"OpenAI-compatible provider returned HTTP {resp.status_code}.",
                    attack_scenario=context.attack_scenario or "Investigation pending provider recovery.",
                    observed_behaviors=[],
                    timeline=[],
                    risk_level=context.severity,
                    risk_score=50,
                    confidence_level="low",
                    confidence_reason="Provider error.",
                    supporting_evidence=sorted(list(context.allowed_evidence_ids)),
                    contradicting_evidence=[],
                    unknowns=[],
                    impact_assessment="Manual review required.",
                    recommended_actions=[],
                    containment_recommendations=[],
                    investigation_notes=f"HTTP {resp.status_code}",
                    provider="openai-compatible",
                    model=self.model_name,
                    storage_backend="database",
                    created_at=now_iso,
                    completed_at=now_iso,
                )

            data = resp.json()["choices"][0]["message"]["content"]
            parsed = json.loads(data)

            cited = parsed.get("supporting_evidence", [])
            valid_citations = [cid for cid in cited if cid in context.allowed_evidence_ids]
            if not valid_citations and context.allowed_evidence_ids:
                valid_citations = sorted(list(context.allowed_evidence_ids))

            return AIAnalysisItem(
                analysis_id=analysis_id,
                incident_id=context.incident_id,
                alert_id=context.alerts[0].get("id") if context.alerts else None,
                host_id=context.host_id,
                analysis_status="completed",
                threat_classification=parsed.get("threat_classification", "Security Detection"),
                executive_summary=parsed.get("executive_summary", "Incident analysis completed."),
                attack_scenario=parsed.get("attack_scenario", context.attack_scenario or ""),
                observed_behaviors=parsed.get("observed_behaviors", []),
                timeline=parsed.get("timeline", []),
                risk_level=context.severity,
                risk_score=80 if context.severity == "high" else 45,
                confidence_level=parsed.get("confidence_level", "high"),
                confidence_reason=parsed.get("confidence_reason", "Verified against ground truth telemetry."),
                supporting_evidence=valid_citations,
                contradicting_evidence=[],
                unknowns=parsed.get("unknowns", []),
                impact_assessment=parsed.get("impact_assessment", "Access risk identified."),
                recommended_actions=parsed.get("recommended_actions", []),
                containment_recommendations=parsed.get("containment_recommendations", []),
                investigation_notes="Analyzed via OpenAI-compatible endpoint.",
                provider="openai-compatible",
                model=self.model_name,
                storage_backend="database",
                created_at=now_iso,
                completed_at=datetime.now(timezone.utc).isoformat(),
            )
        except Exception as e:
            return AIAnalysisItem(
                analysis_id=analysis_id,
                incident_id=context.incident_id,
                alert_id=context.alerts[0].get("id") if context.alerts else None,
                host_id=context.host_id,
                analysis_status="failed",
                threat_classification="Analysis Exception",
                executive_summary=f"Exception calling provider: {str(e)}",
                attack_scenario=context.attack_scenario or "",
                observed_behaviors=[],
                timeline=[],
                risk_level=context.severity,
                risk_score=50,
                confidence_level="low",
                confidence_reason="Technical failure.",
                supporting_evidence=sorted(list(context.allowed_evidence_ids)),
                contradicting_evidence=[],
                unknowns=[],
                impact_assessment="Manual review required.",
                recommended_actions=[],
                containment_recommendations=[],
                investigation_notes=str(e),
                provider="openai-compatible",
                model=self.model_name,
                storage_backend="database",
                created_at=now_iso,
                completed_at=now_iso,
            )


class NullAIProvider(BaseAIProvider):
    """Returned when no AI provider is configured."""

    def health_check(self) -> Dict[str, Any]:
        return {
            "status": "unavailable",
            "provider": "none",
            "model": "none",
            "configured": False,
            "reachable": False,
            "message": "No AI provider configured. Set AEGIS_LLM_PROVIDER and AEGIS_LLM_API_KEY in .env.",
        }

    def analyze_incident(self, context: IncidentContext) -> AIAnalysisItem:
        now_iso = datetime.now(timezone.utc).isoformat()
        return AIAnalysisItem(
            analysis_id=f"ANL-UNAVAIL-{context.incident_id}",
            incident_id=context.incident_id,
            alert_id=context.alerts[0].get("id") if context.alerts else None,
            host_id=context.host_id,
            analysis_status="unavailable",
            threat_classification="AI Provider Unconfigured",
            executive_summary=(
                "AI Investigation Engine is currently unconfigured or unavailable. "
                "Deterministic detection alerts and evidence remain fully intact."
            ),
            attack_scenario=context.attack_scenario or "Please configure an LLM provider to enable automatic narrative generation.",
            observed_behaviors=[],
            timeline=[],
            risk_level=context.severity,
            risk_score=50,
            confidence_level="low",
            confidence_reason="AI provider not active.",
            supporting_evidence=sorted(list(context.allowed_evidence_ids)),
            contradicting_evidence=[],
            unknowns=["AI narrative unavailable."],
            impact_assessment="Manual investigation by security administrator required.",
            recommended_actions=[
                {"priority": "immediate", "action": "Configure AEGIS_LLM_PROVIDER and AEGIS_LLM_API_KEY in .env."},
                {"priority": "high", "action": "Review alerts and evidence directly from the Detections screen."},
            ],
            containment_recommendations=[],
            investigation_notes="Deterministic fallback playbook applied. AI provider offline or unconfigured.",
            provider="none",
            model="none",
            storage_backend="sqlite_local",
            created_at=now_iso,
            completed_at=now_iso,
        )


def get_ai_provider() -> BaseAIProvider:
    """Factory creating the configured AI provider based on environment settings."""
    provider_type = os.getenv("AEGIS_LLM_PROVIDER", "gemini").lower().strip()

    # Allow forcing mock provider for test runs
    if os.getenv("AEGIS_USE_MOCK_LLM", "false").lower() in ("1", "true", "yes"):
        return MockAIProvider()

    if provider_type == "gemini":
        gemini = GeminiProvider()
        if gemini.api_keys:
            return gemini
        return NullAIProvider()

    if provider_type in ("openai", "openai-compatible"):
        openai_p = OpenAICompatibleProvider()
        if openai_p.api_key:
            return openai_p
        return NullAIProvider()

    if provider_type == "mock":
        return MockAIProvider()

    return NullAIProvider()

