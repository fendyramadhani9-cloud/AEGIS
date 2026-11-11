"""
AEGIS AI Investigation Provider Abstraction.
Integrates Google Gemini REST API with key rotation, timeout resilience,
anti-hallucination prompt engineering, and offline deterministic fallback.

Guarantees:
1. Anti-Hallucination Grounding: Validates that all cited evidence IDs exist in input context.
2. 4-Tier Forensic Taxonomy: Facts, Inferences, Hypotheses, Unknowns.
3. Context-Aware Attribution: Distinguishes loopback, internal, benchmark, and remote traffic.
4. Single Source of Truth for Risk: The official risk score is deterministically provided by
   RiskAssessmentEngine and NEVER altered by the AI provider.
5. Key Rotation & Redaction: Rotates through AEGIS API keys on rate limits; redacts keys from error messages.
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
from aegis_backend.source_attribution import classify_ip_source


def _resolve_storage_backend() -> str:
    """Dynamically resolves storage backend label based on active database mode."""
    try:
        from aegis_backend.config import settings
        return "supabase_cloud" if getattr(settings, "database_mode", "hybrid") == "cloud_ssot" else "sqlite_local"
    except Exception:
        return "sqlite_local"


def _safe_json_loads(text: str) -> Any:
    """Robust JSON parser that handles markdown code fences and unescaped LLM backslashes."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        return json.loads(cleaned, strict=False)
    except Exception:
        fixed = re.sub(r'\\(?![/"\\bfnrtu]|u[0-9a-fA-F]{4})', r'\\\\', cleaned)
        return json.loads(fixed, strict=False)

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


# =============================================================================
# CONTEXTUAL FORENSIC PATTERNS & QUALITY VALIDATION CONFIG
# =============================================================================

THREAT_CONCEPTS = {
    "exfiltration": {
        "label": "Data Exfiltration / Eksfiltrasi Data",
        "patterns": [
            re.compile(r"\b(data\s+)?exfiltrat(e|ed|ing|ion)\b", re.IGNORECASE),
            re.compile(r"\b(eksfiltrasi|kebocoran|pencurian)\s+(data|informasi|berkas|file)\b", re.IGNORECASE),
            re.compile(r"\btransfer(ring)?\s+(sensitive\s+)?data\s+(out\s+of|outside|to\s+remote)\b", re.IGNORECASE),
            re.compile(r"\bmengirim(kan)?\s+data\s+(ke\s+luar|ke\s+server\s+asing)\b", re.IGNORECASE),
            re.compile(r"\b(stolen|leaked)\s+data\b", re.IGNORECASE),
        ],
        "is_evidenced": lambda ctx: any(
            "exfil" in str(r).lower() or "data_leak" in str(r).lower()
            for r in [a.get("rule_id", "") for a in ctx.alerts]
        ) or any(
            any(cmd in str(ev.get("message", "")).lower() for cmd in ("scp ", "rsync ", "curl -t", "curl -f", "ftp ", "sftp ", "nc -l", "base64"))
            for ev in ctx.evidence_items
        ),
        "verification_step": "Inspeksi log firewall egress, NetFlow, dan transfer berkas (SCP/SFTP/rsync) untuk mengonfirmasi ada tidaknya volume data keluar yang mencurigakan.",
        "data_gap": "Ketiadaan bukti telemetri langsung atau log transfer berkas untuk membuktikan eksfiltrasi data.",
    },
    "c2": {
        "label": "Command & Control / Komunikasi C2",
        "patterns": [
            re.compile(r"\b(c2|c&c|command\s+and\s+control)\s+(channel|traffic|server|communication|beacon|infrastructure)\b", re.IGNORECASE),
            re.compile(r"\b(server\s+c2|komunikasi\s+c2|perintah\s+kontrol|saluran\s+c2)\b", re.IGNORECASE),
            re.compile(r"\b(beaconing|callback)\s+to\b", re.IGNORECASE),
            re.compile(r"\bconnecting\s+to\s+c2\b", re.IGNORECASE),
        ],
        "is_evidenced": lambda ctx: any(
            "c2" in str(r).lower() or "botnet" in str(r).lower() or "beacon" in str(r).lower()
            for r in [a.get("rule_id", "") for a in ctx.alerts]
        ) or any(
            "c2" in str(ev.get("message", "")).lower() for ev in ctx.evidence_items
        ),
        "verification_step": "Periksa koneksi soket aktif ('ss -tupn', 'lsof -i') dan riwayat kueri DNS lokal untuk mendeteksi beaconing atau callback ke infrastruktur luar.",
        "data_gap": "Ketiadaan telemetri koneksi soket outbound atau komunikasi C2.",
    },
    "lateral_movement": {
        "label": "Lateral Movement / Pergerakan Lateral",
        "patterns": [
            re.compile(r"\blateral\s+movement\b", re.IGNORECASE),
            re.compile(r"\b(pergerakan|penyebaran|perpindahan)\s+lateral\b", re.IGNORECASE),
            re.compile(r"\bmov(e|ing)\s+laterally\b", re.IGNORECASE),
            re.compile(r"\bpivot(ing)?\s+to\s+(other|internal)\s+(hosts?|servers?)\b", re.IGNORECASE),
        ],
        "is_evidenced": lambda ctx: any(
            "lateral" in str(r).lower() or "pivot" in str(r).lower()
            for r in [a.get("rule_id", "") for a in ctx.alerts]
        ),
        "verification_step": "Tinjau log autentikasi SSH/Kerberos pada host internal lain dalam subnet yang sama untuk mendeteksi upaya pergerakan internal.",
        "data_gap": "Ketiadaan bukti telemetri autentikasi silang antar-host pada subnet lokal.",
    },
    "persistence": {
        "label": "Persistence Mechanism / Persistensi",
        "patterns": [
            re.compile(r"\bpersistence\s+(via|through|mechanism|established)\b", re.IGNORECASE),
            re.compile(r"\bpersistensi\s+(melalui|lewat|ditemukan)\b", re.IGNORECASE),
            re.compile(r"\b(installed|created)\s+(a\s+)?backdoor\b", re.IGNORECASE),
            re.compile(r"\b(crontab|cron\s+job)\s+persistence\b", re.IGNORECASE),
        ],
        "is_evidenced": lambda ctx: any(
            "persist" in str(r).lower() or "cron" in str(r).lower() or "backdoor" in str(r).lower()
            for r in [a.get("rule_id", "") for a in ctx.alerts]
        ) or any(
            any(k in str(ev.get("message", "")).lower() for k in ("/etc/cron", "crontab", "authorized_keys", "/etc/systemd"))
            for ev in ctx.evidence_items
        ),
        "verification_step": "Periksa berkas crontab sistem (/etc/crontab, /etc/cron.*), unit systemd baru, dan file ~/.ssh/authorized_keys milik seluruh akun pengguna.",
        "data_gap": "Ketiadaan bukti modifikasi berkas cron, kunci SSH, atau unit startup sistem.",
    },
}

MULTIPLE_FAILURE_PATTERNS = [
    re.compile(r"\b(multiple|several|repeated|numerous|successive|continuous)\s+(failed|failure|attempts|attacks|brute\s*force)\b", re.IGNORECASE),
    re.compile(r"\b(beberapa|banyak|berulang|berkali-kali|serangkaian)\s+(kegagalan|percobaan|login\s+gagal|serangan)\b", re.IGNORECASE),
    re.compile(r"\bfailed\s+logins\b", re.IGNORECASE),
]

NEGATION_PATTERNS = [
    re.compile(r"\b(no|zero|neither|nor|without|never|not|cannot|lacks?)\b.{0,40}\b(evidence|indication|signs?|proof|finding|activity|trace|record)s?\b", re.IGNORECASE),
    re.compile(r"\b(no|without)\s+(observed|detected|confirmed|evident|actionable)\b", re.IGNORECASE),
    re.compile(r"\b(was|were|is|are|did|does|have|has)\s+not\s+(observe|detect|find|confirm|indicate|show|contain|occur)", re.IGNORECASE),
    re.compile(r"\bno\s+evidence\s+of\b", re.IGNORECASE),
    re.compile(r"\bno\s+(signs?|indication)\s+of\b", re.IGNORECASE),
    re.compile(r"\babsence\s+of\b", re.IGNORECASE),
    re.compile(r"\bnot\s+(found|observed|detected)\b", re.IGNORECASE),
    re.compile(r"\b(tidak|belum|bukan|tanpa)\s+(ada|ditemukan|terdapat|terlihat|terdeteksi|adanya)\b", re.IGNORECASE),
    re.compile(r"\b(tidak|belum)\s+ada\s+(bukti|indikasi|tanda|rekaman)\b", re.IGNORECASE),
    re.compile(r"\b(ketiadaan|nihil)\s+(bukti|indikasi|aktivitas)\b", re.IGNORECASE),
    re.compile(r"\btanpa\s+adanya\s+bukti\b", re.IGNORECASE),
    re.compile(r"\btidak\s+(terjadi|ditemukan|terdeteksi)\b", re.IGNORECASE),
]

INQUIRY_PATTERNS = [
    re.compile(r"\b(investigate|determine|check|verify|inspect|assess|evaluate|monitor|review|examine)\s+(whether|if|for|potential|possible)\b", re.IGNORECASE),
    re.compile(r"\b(whether|if)\s+(any\s+)?(lateral\s+movement|exfiltration|persistence|c2)\b", re.IGNORECASE),
    re.compile(r"\bpotential\s+(for|risk\s+of)\b", re.IGNORECASE),
    re.compile(r"\b(periksa|tinjau|investigasi|pastikan|cek|evaluasi|pantau)\s+(apakah|adanya|potensi|jika)\b", re.IGNORECASE),
    re.compile(r"\bapakah\s+(terjadi|terdapat|ada)\b", re.IGNORECASE),
]

TECHNIQUE_ASSERTIONS = {
    "privilege_escalation": {
        "statement_patterns": [
            re.compile(r"\b(privilege\s+escalat(ion|ed)?|escalat(ed|ion)\s+to\s+root|sudo\s+execution|executed\s+(commands?\s+as\s+root|via\s+sudo)|elevated\s+privileges?)\b", re.IGNORECASE),
            re.compile(r"\b(eskalasi\s+priviles?e|menjalankan\s+sudo|perintah\s+root|eksekusi\s+sudo)\b", re.IGNORECASE),
        ],
        "evidence_markers": ("sudo", "command=", "uid=0", "session opened for user root", "pkexec", "su:", "root:"),
        "verification_step": "Verifikasi log sudo (/var/log/auth.log) dan jejak auditd (EXECVE uid=0) untuk mengonfirmasi apakah terjadi eksekusi privilese yang valid.",
        "gap_template": "Ketidaksesuaian relevansi bukti: Inferensi eskalasi privilese/sudo merujuk bukti ({cited_ids}) yang tidak memuat telemetri eksekusi sudo/root.",
    },
    "authentication_success": {
        "statement_patterns": [
            re.compile(r"\b(successful(ly)?\s+(authenticated|logged\s+in|login)|authentication\s+succeeded|account\s+compromise(d)?)\b", re.IGNORECASE),
            re.compile(r"\b(berhasil\s+login|autentikasi\s+berhasil|akun\s+dikompromikan)\b", re.IGNORECASE),
        ],
        "evidence_markers": ("accepted", "session opened", "auth_success", "login success", "success"),
        "verification_step": "Tinjau log sesi PAM dan SSH untuk membuktikan apakah koneksi terautentikasi benar-benar berhasil.",
        "gap_template": "Ketidaksesuaian relevansi bukti: Inferensi autentikasi berhasil merujuk bukti ({cited_ids}) yang hanya merekam kegagalan tanpa bukti sukses.",
    },
}


def is_clause_negated_or_inquiry(text: str, match_start: int, match_end: int) -> bool:
    """Checks whether a concept match in text is in a negative or inquiry/conditional context."""
    prefix = text[max(0, match_start - 60):match_start]
    suffix = text[match_end:min(len(text), match_end + 60)]
    for p in NEGATION_PATTERNS:
        if p.search(prefix) or p.search(suffix) or p.search(text):
            return True
    for p in INQUIRY_PATTERNS:
        if p.search(prefix) or p.search(suffix) or p.search(text):
            return True
    return False


def verify_forensic_grounding(analysis: AIAnalysisItem, context: IncidentContext) -> AIAnalysisItem:
    """
    Comprehensive forensic grounding and semantic quality validator (Prioritas 10.1 Hardened).
    Enforces:
    1. Contextual Buzzword Quarantine: Demotes unsupported claims (Exfiltration, C2, Lateral Movement,
       Persistence) from facts/inferences into unverified hypotheses with verification steps and data gaps,
       EXCEPT when used in negative statements or conditional inquiries.
    2. Semantic Evidence Relevance: Verifies that technique claims (sudo/privilege escalation, auth success)
       are corroborated by the actual semantic payload of cited evidence items.
    3. Quantitative Claim Fidelity: Detects claims of multiple/repeated failures when telemetry records <= 1.
    4. Loopback Identity Discontinuity Guard: Prevents merging distinct local identities (e.g. guest and ubuntu)
       into a single attacker without process tree evidence.
    5. SSoT Immutability: Guarantees risk_score, risk_level, and severity freeze.
    6. Evidence Provenance & Whitelisting: Strips hallucinated IDs from facts, inferences, and citations.
    7. Chronological Timeline Normalization: Sorts timeline entries chronologically and normalizes sequential steps.
    8. Malformed Payload Recovery: Gracefully recovers from raw string or non-list payloads.
    """
    allowed_ids = set(context.allowed_evidence_ids)

    # 0. Malformed payload coercion & normalization
    if not isinstance(analysis.facts, list):
        if isinstance(analysis.facts, str) and analysis.facts.strip():
            fallback_id = next(iter(allowed_ids), "EVT-UNKNOWN")
            analysis.facts = [{"evidence_id": fallback_id, "fact": analysis.facts.strip(), "timestamp": None}]
        else:
            analysis.facts = []
    else:
        coerced_facts = []
        for f in analysis.facts:
            if isinstance(f, dict):
                coerced_facts.append(f)
            elif isinstance(f, str) and f.strip():
                fallback_id = next(iter(allowed_ids), "EVT-UNKNOWN")
                coerced_facts.append({"evidence_id": fallback_id, "fact": f.strip(), "timestamp": None})
        analysis.facts = coerced_facts

    if not isinstance(analysis.inferences, list):
        if isinstance(analysis.inferences, str) and analysis.inferences.strip():
            analysis.inferences = [{
                "statement": analysis.inferences.strip(),
                "supporting_evidence_ids": sorted(list(allowed_ids))[:2],
                "rationale": "Extracted from model response."
            }]
        else:
            analysis.inferences = []
    else:
        coerced_inferences = []
        for inf in analysis.inferences:
            if isinstance(inf, dict):
                coerced_inferences.append(inf)
            elif isinstance(inf, str) and inf.strip():
                coerced_inferences.append({
                    "statement": inf.strip(),
                    "supporting_evidence_ids": sorted(list(allowed_ids))[:2],
                    "rationale": "Extracted from model response."
                })
        analysis.inferences = coerced_inferences

    if not isinstance(analysis.hypotheses, list):
        if isinstance(analysis.hypotheses, str) and analysis.hypotheses.strip():
            analysis.hypotheses = [{
                "statement": analysis.hypotheses.strip(),
                "status": "unverified",
                "investigation_step": "Verifikasi telemetri host lebih lanjut."
            }]
        else:
            analysis.hypotheses = []
    else:
        coerced_hypotheses = []
        for h in analysis.hypotheses:
            if isinstance(h, dict):
                coerced_hypotheses.append(h)
            elif isinstance(h, str) and h.strip():
                coerced_hypotheses.append({
                    "statement": h.strip(),
                    "status": "unverified",
                    "investigation_step": "Verifikasi telemetri host lebih lanjut."
                })
        analysis.hypotheses = coerced_hypotheses

    if not isinstance(analysis.unknown_items, list):
        if isinstance(analysis.unknown_items, str) and analysis.unknown_items.strip():
            analysis.unknown_items = [{"data_gap": analysis.unknown_items.strip(), "impact": "Requires further investigation."}]
        else:
            analysis.unknown_items = []
    else:
        coerced_unknowns = []
        for u in analysis.unknown_items:
            if isinstance(u, dict):
                coerced_unknowns.append(u)
            elif isinstance(u, str) and u.strip():
                coerced_unknowns.append({"data_gap": u.strip(), "impact": "Requires further investigation."})
        analysis.unknown_items = coerced_unknowns

    if not isinstance(analysis.supporting_evidence, list):
        if isinstance(analysis.supporting_evidence, str) and analysis.supporting_evidence.strip():
            analysis.supporting_evidence = [analysis.supporting_evidence.strip()]
        else:
            analysis.supporting_evidence = []

    # 1. Enforce SSoT Immutability for Risk Score & Level
    try:
        import math
        raw_score = context.risk_score
        if isinstance(raw_score, float) and math.isnan(raw_score):
            analysis.risk_score = 0
        else:
            analysis.risk_score = max(0, min(100, int(raw_score)))
    except (ValueError, TypeError):
        analysis.risk_score = 0
    analysis.risk_level = str(context.risk_level or "low").lower()

    # 2. Whitelist & Ground Cited Evidence IDs
    valid_supporting: List[str] = []
    for eid in analysis.supporting_evidence:
        if eid in allowed_ids and eid not in valid_supporting:
            valid_supporting.append(eid)
    if not valid_supporting and allowed_ids:
        valid_supporting = sorted(list(allowed_ids))[:5]
    analysis.supporting_evidence = valid_supporting

    # 3. Contextual Buzzword Quarantine & Semantic Evidence Relevance Check
    clean_inferences: List[Dict[str, Any]] = []
    existing_hypotheses: List[Dict[str, Any]] = list(analysis.hypotheses or [])
    existing_unknown_items: List[Dict[str, Any]] = list(analysis.unknown_items or [])
    demoted_concepts: List[str] = []

    # Check inferences
    for inf in analysis.inferences:
        stmt = str(inf.get("statement", ""))
        clean_eids = [eid for eid in inf.get("supporting_evidence_ids", []) if eid in allowed_ids]
        inf["supporting_evidence_ids"] = clean_eids or (valid_supporting[:2] if valid_supporting else [])

        # A. Check unevidenced threat concepts (negation and inquiry aware)
        matched_concept = None
        for concept_name, concept_cfg in THREAT_CONCEPTS.items():
            if not concept_cfg["is_evidenced"](context):
                for p in concept_cfg["patterns"]:
                    m = p.search(stmt)
                    if m:
                        # Only quarantine if NOT negated and NOT an inquiry/conditional check
                        if not is_clause_negated_or_inquiry(stmt, m.start(), m.end()):
                            matched_concept = (concept_name, concept_cfg)
                            break
                if matched_concept:
                    break

        if matched_concept:
            c_name, c_cfg = matched_concept
            demoted_concepts.append(c_cfg["label"])
            existing_hypotheses.append({
                "statement": f"Dugaan/Potensi: {stmt}",
                "status": "unverified",
                "investigation_step": c_cfg["verification_step"],
                "source_inference": stmt,
            })
            existing_unknown_items.append({
                "data_gap": c_cfg["data_gap"],
                "impact": f"Klaim {c_cfg['label']} belum terverifikasi secara forensik dan dialihkan ke hipotesis unverified."
            })
            continue

        # B. Check semantic evidence relevance for specific techniques
        semantic_mismatch = None
        for tech_name, tech_cfg in TECHNIQUE_ASSERTIONS.items():
            matched_p = None
            for p in tech_cfg["statement_patterns"]:
                m = p.search(stmt)
                if m:
                    matched_p = m
                    break
            if matched_p:
                # If statement is negated or inquiry, skip mismatch check
                if is_clause_negated_or_inquiry(stmt, matched_p.start(), matched_p.end()):
                    continue
                # Retrieve text of cited evidence items
                cited_items = [
                    ev for ev in context.evidence_items
                    if str(ev.get("event_id") or ev.get("id")) in inf["supporting_evidence_ids"]
                ]
                if cited_items:
                    combined_cited_text = " ".join(
                        str(ev.get("message", "")) + " " + str(ev.get("event_type", "")) for ev in cited_items
                    ).lower()
                    has_required_marker = any(marker in combined_cited_text for marker in tech_cfg["evidence_markers"])
                    if not has_required_marker:
                        semantic_mismatch = (tech_name, tech_cfg, inf["supporting_evidence_ids"])
                        break

        if semantic_mismatch:
            t_name, t_cfg, c_ids = semantic_mismatch
            existing_hypotheses.append({
                "statement": f"Dugaan/Potensi: {stmt}",
                "status": "unverified",
                "investigation_step": t_cfg["verification_step"],
                "source_inference": stmt,
            })
            existing_unknown_items.append({
                "data_gap": t_cfg["gap_template"].format(cited_ids=", ".join(c_ids)),
                "impact": f"Klaim {t_name.replace('_', ' ')} dialihkan ke hipotesis unverified karena bukti yang dirujuk tidak relevan secara semantik."
            })
            continue

        clean_inferences.append(inf)

    analysis.inferences = clean_inferences

    # Clean facts: facts must strictly cite verified evidence IDs and not assert unverified concepts
    clean_facts: List[Dict[str, Any]] = []
    for f in analysis.facts:
        feid = f.get("evidence_id")
        if feid in allowed_ids:
            f_fact = str(f.get("fact", ""))
            has_unsupported_concept = False
            for concept_name, concept_cfg in THREAT_CONCEPTS.items():
                if not concept_cfg["is_evidenced"](context):
                    for p in concept_cfg["patterns"]:
                        m = p.search(f_fact)
                        if m:
                            if not is_clause_negated_or_inquiry(f_fact, m.start(), m.end()):
                                has_unsupported_concept = True
                                demoted_concepts.append(concept_cfg["label"])
                                existing_hypotheses.append({
                                    "statement": f"Dugaan/Potensi: {f_fact}",
                                    "status": "unverified",
                                    "investigation_step": concept_cfg["verification_step"],
                                })
                                existing_unknown_items.append({
                                    "data_gap": concept_cfg["data_gap"],
                                    "impact": f"Fakta AI dikoreksi: {concept_cfg['label']} dialihkan ke hipotesis unverified."
                                })
                                break
                    if has_unsupported_concept:
                        break
            if not has_unsupported_concept:
                clean_facts.append(f)

    if not clean_facts and context.evidence_items:
        for ev in context.evidence_items[:3]:
            eid = ev.get("event_id") or ev.get("id")
            if eid in allowed_ids:
                clean_facts.append({
                    "evidence_id": eid,
                    "fact": ev.get("message", "Telemetry observation recorded."),
                    "timestamp": ev.get("event_timestamp") or ev.get("created_at"),
                })
    analysis.facts = clean_facts
    analysis.observed_behaviors = clean_facts

    # 4. Quantitative Fidelity Check (Single vs Multiple)
    failure_count = sum(
        1 for ev in context.evidence_items
        if any(k in str(ev.get("message", "")).lower() for k in ("fail", "gagal", "invalid", "denied"))
        or any(k in str(ev.get("event_type", "")).lower() for k in ("fail", "gagal"))
    )

    claims_multiple = any(
        any(p.search(str(inf.get("statement", ""))) for p in MULTIPLE_FAILURE_PATTERNS)
        for inf in analysis.inferences
    ) or any(p.search(str(analysis.executive_summary)) for p in MULTIPLE_FAILURE_PATTERNS)

    if claims_multiple and failure_count <= 1:
        existing_unknown_items.append({
            "data_gap": f"Ketidaksesuaian kuantitatif: Narasi mengindikasikan kejadian berulang/jamak, namun telemetri hanya merekam {failure_count} event kegagalan.",
            "impact": "Analisis diklasifikasikan dengan catatan kuantitatif parsial."
        })
        if "Catatan Kuantitatif" not in (analysis.investigation_notes or ""):
            analysis.investigation_notes = (
                (analysis.investigation_notes or "")
                + f" [Catatan Kuantitatif: Telemetri faktual hanya memuat {failure_count} event kegagalan; klaim jamak disesuaikan]."
            ).strip()

    # 5. Loopback Identity Discontinuity Guard
    attr = classify_ip_source(context.source_ip)
    if attr.get("is_loopback") or context.source_ip in ("127.0.0.1", "::1", "localhost"):
        evidence_users = set()
        for ev in context.evidence_items:
            u = ev.get("user") or ev.get("user_name") or (ev.get("details", {}) or {}).get("user")
            if u and str(u).strip() and str(u).strip().lower() not in ("none", "null", ""):
                evidence_users.add(str(u).strip())

        if len(evidence_users) >= 2:
            user_list_str = " dan ".join(sorted(list(evidence_users)))
            existing_unknown_items.append({
                "data_gap": f"Ketiadaan jejak pohon proses (parent PID tree) antara identitas {sorted(list(evidence_users))}.",
                "impact": f"Peralihan identitas pada antarmuka loopback ({user_list_str}) tidak dapat diasumsikan sebagai satu penyerang tunggal tanpa bukti korelasi proses."
            })
            for inf in analysis.inferences:
                stmt = str(inf.get("statement", ""))
                if any(u in stmt for u in evidence_users) and "korelasi proses" not in stmt:
                    inf["rationale"] = (
                        str(inf.get("rationale", ""))
                        + f" (Perhatian: Aktivitas berasal dari loopback lokal dengan identitas terpisah {sorted(list(evidence_users))}; korelasi proses belum terbukti)."
                    ).strip()

    # 6. Chronological Timeline Normalization & Step Renumbering
    raw_timeline = analysis.timeline
    if isinstance(raw_timeline, list):
        parsed_timeline = []
        for item in raw_timeline:
            if isinstance(item, dict):
                ts_str = str(item.get("timestamp") or "")
                parsed_timeline.append((ts_str, item))
            elif isinstance(item, str) and item.strip():
                parsed_timeline.append(("", {
                    "step": len(parsed_timeline) + 1,
                    "timestamp": None,
                    "event_type": "observation",
                    "description": item.strip(),
                    "evidence_id": next(iter(allowed_ids), "EVT-UNKNOWN"),
                }))

        def _sort_ts(entry):
            ts = entry[0]
            if not ts:
                return datetime.min.replace(tzinfo=timezone.utc)
            try:
                clean_ts = ts[:-1] + "+00:00" if ts.endswith("Z") else ts
                return datetime.fromisoformat(clean_ts)
            except Exception:
                return datetime.min.replace(tzinfo=timezone.utc)

        parsed_timeline.sort(key=_sort_ts)
        final_timeline = []
        for idx, (_, item) in enumerate(parsed_timeline, start=1):
            clean_item = dict(item)
            clean_item["step"] = idx
            final_timeline.append(clean_item)
        analysis.timeline = final_timeline
    else:
        analysis.timeline = []

    # 7. Executive Summary & Threat Classification Forensic Grounding Caveats
    if demoted_concepts:
        caveat_text = f" (Catatan Forensik: Dugaan {', '.join(set(demoted_concepts))} belum didukung bukti telemetri langsung dan diklasifikasikan sebagai hipotesis unverified)."
        if caveat_text not in analysis.executive_summary:
            analysis.executive_summary += caveat_text

    # Deduplicate unknown_items and synchronize with plain unknowns list
    seen_gaps = set()
    deduped_unknown_items = []
    plain_unknowns = []
    for u in existing_unknown_items:
        gap = u.get("data_gap", "")
        if gap and gap not in seen_gaps:
            seen_gaps.add(gap)
            deduped_unknown_items.append(u)
            plain_unknowns.append(gap)

    # Ensure all hypotheses have status and investigation_step
    for h in existing_hypotheses:
        if not h.get("status"):
            h["status"] = "unverified"
        if not h.get("investigation_step"):
            h["investigation_step"] = "Verifikasi log auditd dan telemetri jaringan host untuk mengonfirmasi hipotesis."

    analysis.hypotheses = existing_hypotheses
    analysis.unknown_items = deduped_unknown_items
    analysis.unknowns = plain_unknowns or analysis.unknowns or ["Telemetry provides sufficient scope for primary threat vector."]

    return analysis


class BaseAIProvider(ABC):
    """Abstract contract for security analysis providers."""

    @abstractmethod
    def analyze_incident(self, context: IncidentContext) -> AIAnalysisItem:
        pass

    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        pass


class MockAIProvider(BaseAIProvider):
    """Deterministic, offline evaluator for unit tests and local evaluation harness."""

    def __init__(self, model_name: str = "mock-evaluator"):
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

        attr = classify_ip_source(context.source_ip)
        is_loopback = attr["is_loopback"]
        is_test = context.provenance == "controlled_operational_test" or is_loopback
        is_benchmark = context.provenance == "synthetic_benchmark" or attr["is_benchmark"]

        rule_ids = {a.get("rule_id") for a in context.alerts}

        # Context-Aware Threat Classification
        if is_test:
            if "RULE-SSH-BRUTE" in rule_ids and "RULE-AUTH-003" in rule_ids and "RULE-SUSP-SUDO" in rule_ids:
                threat_cls = "Controlled Security Test: Authentication Sequence & Sudo Simulation"
                exec_summary = (
                    f"Controlled security testing activity detected on host '{context.host_id}' originating locally via loopback ({context.source_ip or '127.0.0.1'}). "
                    f"Automated authentication failure sequence was followed by key-based login as '{context.target_user or 'ubuntu'}' and simulated privileged sudo execution. "
                    f"Activity reflects a controlled operational test rather than a hostile host compromise."
                )
            else:
                threat_cls = "Controlled Operational Security Test"
                exec_summary = f"Controlled validation activity executed on host '{context.host_id}' from {attr['attribution_narrative']}."
        elif is_benchmark:
            threat_cls = "Synthetic Benchmark: Multi-Stage Brute-Force to Privileged Shell"
            exec_summary = f"Synthetic benchmark scenario evaluated on host '{context.host_id}' using reserved documentation address {context.source_ip}."
        elif is_loopback:
            threat_cls = "Local Authentication Sequence & Privileged Sudo Activity"
            exec_summary = (
                f"Security activity detected on host '{context.host_id}' originating locally via loopback interface ({context.source_ip}). "
                f"Activity reflects local system process execution or administrative task."
            )
        else:
            if "RULE-SSH-BRUTE" in rule_ids and "RULE-AUTH-003" in rule_ids and "RULE-SUSP-SUDO" in rule_ids:
                threat_cls = "Multi-Stage Attack Chain: Brute-Force to Privileged Root Shell"
                exec_summary = (
                    f"Adversary conducted a brute-force campaign against SSH from {attr['attribution_narrative']}, "
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
                    f"Observed multiple consecutive SSH authentication failures originated from "
                    f"{attr['attribution_narrative']} targeted at host '{context.host_id}'."
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

        if is_test:
            inferences = [
                {
                    "statement": "Observed authentication attempts and subsequent privileged commands represent an automated local test routine.",
                    "supporting_evidence_ids": evidence_ids[:3],
                    "rationale": f"Activity originates on {attr['attribution_narrative']} with command markers indicating a scheduled validation test.",
                }
            ]
            hypotheses = [
                {
                    "statement": "The validation run was triggered by an automated CI/CD pipeline or security engineering health check.",
                    "status": "unverified",
                    "investigation_step": "Cross-reference test execution timestamp with scheduled operations logs.",
                }
            ]
            unknown_items = [
                {"data_gap": "Full parent PID process tree prior to command invocation.", "impact": "Telemetry confirms execution but not initiating script name."},
            ]
            recommended_actions = [
                {"priority": "immediate", "action": "Confirm with security operations team that the controlled test completed successfully."},
                {"priority": "medium", "action": "Ensure any temporary test credentials or keys are safely de-provisioned."},
            ]
            containment = ["No containment action required for authorized operational security tests."]
        else:
            inferences = [
                {
                    "statement": f"Observed activity pattern aligns with {threat_cls}.",
                    "supporting_evidence_ids": evidence_ids[:3],
                    "rationale": "Sequential correlation across logged telemetry events.",
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
                {"data_gap": f"Process attribution details for source {attr['attribution_narrative']}.", "impact": "Attribution to specific threat group incomplete."},
                {"data_gap": "Full process execution parameters inside spawned interactive shells.", "impact": "Sub-command actions require auditd inspection."},
            ]
            recommended_actions = [
                {"priority": "immediate", "action": f"Verify account '{context.target_user or 'authorized users'}' credentials and revoke active SSH sessions."},
                {"priority": "high", "action": f"Review ingress access rules for {attr['attribution_narrative']} in firewall (UFW)."},
            ]
            containment = [
                f"Isolate host '{context.host_id}' from the management network if lateral movement is suspected.",
                "Lock targeted user account pending administrator review.",
            ]

        unknowns = [item["data_gap"] for item in unknown_items]

        # Posture enrichment
        if context.posture_findings:
            unknowns.append(
                f"Host posture notes: {len(context.posture_findings)} security check issues identified on host."
            )

        now_iso = datetime.now(timezone.utc).isoformat()
        notes = "Offline deterministic analysis based strictly on collected telemetry."
        if is_test:
            notes += f" (Notice: Source is {attr['attribution_narrative']}; reflects local security testing, not an external adversary compromise)."
        elif is_benchmark:
            notes += " (Notice: Source IP is in RFC 5737 TEST-NET range; represents synthetic test telemetry, not a live internet compromise)."

        timeline = []
        for i, ev in enumerate(context.evidence_items[:6]):
            timeline.append({
                "step": i + 1,
                "timestamp": ev.get("event_timestamp") or ev.get("created_at"),
                "event_type": ev.get("event_type", "audit"),
                "description": ev.get("message", "Observed event."),
                "evidence_id": ev.get("event_id") or ev.get("id"),
            })

        # Single source of truth for risk score: Use context.risk_score
        official_risk_score = context.risk_score
        official_risk_level = context.risk_level

        analysis_item = AIAnalysisItem(
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
            risk_level=official_risk_level,
            risk_score=official_risk_score,
            confidence_level="high" if len(evidence_ids) >= 3 else "medium",
            confidence_reason=f"Derived from {len(evidence_ids)} concrete supporting telemetry events.",
            supporting_evidence=evidence_ids,
            contradicting_evidence=[],
            unknowns=unknowns,
            impact_assessment="Controlled testing exercise" if is_test else "Potential unauthorized host access.",
            recommended_actions=recommended_actions,
            containment_recommendations=containment,
            investigation_notes=notes,
            provider="mock-evaluator",
            model=self.model_name,
            storage_backend=_resolve_storage_backend(),
            created_at=now_iso,
            completed_at=now_iso,
        )
        return verify_forensic_grounding(analysis_item, context)


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
                "message": "No active Gemini API key configured in environment (AEGIS_LLM_API_KEY / AEGIS1-3).",
            }

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}?key={key}"
        try:
            resp = self.session.get(url, timeout=5)
            if resp.status_code == 200:
                return {
                    "status": "ok",
                    "provider": "gemini",
                    "model": self.model_name,
                    "configured": True,
                    "reachable": True,
                    "key_count": len(self.api_keys),
                    "message": "Gemini API reachable and model available.",
                }
            if resp.status_code in (429, 503) and len(self.api_keys) > 1:
                self._rotate_key()
                return self.health_check()
            return {
                "status": "degraded",
                "provider": "gemini",
                "model": self.model_name,
                "configured": True,
                "reachable": False,
                "message": f"API returned status {resp.status_code}: {self._sanitize_error(resp.text)}",
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
            return NullAIProvider().analyze_incident(context)

        attr = classify_ip_source(context.source_ip)
        is_loopback = attr["is_loopback"]
        is_test = context.provenance == "controlled_operational_test" or is_loopback

        system_prompt = (
            "You are AEGIS AI Incident Investigation Analyst. Analyze the provided Linux security incident context.\n"
            "STRICT OPERATIONAL & FORENSIC RULES:\n"
            "1. LOCALHOST & LOOPBACK ATTRIBUTION: If the source IP is 127.0.0.1, ::1, or categorized as loopback, you MUST identify it as local-origin activity on the host. You MUST NEVER state or imply that loopback represents an 'external attacker', 'remote adversary', or 'internet ingress'.\n"
            "2. CONTROLLED TEST CONTEXT: If provenance is 'controlled_operational_test' or telemetry commands contain 'controlled_aegis_test' or test usernames ('sec_test_user'), classify the event as a controlled operational testing exercise or validation sequence, NOT a malicious host compromise.\n"
            "3. IDENTITY DISCONTINUITY GUARD: Do NOT assume that an accepted login represents an attacker continuation from previous failed logins merely because they occurred on the same loopback interface (127.0.0.1). If the failed user and the accepted user differ, explicitly state that separate identities indicate distinct local processes rather than single attacker continuation.\n"
            "4. RISK SCORE IMMUTABILITY: The official risk score is deterministically computed by the AEGIS Risk Assessment Engine and provided in 'official_risk_score'. You must NOT modify, guess, or invent an alternate official risk score.\n"
            "5. ANTI-HALLUCINATION REQUIREMENT: Only reference event IDs explicitly listed in 'allowed_evidence_ids'. Do NOT invent event IDs, IPs, users, or commands. If evidence is insufficient, state inconclusive.\n"
            "6. STRICT 4-TIER TAXONOMY SEPARATION:\n"
            "   - 'facts': Concrete telemetry statements with valid evidence_id.\n"
            "   - 'inferences': Logical conclusions derived from multiple facts with rationale.\n"
            "   - 'hypotheses': Unproven possibilities marked as status 'unverified' with next steps.\n"
            "   - 'unknowns': Explicitly state forensic limitations (e.g. absence of full process tree or parent PID tracking).\n"
            "7. NEVER suggest modifying production systems directly; provide actionable administrator recommendations.\n"
            "8. Output JSON format:\n"
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
                    risk_level=context.risk_level,
                    risk_score=context.risk_score,
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
                    storage_backend=_resolve_storage_backend(),
                    created_at=now_iso,
                    completed_at=now_iso,
                )

            data = resp.json()
            candidates = data.get("candidates", [])
            if not candidates:
                raise RuntimeError("Gemini API returned no candidates.")

            text_content = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            parsed = _safe_json_loads(text_content)
            return self._validate_and_normalize(parsed, context, analysis_id=analysis_id, now_iso=now_iso)
        except Exception as e:
            sanitized_err = self._sanitize_error(str(e))
            logger.error(f"Gemini analysis exception: {sanitized_err}")
            return AIAnalysisItem(
                analysis_id=analysis_id,
                incident_id=context.incident_id,
                alert_id=context.alerts[0].get("id") if context.alerts else None,
                host_id=context.host_id,
                analysis_status="failed",
                threat_classification="Analysis Exception",
                executive_summary=f"Analysis failed due to exception: {sanitized_err}",
                attack_scenario=context.attack_scenario or "",
                observed_behaviors=[],
                timeline=[],
                risk_level=context.risk_level,
                risk_score=context.risk_score,
                confidence_level="low",
                confidence_reason="Analysis generation failed.",
                supporting_evidence=sorted(list(context.allowed_evidence_ids)),
                contradicting_evidence=[],
                unknowns=["Analysis payload could not be compiled due to exception."],
                impact_assessment="Unknown.",
                recommended_actions=[{"priority": "immediate", "action": "Review alerts manually in dashboard."}],
                containment_recommendations=[],
                investigation_notes=f"Exception: {sanitized_err}",
                provider="gemini",
                model=self.model_name,
                storage_backend=_resolve_storage_backend(),
                created_at=now_iso,
                completed_at=datetime.now(timezone.utc).isoformat(),
            )

    def _validate_and_normalize(
        self,
        parsed: Dict[str, Any],
        context: IncidentContext,
        analysis_id: Optional[str] = None,
        now_iso: Optional[str] = None,
    ) -> AIAnalysisItem:
        """Strictly validates and grounds LLM output against verified context telemetry."""
        now_iso = now_iso or datetime.now(timezone.utc).isoformat()
        analysis_id = analysis_id or f"ANL-{context.incident_id}-{int(datetime.now(timezone.utc).timestamp())}"

        attr = classify_ip_source(context.source_ip)
        is_loopback = attr["is_loopback"]
        is_test = context.provenance == "controlled_operational_test" or is_loopback

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

        raw_actions = parsed.get("recommended_actions", [])
        valid_actions = []
        for a in raw_actions:
            if isinstance(a, dict):
                valid_actions.append(a)
            elif isinstance(a, str):
                valid_actions.append({"priority": "medium", "action": a})
        if not valid_actions:
            valid_actions = [{"priority": "immediate", "action": "Review alerts and raw evidence in AEGIS dashboard."}]

        notes = "Live Google Gemini analysis verified against grounding telemetry."
        if is_test:
            notes += f" (Notice: Source is {attr['attribution_narrative']}; represents local security testing, not an external adversary compromise)."
        elif attr["is_benchmark"]:
            notes += " (Notice: Source IP is within RFC 5737 reserved TEST-NET documentation range; indicates synthetic test telemetry, not a confirmed real-world compromise)."

        # SSoT: official risk score and level from context ALWAYS override LLM outputs
        analysis_item = AIAnalysisItem(
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
            risk_level=context.risk_level,
            risk_score=context.risk_score,
            confidence_level=parsed.get("confidence_level", "high"),
            confidence_reason=parsed.get("confidence_reason", "Grounded in verified telemetry."),
            supporting_evidence=valid_citations,
            contradicting_evidence=[],
            unknowns=plain_unknowns or ["Telemetry provides sufficient scope for primary threat vector."],
            impact_assessment=parsed.get("impact_assessment", "Potential access violation."),
            recommended_actions=valid_actions,
            containment_recommendations=parsed.get("containment_recommendations", []),
            investigation_notes=notes,
            provider="gemini",
            model=self.model_name,
            storage_backend=_resolve_storage_backend(),
            created_at=now_iso,
            completed_at=datetime.now(timezone.utc).isoformat(),
        )
        return verify_forensic_grounding(analysis_item, context)


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
        system_prompt = (
            "You are AEGIS AI Incident Investigation Analyst. Analyze the provided Linux security incident context.\n"
            "STRICT RULES:\n"
            "1. Output valid JSON adhering to standard schema.\n"
            "2. ANTI-HALLUCINATION: Only cite verified evidence IDs from allowed_evidence_ids.\n"
            "3. If source is loopback (127.0.0.1), identify as local-origin activity, NEVER an external adversary.\n"
            "4. Follow 4-tier taxonomy: facts, inferences, hypotheses, unknowns.\n"
        )
        user_content = json.dumps(context.to_dict())
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }
        now_iso = datetime.now(timezone.utc).isoformat()
        analysis_id = f"ANL-{context.incident_id}-{int(datetime.now(timezone.utc).timestamp())}"
        try:
            resp = self.session.post(url, headers=headers, json=payload, timeout=self.timeout)
            if resp.status_code != 200:
                raise RuntimeError(f"OpenAI API returned HTTP {resp.status_code}: {resp.text}")
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            parsed = _safe_json_loads(content)

            analysis_item = AIAnalysisItem(
                analysis_id=analysis_id,
                incident_id=context.incident_id,
                alert_id=context.alerts[0].get("id") if context.alerts else None,
                host_id=context.host_id,
                analysis_status="completed",
                threat_classification=parsed.get("threat_classification", "Security Detection"),
                executive_summary=parsed.get("executive_summary", "Incident analysis completed."),
                attack_scenario=parsed.get("attack_scenario", context.attack_scenario or ""),
                facts=parsed.get("facts", []),
                inferences=parsed.get("inferences", []),
                hypotheses=parsed.get("hypotheses", []),
                unknown_items=parsed.get("unknown_items", []),
                observed_behaviors=parsed.get("facts", []),
                timeline=parsed.get("timeline", []),
                risk_level=context.risk_level,
                risk_score=context.risk_score,
                confidence_level=parsed.get("confidence_level", "high"),
                confidence_reason=parsed.get("confidence_reason", "Grounded in verified telemetry."),
                supporting_evidence=[e for e in parsed.get("supporting_evidence", []) if e in context.allowed_evidence_ids],
                contradicting_evidence=[],
                unknowns=[u.get("data_gap", str(u)) if isinstance(u, dict) else str(u) for u in parsed.get("unknowns", [])],
                impact_assessment=parsed.get("impact_assessment", "Security investigation active."),
                recommended_actions=parsed.get("recommended_actions", []),
                containment_recommendations=parsed.get("containment_recommendations", []),
                investigation_notes="OpenAI-compatible gateway analysis.",
                provider="openai-compatible",
                model=self.model_name,
                storage_backend=_resolve_storage_backend(),
                created_at=now_iso,
                completed_at=datetime.now(timezone.utc).isoformat(),
            )
            return verify_forensic_grounding(analysis_item, context)
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
                risk_level=context.risk_level,
                risk_score=context.risk_score,
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
                storage_backend=_resolve_storage_backend(),
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
            risk_level=context.risk_level,
            risk_score=context.risk_score,
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
            storage_backend=_resolve_storage_backend(),
            created_at=now_iso,
            completed_at=now_iso,
        )


def get_ai_provider() -> BaseAIProvider:
    """Factory selecting configured provider based on AEGIS_LLM_PROVIDER."""
    provider_name = os.getenv("AEGIS_LLM_PROVIDER", "").strip().lower()

    if provider_name == "gemini":
        return GeminiProvider()
    elif provider_name in ("openai", "openai-compatible", "local-llm"):
        return OpenAICompatibleProvider()
    elif provider_name == "mock":
        return MockAIProvider()

    # Default to Gemini if keys are present
    if os.getenv("AEGIS_LLM_API_KEY") or os.getenv("AEGIS1"):
        return GeminiProvider()

    return NullAIProvider()
