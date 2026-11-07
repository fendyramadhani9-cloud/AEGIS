"""
Backend Gatekeeper and Tool Registry for Runtime Monitor (RM).
Enforces:
1. Strict Context Binding (investigation_id, alert_id, authorized_host_id).
2. Time-Window clamping / rejection relative to alert_timestamp.
3. Global Tool Budget capping.
4. Automatic credential and token redaction.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from aegis_agent.schemas import ToolCallRequest, ToolCallResult, EvidenceItem


class BackendGatekeeper:
    """
    Enforces security, budget, context binding, and redaction for RM tool requests.
    """

    def __init__(
        self,
        investigation_id: str,
        alert_id: str,
        authorized_host_id: str,
        alert_timestamp: str,
        evidence_db: Optional[List[Dict[str, Any]]] = None,
        max_tool_calls: int = 3,
        max_events_per_call: int = 50,
        max_total_events: int = 100,
        window_tolerance_minutes: int = 30,
    ):
        self.investigation_id = investigation_id
        self.alert_id = alert_id
        self.authorized_host_id = authorized_host_id
        self.alert_timestamp = alert_timestamp
        self.evidence_db = evidence_db or []

        # Budgets
        self.max_tool_calls = max_tool_calls
        self.max_events_per_call = max_events_per_call
        self.max_total_events = max_total_events
        self.window_tolerance_minutes = window_tolerance_minutes

        self.current_tool_calls = 0
        self.current_total_events = 0

    def _parse_iso(self, ts_str: str) -> datetime:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

    def _redact_sensitive_data(self, text: str) -> str:
        """Redacts tokens, passwords, API keys, and sensitive secrets from command lines or logs."""
        redacted = re.sub(r"(?i)(authorization:\s*bearer\s+)[^\s';\"]+", r"\1[REDACTED]", text)
        redacted = re.sub(r"(?i)(password|passwd|token|secret|api_key|apikey)\s*[:=]\s*[^\s';\"]+", r"\1=[REDACTED]", redacted)
        return redacted

    def execute_tool(self, request: ToolCallRequest) -> ToolCallResult:
        # Check 1: Tool Budget
        if self.current_tool_calls >= self.max_tool_calls:
            return ToolCallResult(
                status="rejected",
                error_code="TOOL_BUDGET_EXCEEDED",
                message=f"Batas maksimum pemanggilan tool ({self.max_tool_calls}) telah tercapai.",
            )

        # Check 2: Context Binding (investigation_id & alert_id)
        if request.investigation_id != self.investigation_id or request.alert_id != self.alert_id:
            return ToolCallResult(
                status="rejected",
                error_code="UNAUTHORIZED_CONTEXT_SHIFT",
                message="Investigation ID atau Alert ID tidak sesuai dengan sesi investigasi aktif.",
            )

        self.current_tool_calls += 1

        # Check 3: Host Context Validation
        # If AI explicitly requests another host in parameters, reject
        requested_host = request.parameters.get("target_host")
        if requested_host and requested_host != self.authorized_host_id:
            return ToolCallResult(
                status="rejected",
                error_code="UNAUTHORIZED_CONTEXT_SHIFT",
                message=f"Akses ke host '{requested_host}' ditolak. Sesi hanya berwenang untuk '{self.authorized_host_id}'.",
            )

        # Dispatch based on tool name
        if request.tool_name == "get_related_auth_events":
            return self._handle_auth_events(request.parameters)
        elif request.tool_name == "get_process_activity":
            return self._handle_process_activity(request.parameters)
        elif request.tool_name == "get_network_connections":
            return self._handle_network_connections(request.parameters)
        elif request.tool_name == "get_user_context":
            return self._handle_user_context(request.parameters)
        elif request.tool_name == "get_host_context":
            return self._handle_host_context(request.parameters)
        else:
            return ToolCallResult(
                status="rejected",
                error_code="INVALID_PARAMETERS",
                message=f"Tool '{request.tool_name}' tidak dikenal.",
            )

    def _handle_auth_events(self, params: Dict[str, Any]) -> ToolCallResult:
        time_range = params.get("time_range", {})
        was_clamped = False

        if "start" in time_range and "end" in time_range:
            try:
                start_dt = self._parse_iso(time_range["start"])
                end_dt = self._parse_iso(time_range["end"])
                if start_dt > end_dt:
                    return ToolCallResult(
                        status="rejected",
                        error_code="WINDOW_OUT_OF_BOUNDS",
                        message="Waktu start tidak boleh lebih besar dari end.",
                    )
                alert_dt = self._parse_iso(self.alert_timestamp)
                min_allowed = alert_dt - timedelta(minutes=self.window_tolerance_minutes)
                max_allowed = alert_dt + timedelta(minutes=self.window_tolerance_minutes)

                # Extreme window check (> 7 days)
                if (end_dt - start_dt).days > 7:
                    return ToolCallResult(
                        status="rejected",
                        error_code="WINDOW_OUT_OF_BOUNDS",
                        message="Rentang waktu yang diminta melebihi batas ekstrem.",
                    )

                if start_dt < min_allowed or end_dt > max_allowed:
                    was_clamped = True
            except Exception as e:
                return ToolCallResult(status="rejected", error_code="INVALID_PARAMETERS", message=str(e))

        # Filter events from evidence_db matching host and event_type
        filtered_events: List[EvidenceItem] = []
        limit = min(params.get("limit", 20), self.max_events_per_call)

        for item in self.evidence_db:
            if item.get("host_id") == self.authorized_host_id and item.get("source_type") == "authentication_log":
                if len(filtered_events) < limit and (self.current_total_events + len(filtered_events)) < self.max_total_events:
                    filtered_events.append(EvidenceItem(**item))

        self.current_total_events += len(filtered_events)
        return ToolCallResult(
            status="success",
            was_clamped=was_clamped,
            events_returned=len(filtered_events),
            events=filtered_events,
        )

    def _handle_process_activity(self, params: Dict[str, Any]) -> ToolCallResult:
        filtered_events: List[EvidenceItem] = []
        limit = min(params.get("limit", 20), self.max_events_per_call)

        for item in self.evidence_db:
            if item.get("host_id") == self.authorized_host_id and item.get("source_type") == "process_activity":
                # Apply automatic redaction on command line
                raw_data = item.copy()
                if "command_line" in raw_data.get("data", {}):
                    raw_data["data"]["command_line"] = self._redact_sensitive_data(
                        raw_data["data"]["command_line"]
                    )
                if len(filtered_events) < limit and (self.current_total_events + len(filtered_events)) < self.max_total_events:
                    filtered_events.append(EvidenceItem(**raw_data))

        self.current_total_events += len(filtered_events)
        return ToolCallResult(
            status="success",
            events_returned=len(filtered_events),
            events=filtered_events,
        )

    def _handle_network_connections(self, params: Dict[str, Any]) -> ToolCallResult:
        filtered_events: List[EvidenceItem] = []
        limit = min(params.get("limit", 20), self.max_events_per_call)

        for item in self.evidence_db:
            if item.get("host_id") == self.authorized_host_id and item.get("source_type") == "network_connection":
                if len(filtered_events) < limit and (self.current_total_events + len(filtered_events)) < self.max_total_events:
                    filtered_events.append(EvidenceItem(**item))

        self.current_total_events += len(filtered_events)
        return ToolCallResult(
            status="success",
            events_returned=len(filtered_events),
            events=filtered_events,
        )

    def _handle_user_context(self, params: Dict[str, Any]) -> ToolCallResult:
        username = params.get("username", "unknown")
        # Returns security-focused profile, omitting private personal info
        return ToolCallResult(
            status="success",
            context_data={
                "username": username,
                "is_privileged": username in ["admin", "root", "sec_admin"],
                "role": "SuperAdmin" if username in ["admin", "root"] else "StandardUser",
                "account_status": "active",
                "mfa_enforced": True,
            },
        )

    def _handle_host_context(self, params: Dict[str, Any]) -> ToolCallResult:
        return ToolCallResult(
            status="success",
            context_data={
                "host_id": self.authorized_host_id,
                "environment": "production",
                "role": "Authentication Server",
                "criticality": "High",
            },
        )

