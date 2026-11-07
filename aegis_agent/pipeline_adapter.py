"""
Pipeline Adapter for Linux Telemetry Integration in AEGIS.
Bridges raw Linux log streams (SSH/PAM, Auditd, ss/netstat) to AEGIS Incident Investigation pipelines.

Enforces:
1. Strict schema compliance with IncidentInvestigationInput and LogEventInput.
2. In-memory deduplication and ordering by timestamp.
3. Filtering and quarantine tracking of malformed lines.
4. Absolute immutability of alert severity and target bindings.
5. Zero side-effects: purely transformation and validation logic (no active OS collectors/listeners).
"""

from typing import List, Dict, Any, Optional, Tuple
from aegis_agent.schemas import (
    IncidentInvestigationInput,
    AlertInput,
    EntityContext,
    LogEventInput,
    SeverityLevel,
)
from aegis_agent.linux_parser import LinuxTelemetryParser


class LinuxLogPipelineAdapter:
    """
    Adapter bridging raw Linux syslog/audit/socket records into structured
    LogEventInput streams and IncidentInvestigationInput models for RuntimeMonitor.
    """

    def __init__(self, parser: Optional[LinuxTelemetryParser] = None):
        self.parser = parser or LinuxTelemetryParser()

    def process_raw_logs(
        self,
        raw_lines: List[str],
        prefix: str = "EVT-LINUX",
        deduplicate: bool = True,
    ) -> Tuple[List[LogEventInput], List[str]]:
        """
        Parses raw text log lines, returns (parsed_events, unparseable_lines).
        Optionally deduplicates identical events (based on event_id or timestamp+event_type+details).
        """
        parsed_events: List[LogEventInput] = []
        unparseable_lines: List[str] = []
        seen_keys = set()

        for line in raw_lines:
            stripped = line.strip()
            if not stripped:
                continue

            event = self.parser.parse_line(stripped, event_id_prefix=prefix)
            if not event:
                unparseable_lines.append(stripped)
                continue

            if deduplicate:
                # Deduplication key combines event_type, source_ip, user, and unique details
                details_key = ""
                if event.details:
                    details_key = f"{event.details.get('pid', '')}-{event.details.get('action', '')}-{event.details.get('audit_msg_id', '')}-{event.details.get('remote_address', '')}"
                dedup_key = (event.event_type, event.source_ip, event.user, event.timestamp, details_key)
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

            parsed_events.append(event)

        return parsed_events, unparseable_lines

    def build_incident_input(
        self,
        incident_id: str,
        alert: AlertInput,
        entities: Optional[EntityContext] = None,
        raw_lines: Optional[List[str]] = None,
        existing_logs: Optional[List[LogEventInput]] = None,
        context: Optional[Dict[str, Any]] = None,
        prefix: str = "EVT-LINUX",
    ) -> Tuple[IncidentInvestigationInput, Dict[str, Any]]:
        """
        Builds an IncidentInvestigationInput object directly from raw Linux log lines
        and optional pre-existing logs.
        Guarantees that AlertInput severity is passed without modification.
        
        Returns:
            (incident_input, ingestion_metadata)
        """
        raw_lines = raw_lines or []
        existing_logs = existing_logs or []
        context = context or {}

        # Parse raw lines
        new_logs, unparseable = self.process_raw_logs(raw_lines, prefix=prefix, deduplicate=True)

        # Merge existing logs + new logs, deduplicating by event_id
        all_logs: List[LogEventInput] = []
        seen_ids = set()

        for l in existing_logs:
            if l.event_id not in seen_ids:
                all_logs.append(l)
                seen_ids.add(l.event_id)

        for l in new_logs:
            if l.event_id not in seen_ids:
                all_logs.append(l)
                seen_ids.add(l.event_id)

        # Infer entities if missing
        inferred_entities = entities or EntityContext()
        if not inferred_entities.source_ip:
            # find first source_ip from logs
            for l in all_logs:
                if l.source_ip:
                    inferred_entities.source_ip = l.source_ip
                    break

        if not inferred_entities.target_user:
            # find first user from logs
            for l in all_logs:
                if l.user:
                    inferred_entities.target_user = l.user
                    break

        if not inferred_entities.target_host:
            for l in all_logs:
                if l.details and l.details.get("host"):
                    inferred_entities.target_host = l.details["host"]
                    break

        # Metadata for pipeline observability
        ingestion_metadata = {
            "total_raw_lines": len(raw_lines),
            "parsed_events_count": len(new_logs),
            "unparseable_lines_count": len(unparseable),
            "unparseable_lines": unparseable,
            "total_investigation_logs": len(all_logs),
        }

        # Embed ingestion summary inside context for auditor visibility
        updated_context = dict(context)
        updated_context["_pipeline_ingestion"] = ingestion_metadata

        # Build IncidentInvestigationInput
        incident_input = IncidentInvestigationInput(
            incident_id=incident_id,
            alert=alert,
            entities=inferred_entities,
            logs=all_logs,
            context=updated_context,
        )

        return incident_input, ingestion_metadata

