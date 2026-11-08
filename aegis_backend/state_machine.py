"""
AEGIS Database State Machine Specification and Runtime Controller.
Author: Apri (Senior Software Engineer, Database Architect, DevSecOps Lead)

Defines explicit, deterministic operational states for the AEGIS database subsystem:
- HYBRID: SQLite is local primary storage; Cloud receives streaming telemetry.
- CLOUD_SSoT: Supabase Cloud PostgreSQL is sole authoritative SSoT. SQLite is cold durability replica.
- CLOUD_UNAVAILABLE: Cloud connection failed in SSoT mode. Strict fail-closed. Reads/writes fail-loud (HTTP 503).
- RECOVERY_REQUIRED: Consistency violation detected (e.g., startup catch-up failed, disk full on queue).
- MANUAL_FAILOVER: Operator explicitly initiated failover to SQLite.
- RECONCILIATION: Active synchronization (sync_cloud_to_sqlite.py) in progress.
- RESTORED: Reconciliation completed and verified, ready for transition to target operational state.
"""

from enum import Enum
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
import logging

logger = logging.getLogger("aegis_backend.state_machine")


class DatabaseState(str, Enum):
    HYBRID = "HYBRID"
    CLOUD_SSoT = "CLOUD_SSoT"
    CLOUD_UNAVAILABLE = "CLOUD_UNAVAILABLE"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    MANUAL_FAILOVER = "MANUAL_FAILOVER"
    RECONCILIATION = "RECONCILIATION"
    RESTORED = "RESTORED"


class DatabaseStateMachine:
    """
    Singleton state machine governing AEGIS database authority, permitted operations,
    and deterministic transitions between operational and emergency states.
    """

    # Explicit allowed state transition map: Source -> Set of Allowed Targets
    ALLOWED_TRANSITIONS: Dict[DatabaseState, List[DatabaseState]] = {
        DatabaseState.HYBRID: [
            DatabaseState.RECONCILIATION,
            DatabaseState.CLOUD_SSoT,
            DatabaseState.RECOVERY_REQUIRED,
        ],
        DatabaseState.CLOUD_SSoT: [
            DatabaseState.CLOUD_UNAVAILABLE,
            DatabaseState.RECOVERY_REQUIRED,
            DatabaseState.RECONCILIATION,
            DatabaseState.MANUAL_FAILOVER,
        ],
        DatabaseState.CLOUD_UNAVAILABLE: [
            DatabaseState.CLOUD_SSoT,         # Cloud connectivity restored
            DatabaseState.RECOVERY_REQUIRED,  # Inconsistency detected
            DatabaseState.MANUAL_FAILOVER,    # Operator-initiated failover
        ],
        DatabaseState.RECOVERY_REQUIRED: [
            DatabaseState.RECONCILIATION,     # Operator initiates reconciliation
            DatabaseState.MANUAL_FAILOVER,    # Operator emergency failover
        ],
        DatabaseState.MANUAL_FAILOVER: [
            DatabaseState.RECONCILIATION,     # Reconciling data before cut
            DatabaseState.HYBRID,             # Cutover to Hybrid complete
            DatabaseState.RECOVERY_REQUIRED,  # Failed validation
        ],
        DatabaseState.RECONCILIATION: [
            DatabaseState.RESTORED,           # Sync successfully verified
            DatabaseState.RECOVERY_REQUIRED,  # Sync failed or conflicts detected
        ],
        DatabaseState.RESTORED: [
            DatabaseState.HYBRID,             # Resuming in local mode
            DatabaseState.CLOUD_SSoT,         # Resuming in Cloud mode
        ],
    }

    def __init__(self, initial_state: DatabaseState = DatabaseState.HYBRID):
        self._state: DatabaseState = initial_state
        self._previous_state: Optional[DatabaseState] = None
        self._state_entered_at: datetime = datetime.now(timezone.utc)
        self._last_error: Optional[str] = None
        self._operator: str = "system"
        self._reason: str = "Initial system startup"
        self._details: Dict[str, Any] = {}
        self._catch_up_completed: bool = False

    @property
    def current_state(self) -> DatabaseState:
        return self._state

    @property
    def previous_state(self) -> Optional[DatabaseState]:
        return self._previous_state

    @property
    def state_entered_at(self) -> datetime:
        return self._state_entered_at

    @property
    def reason(self) -> str:
        return self._reason

    @property
    def last_error(self) -> Optional[str]:
        return self._last_error

    @property
    def is_catch_up_completed(self) -> bool:
        return self._catch_up_completed

    def set_catch_up_completed(self, completed: bool = True) -> None:
        self._catch_up_completed = completed

    def transition_to(
        self,
        target_state: DatabaseState,
        reason: str,
        operator: str = "system",
        error_message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        force: bool = False,
    ) -> bool:
        """
        Executes an audited state transition.
        Enforces state transition rules unless explicitly forced by an authorized operator.
        """
        if not force and target_state != self._state:
            allowed = self.ALLOWED_TRANSITIONS.get(self._state, [])
            if target_state not in allowed:
                err = f"Invalid state transition: {self._state.value} -> {target_state.value}. Allowed: {[s.value for s in allowed]}"
                logger.error(err)
                raise ValueError(err)

        prev = self._state
        self._previous_state = prev
        self._state = target_state
        self._state_entered_at = datetime.now(timezone.utc)
        self._reason = reason
        self._operator = operator
        self._last_error = error_message
        self._details = details or {}

        logger.info(
            "DATABASE STATE TRANSITION: [%s] -> [%s] | Operator: %s | Reason: %s",
            prev.value, target_state.value, operator, reason,
        )
        return True

    def is_mutation_allowed(self) -> bool:
        """
        Mutations (POST, PATCH, DELETE, INGEST) are strictly allowed ONLY in
        healthy operational states: CLOUD_SSoT (when catch-up is done) or HYBRID.
        In all failure, recovery, or transitional states, mutations are rejected.
        """
        if self._state == DatabaseState.HYBRID:
            return True
        if self._state == DatabaseState.CLOUD_SSoT:
            return self._catch_up_completed
        return False

    def is_read_allowed(self) -> bool:
        """
        Read queries are allowed in operational and manual failover modes.
        In CLOUD_UNAVAILABLE, strict fail-closed prevents reading stale or divergent state.
        """
        if self._state in (DatabaseState.HYBRID, DatabaseState.CLOUD_SSoT, DatabaseState.RESTORED):
            return True
        return False

    def get_authoritative_database(self) -> str:
        """Returns the single authoritative database for the current state."""
        if self._state in (DatabaseState.CLOUD_SSoT, DatabaseState.CLOUD_UNAVAILABLE):
            return "supabase_cloud"
        if self._state in (DatabaseState.HYBRID, DatabaseState.RESTORED):
            return "sqlite_local"
        if self._state in (DatabaseState.MANUAL_FAILOVER, DatabaseState.RECONCILIATION):
            return "synchronizing_or_locked"
        return "none_recovery_required"

    def get_health_summary(self) -> Dict[str, Any]:
        """Provides a structured dictionary for health reporting."""
        return {
            "current_state": self._state.value,
            "previous_state": self._previous_state.value if self._previous_state else None,
            "authoritative_database": self.get_authoritative_database(),
            "is_mutation_allowed": self.is_mutation_allowed(),
            "is_read_allowed": self.is_read_allowed(),
            "catch_up_completed": self._catch_up_completed,
            "state_entered_at": self._state_entered_at.isoformat(),
            "operator": self._operator,
            "reason": self._reason,
            "last_error": self._last_error,
        }


# Global singleton instance
state_machine = DatabaseStateMachine()
