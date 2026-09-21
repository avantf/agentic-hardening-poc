"""Core data types exchanged between the pipeline stages.

Assessor -> Finding -> Planner -> Action -> PolicyEngine -> ... -> Auditor -> AuditEntry
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

RiskTier = Literal["T1", "T2", "T3", "T4", "T5"]
Severity = Literal["low", "medium", "high", "critical"]
FindingSource = Literal["baseline", "vulnerability_scan"]
AutonomyLevel = Literal["L0", "L1", "L2", "L3"]


@dataclass(frozen=True)
class Finding:
    """A deviation from the baseline or a known vulnerability, reported by the Assessor.

    Attributes:
        id: Unique identifier of this finding within the audit trail.
        control_id: Id of the baseline control that was violated (e.g. "BC-005"),
            as defined in config/baseline_controls.yaml.
        service: Name of the testbed service where the deviation was observed
            (e.g. "jump-host").
        description: Human-readable account of what was observed versus what the
            control expects.
        severity: How serious the deviation is, independent of the risk of fixing it.
        source: Where the finding came from: "baseline" for a failed baseline control
            check, "vulnerability_scan" for a known-vulnerable component.
    """

    id: str
    control_id: str
    service: str
    description: str
    severity: Severity
    source: FindingSource


@dataclass
class Action:
    """A remediation proposed by the Planner for one Finding.

    Not frozen: `risk_tier` is filled in after creation by the PolicyEngine.

    Attributes:
        id: Unique identifier of this action within the audit trail.
        finding_id: Id of the Finding this action is meant to resolve.
        action_class: Class of the action, a key of `action_classes` in
            config/risk_taxonomy.yaml (e.g. "change_ssh_policy"). It determines
            the risk tier and the rollback strategy.
        description: Human-readable explanation of what the action does and why,
            as proposed by the Planner.
        target_service: Name of the testbed service the action will change.
        params: Action-specific parameters (e.g. the config key and new value).
            Interpreted by the matching adapter in tools/.
        risk_tier: Risk tier derived from the taxonomy by the PolicyEngine. None
            until the action has been classified. It is never taken from the
            Planner's output.
    """

    id: str
    finding_id: str
    action_class: str
    description: str
    target_service: str
    params: dict[str, Any] = field(default_factory=dict)
    risk_tier: RiskTier | None = None


@dataclass(frozen=True)
class AuditEntry:
    """One record of the append-only audit trail. Entries are never modified.

    Attributes:
        timestamp: When the event occurred (timezone-aware).
        actor: Pipeline component or person that produced the event
            (e.g. "assessor", "planner", "policy_engine", "remediator",
            "verifier", or a human approver's identifier).
        event_type: Kind of event (e.g. "finding_detected", "action_proposed",
            "decision_made", "action_executed", "rollback_performed").
        payload: Event-specific data, e.g. the serialized Finding, Action or
            decision with its reasons.
        autonomy_level: Autonomy level active when the event was recorded.
    """

    timestamp: datetime
    actor: str
    event_type: str
    payload: dict[str, Any]
    autonomy_level: AutonomyLevel
