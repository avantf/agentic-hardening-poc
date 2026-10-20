"""Deterministic authorization of proposed Actions (config/autonomy_policy.yaml).

The PolicyEngine is the point where "the LLM proposes, deterministic code
decides" is enforced. A decision depends only on:

  - the action_class of the Action, and the risk tier derived from it by the
    RiskTaxonomy (any risk_tier already set on the Action is ignored);
  - the autonomy level;
  - tier_adjustment;
  - the state of the global guardrails (actions executed in this run, whether
    a maintenance window is open).

Free text (Finding.description, Action.description, any LLM rationale) and
Action.params are never read, and never copied into the decision's reason.

Order of evaluation, first match wins:

  1. unclassified action_class        -> BLOCKED  (block_unclassified_actions)
  2. guardrail tier in always_block   -> BLOCKED
  3. level L0                         -> OBSERVE_ONLY
  4. circuit breaker tripped          -> BLOCKED  (max_actions_per_run)
  5. guardrail tier needs a window
     and none is open                 -> BLOCKED  (deferred)
  6. effective tier auto-executable   -> AUTO_EXECUTE
  7. level requires approval          -> REQUIRE_APPROVAL
  8. otherwise                        -> BLOCKED

tier_adjustment moves the effective tier, which drives the level mapping
(steps 6-8). Guardrails (steps 2 and 5) use the higher of the nominal and the
effective tier, so an adjustment can tighten a guardrail but never loosen it.
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from agent.models import Action, RiskTier
from agent.risk_taxonomy import RiskTaxonomy, UnknownActionClassError

DEFAULT_POLICY_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "autonomy_policy.yaml"
)
TIER_ORDER: tuple[RiskTier, ...] = ("T1", "T2", "T3", "T4", "T5")
OBSERVE_LEVEL = "L0"


class PolicyConfigError(ValueError):
    """The autonomy policy file is malformed or inconsistent."""


class Decision(str, Enum):
    AUTO_EXECUTE = "auto_execute"
    REQUIRE_APPROVAL = "require_approval"
    BLOCKED = "blocked"
    OBSERVE_ONLY = "observe_only"


@dataclass(frozen=True)
class PolicyDecision:
    """Outcome of PolicyEngine.decide for one Action.

    Attributes:
        decision: What may happen to the Action.
        nominal_tier: Tier derived from the taxonomy (unclassified_action_tier
            for an unknown action_class).
        effective_tier: nominal_tier moved by tier_adjustment, clamped to T1..T5.
        reason: Human-readable explanation for the audit trail. Built only from
            the decision inputs, never from free text.
    """

    decision: Decision
    nominal_tier: RiskTier
    effective_tier: RiskTier
    reason: str


@dataclass(frozen=True)
class _Level:
    auto_execute_tiers: frozenset[str]
    require_approval: bool


class PolicyEngine:
    """Applies the autonomy policy and global guardrails to proposed Actions.

    Holds per-run state: the number of actions authorized for automatic
    execution, used by the max_actions_per_run circuit breaker. Call
    `reset_run()` at the start of every run.
    """

    def __init__(
        self,
        policy_path: Path | str = DEFAULT_POLICY_PATH,
        taxonomy: RiskTaxonomy | None = None,
    ) -> None:
        self._path = Path(policy_path)
        self._taxonomy = taxonomy if taxonomy is not None else RiskTaxonomy()
        with self._path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise PolicyConfigError(f"{self._path}: expected a mapping at top level")
        self._levels = self._load_levels(data)
        guardrails = self._require(data, "global_guardrails")
        self._max_actions_per_run = self._load_max_actions(guardrails)
        self._window_tiers = self._load_tiers(guardrails, "require_maintenance_window_for_tiers")
        self._always_block_tiers = self._load_tiers(guardrails, "always_block_tiers")
        self._block_unclassified = guardrails.get("block_unclassified_actions", True) is not False
        self._executed_in_run = 0

    @property
    def actions_executed_in_run(self) -> int:
        return self._executed_in_run

    @property
    def max_actions_per_run(self) -> int:
        return self._max_actions_per_run

    def reset_run(self) -> None:
        """Reset the circuit-breaker counter. Call at the start of each run."""
        self._executed_in_run = 0

    def decide(
        self,
        action: Action,
        autonomy_level: str,
        tier_adjustment: int = 0,
        *,
        in_maintenance_window: bool = False,
    ) -> PolicyDecision:
        """Decide what may happen to `action` at `autonomy_level`.

        Sets `action.risk_tier` to the nominal tier, overwriting any value the
        Planner may have supplied. An AUTO_EXECUTE decision counts towards
        max_actions_per_run.
        """
        level = self._levels.get(autonomy_level)
        if level is None:
            raise ValueError(
                f"unknown autonomy level {autonomy_level!r}; known levels: {', '.join(sorted(self._levels))}"
            )
        if not isinstance(tier_adjustment, int) or isinstance(tier_adjustment, bool):
            raise TypeError(f"tier_adjustment must be an int, got {type(tier_adjustment).__name__}")
        if not isinstance(in_maintenance_window, bool):
            raise TypeError("in_maintenance_window must be a bool")

        action_class = action.action_class
        try:
            nominal = self._taxonomy.get_risk_tier(action_class)
            classified = True
        except UnknownActionClassError:
            nominal = self._taxonomy.unclassified_action_tier
            classified = False
        action.risk_tier = nominal

        effective = _shift_tier(nominal, tier_adjustment)
        guard_tier = max(nominal, effective, key=TIER_ORDER.index)
        context = (
            f"action_class={action_class!r} nominal_tier={nominal} "
            f"tier_adjustment={tier_adjustment:+d} effective_tier={effective} "
            f"level={autonomy_level}"
        )

        def result(decision: Decision, why: str) -> PolicyDecision:
            return PolicyDecision(decision, nominal, effective, f"{decision.value}: {why} [{context}]")

        if not classified and self._block_unclassified:
            return result(Decision.BLOCKED, "action_class is not in the risk taxonomy")
        if guard_tier in self._always_block_tiers:
            return result(Decision.BLOCKED, f"tier {guard_tier} is in always_block_tiers")
        if autonomy_level == OBSERVE_LEVEL:
            return result(Decision.OBSERVE_ONLY, "level L0 records proposals without executing them")
        if self._executed_in_run >= self._max_actions_per_run:
            return result(
                Decision.BLOCKED,
                f"circuit breaker: {self._executed_in_run} actions already executed in this run "
                f"(max_actions_per_run={self._max_actions_per_run})",
            )
        if guard_tier in self._window_tiers and not in_maintenance_window:
            return result(
                Decision.BLOCKED,
                f"deferred: tier {guard_tier} requires a maintenance window and none is open",
            )
        if effective in level.auto_execute_tiers:
            self._executed_in_run += 1
            return result(
                Decision.AUTO_EXECUTE,
                f"tier {effective} is auto-executable at {autonomy_level} "
                f"(action {self._executed_in_run}/{self._max_actions_per_run} in this run)",
            )
        if level.require_approval:
            return result(
                Decision.REQUIRE_APPROVAL,
                f"tier {effective} is not auto-executable at {autonomy_level}; human approval required",
            )
        return result(
            Decision.BLOCKED,
            f"tier {effective} is not auto-executable at {autonomy_level} and the level allows no approval",
        )

    def _load_levels(self, data: dict[str, Any]) -> dict[str, _Level]:
        raw_levels = self._require(data, "levels")
        if not isinstance(raw_levels, dict):
            raise PolicyConfigError(f"{self._path}: 'levels' must be a mapping")
        missing = {"L0", "L1", "L2", "L3"} - set(raw_levels)
        if missing:
            raise PolicyConfigError(f"{self._path}: missing levels {sorted(missing)}")
        levels = {}
        for name, raw in raw_levels.items():
            if not isinstance(raw.get("require_approval"), bool):
                raise PolicyConfigError(f"level {name!r}: require_approval must be true or false")
            levels[name] = _Level(
                auto_execute_tiers=self._load_tiers(raw, "auto_execute_tiers", owner=f"level {name!r}"),
                require_approval=raw["require_approval"],
            )
        if levels[OBSERVE_LEVEL].auto_execute_tiers:
            raise PolicyConfigError(f"level {OBSERVE_LEVEL} must not auto-execute any tier")
        return levels

    def _load_max_actions(self, guardrails: dict[str, Any]) -> int:
        value = self._require(guardrails, "max_actions_per_run")
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise PolicyConfigError(f"max_actions_per_run must be a non-negative integer, got {value!r}")
        return value

    def _load_tiers(
        self, data: dict[str, Any], key: str, owner: str = "global_guardrails"
    ) -> frozenset[str]:
        tiers = data.get(key) or []
        unknown = [t for t in tiers if t not in TIER_ORDER]
        if unknown:
            raise PolicyConfigError(f"{owner}: {key} uses undefined tiers {unknown}")
        return frozenset(tiers)

    def _require(self, data: dict[str, Any], key: str) -> Any:
        if key not in data:
            raise PolicyConfigError(f"{self._path}: missing required key {key!r}")
        return data[key]


def _shift_tier(tier: RiskTier, adjustment: int) -> RiskTier:
    index = TIER_ORDER.index(tier) + adjustment
    return TIER_ORDER[max(0, min(len(TIER_ORDER) - 1, index))]
