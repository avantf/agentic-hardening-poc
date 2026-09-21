"""Loader and lookup for the risk / reversibility taxonomy (config/risk_taxonomy.yaml)."""

from pathlib import Path
from typing import Any

import yaml

from agent.models import RiskTier

DEFAULT_TAXONOMY_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "risk_taxonomy.yaml"
)


class TaxonomyConfigError(ValueError):
    """The taxonomy file is malformed or internally inconsistent."""


class UnknownActionClassError(LookupError):
    """An action_class is not defined in the taxonomy."""


class RiskTaxonomy:
    """Read-only view of the risk taxonomy.

    The risk tier of an action class is derived from its impact and
    reversibility through the risk matrix. Unknown action classes raise
    UnknownActionClassError: the caller decides how to handle them (the
    PolicyEngine blocks them); this class never guesses a tier.
    """

    def __init__(self, path: Path | str = DEFAULT_TAXONOMY_PATH) -> None:
        self._path = Path(path)
        with self._path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise TaxonomyConfigError(f"{self._path}: expected a mapping at top level")
        self._action_classes: dict[str, dict[str, Any]] = self._require(
            data, "action_classes"
        )
        self._risk_matrix: dict[str, dict[str, str]] = self._require(
            data, "risk_matrix"
        )
        self._tiers: set[str] = set(self._require(data, "tiers"))
        self._validate()

    def get_risk_tier(self, action_class: str) -> RiskTier:
        """Return the risk tier (T1..T5) for `action_class` via the risk matrix."""
        definition = self._get_definition(action_class)
        return self._risk_matrix[definition["impact"]][definition["reversibility"]]  # type: ignore[return-value]

    def get_rollback_strategy(self, action_class: str) -> str:
        """Return the rollback strategy identifier (its `type`) for `action_class`."""
        return self._get_definition(action_class)["rollback_strategy"]["type"]

    def _get_definition(self, action_class: str) -> dict[str, Any]:
        try:
            return self._action_classes[action_class]
        except KeyError:
            known = ", ".join(sorted(self._action_classes))
            raise UnknownActionClassError(
                f"action_class {action_class!r} is not defined in {self._path.name}; "
                f"known classes: {known}"
            ) from None

    def _require(self, data: dict[str, Any], key: str) -> Any:
        if key not in data:
            raise TaxonomyConfigError(f"{self._path}: missing required key {key!r}")
        return data[key]

    def _validate(self) -> None:
        for impact, row in self._risk_matrix.items():
            for reversibility, tier in row.items():
                if tier not in self._tiers:
                    raise TaxonomyConfigError(
                        f"risk_matrix[{impact}][{reversibility}] uses undefined tier {tier!r}"
                    )
        for name, definition in self._action_classes.items():
            impact = definition.get("impact")
            reversibility = definition.get("reversibility")
            if reversibility not in self._risk_matrix.get(impact, {}):
                raise TaxonomyConfigError(
                    f"action class {name!r}: no risk_matrix entry for "
                    f"impact={impact!r}, reversibility={reversibility!r}"
                )
            if not definition.get("rollback_strategy", {}).get("type"):
                raise TaxonomyConfigError(
                    f"action class {name!r}: missing rollback_strategy.type"
                )
