"""Cross-file consistency of the shipped configuration."""

from pathlib import Path

import yaml

from agent.risk_taxonomy import RiskTaxonomy

CONFIG = Path(__file__).resolve().parent.parent / "config"


def load_controls() -> list[dict]:
    return yaml.safe_load((CONFIG / "baseline_controls.yaml").read_text(encoding="utf-8"))["controls"]


def test_every_allowed_action_class_exists_in_the_taxonomy():
    taxonomy = RiskTaxonomy()
    for control in load_controls():
        assert control["allowed_action_classes"], control["id"]
        for action_class in control["allowed_action_classes"]:
            taxonomy.get_risk_tier(action_class)  # raises if undefined


def test_every_taxonomy_action_class_is_used_by_a_control():
    used = {c for control in load_controls() for c in control["allowed_action_classes"]}
    defined = set(RiskTaxonomy()._action_classes)
    assert defined == used


def test_control_ids_are_unique():
    ids = [c["id"] for c in load_controls()]
    assert len(ids) == len(set(ids))
