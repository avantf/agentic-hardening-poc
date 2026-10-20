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


def load_scenarios() -> list[dict]:
    return yaml.safe_load((CONFIG / "drift_scenarios.yaml").read_text(encoding="utf-8"))["scenarios"]


def load_compose() -> dict:
    return yaml.safe_load((CONFIG.parent / "testbed" / "docker-compose.yml").read_text(encoding="utf-8"))


def test_every_control_has_a_drift_scenario():
    covered = {s["control_id"] for s in load_scenarios()}
    assert covered == {c["id"] for c in load_controls()}


def test_controls_and_scenarios_target_existing_services():
    services = set(load_compose()["services"])
    for control in load_controls():
        assert control["target_service"] in services | {"*"}, control["id"]
    for scenario in load_scenarios():
        assert scenario["service"] in services, scenario["id"]


def test_scenario_variables_are_used_by_the_compose_file():
    compose_text = (CONFIG.parent / "testbed" / "docker-compose.yml").read_text(encoding="utf-8")
    for scenario in load_scenarios():
        for name in scenario["variables"]:
            assert f"${{{name}:-" in compose_text, (scenario["id"], name)


def test_internal_services_are_only_on_the_internal_network():
    compose = load_compose()
    assert compose["networks"]["internal"]["internal"] is True
    for name in ("identity-service", "storage-service"):
        service = compose["services"][name]
        assert service["networks"] == ["internal"], name
        assert "ports" not in service, name
