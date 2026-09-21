"""Tests for agent.risk_taxonomy.

The shipped taxonomy currently defines no action class in tier T5, so the
per-tier coverage test runs against a fixture taxonomy that has one class for
every tier. The real config is tested separately for the tiers it does cover.
"""

import textwrap

import pytest

from agent.risk_taxonomy import (
    RiskTaxonomy,
    TaxonomyConfigError,
    UnknownActionClassError,
)

FIXTURE_TAXONOMY = textwrap.dedent(
    """
    schema_version: 1
    tiers: {T1: {}, T2: {}, T3: {}, T4: {}, T5: {}}
    action_classes:
      a_t1: {impact: low,    reversibility: reversible,           rollback_strategy: {type: rb_t1}}
      a_t2: {impact: low,    reversibility: partially_reversible, rollback_strategy: {type: rb_t2}}
      a_t3: {impact: medium, reversibility: partially_reversible, rollback_strategy: {type: rb_t3}}
      a_t4: {impact: high,   reversibility: partially_reversible, rollback_strategy: {type: rb_t4}}
      a_t5: {impact: high,   reversibility: irreversible,         rollback_strategy: {type: rb_t5}}
    risk_matrix:
      low:    {reversible: T1, partially_reversible: T2, irreversible: T3}
      medium: {reversible: T2, partially_reversible: T3, irreversible: T4}
      high:   {reversible: T3, partially_reversible: T4, irreversible: T5}
    """
)


@pytest.fixture
def fixture_taxonomy(tmp_path) -> RiskTaxonomy:
    path = tmp_path / "risk_taxonomy.yaml"
    path.write_text(FIXTURE_TAXONOMY, encoding="utf-8")
    return RiskTaxonomy(path)


@pytest.fixture(scope="module")
def real_taxonomy() -> RiskTaxonomy:
    return RiskTaxonomy()


@pytest.mark.parametrize(
    "action_class, tier",
    [("a_t1", "T1"), ("a_t2", "T2"), ("a_t3", "T3"), ("a_t4", "T4"), ("a_t5", "T5")],
)
def test_every_tier_is_reachable_through_the_matrix(fixture_taxonomy, action_class, tier):
    assert fixture_taxonomy.get_risk_tier(action_class) == tier


@pytest.mark.parametrize(
    "action_class, tier",
    [
        ("restrict_file_permissions", "T1"),
        ("close_exposed_port", "T2"),
        ("apply_package_update", "T3"),
        ("remove_privileged_mode", "T4"),
    ],
)
def test_real_config_tiers(real_taxonomy, action_class, tier):
    assert real_taxonomy.get_risk_tier(action_class) == tier


def test_rollback_strategy_returns_type_identifier(fixture_taxonomy, real_taxonomy):
    assert fixture_taxonomy.get_rollback_strategy("a_t3") == "rb_t3"
    assert real_taxonomy.get_rollback_strategy("change_ssh_policy") == "restore_config_file"


def test_every_real_action_class_has_a_tier_and_rollback(real_taxonomy):
    for name in real_taxonomy._action_classes:
        assert real_taxonomy.get_risk_tier(name) in {"T1", "T2", "T3", "T4", "T5"}
        assert real_taxonomy.get_rollback_strategy(name)


@pytest.mark.parametrize("method", ["get_risk_tier", "get_rollback_strategy"])
def test_unknown_action_class_raises(real_taxonomy, method):
    with pytest.raises(UnknownActionClassError, match="delete_everything"):
        getattr(real_taxonomy, method)("delete_everything")


def test_error_lists_known_classes(real_taxonomy):
    with pytest.raises(UnknownActionClassError, match="rotate_credential"):
        real_taxonomy.get_risk_tier("nope")


def test_inconsistent_taxonomy_is_rejected(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(
        FIXTURE_TAXONOMY.replace("impact: low,    reversibility: reversible", "impact: extreme, reversibility: reversible"),
        encoding="utf-8",
    )
    with pytest.raises(TaxonomyConfigError, match="a_t1"):
        RiskTaxonomy(path)
