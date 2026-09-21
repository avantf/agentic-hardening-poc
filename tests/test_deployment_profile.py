"""Tests for agent.deployment_profile."""

import pytest

from agent.deployment_profile import DeploymentProfileError, load_deployment_profile


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("DEPLOYMENT_PROFILE", raising=False)


def test_default_profile_is_airgapped():
    profile = load_deployment_profile()
    assert profile.name == "airgapped"
    assert profile.llm_provider == "local"
    assert profile.allow_external_network is False
    assert profile.note


def test_cloud_profile_allows_external_network():
    profile = load_deployment_profile("cloud")
    assert profile.llm_provider == "cloud"
    assert profile.allow_external_network is True


def test_profile_selected_from_environment(monkeypatch):
    monkeypatch.setenv("DEPLOYMENT_PROFILE", " Cloud ")
    assert load_deployment_profile().name == "cloud"


def test_unknown_profile_raises_and_lists_known():
    with pytest.raises(DeploymentProfileError, match="airgapped"):
        load_deployment_profile("staging")


def test_malformed_profile_is_rejected(tmp_path):
    path = tmp_path / "p.yaml"
    path.write_text(
        "default_profile: x\nprofiles:\n  x: {llm_provider: local, allow_external_network: 'no'}\n"
    )
    with pytest.raises(DeploymentProfileError, match="allow_external_network"):
        load_deployment_profile(path=path)
