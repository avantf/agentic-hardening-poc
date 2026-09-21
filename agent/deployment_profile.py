"""Loader for the deployment profiles (config/deployment_profile.yaml)."""

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_PROFILE_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "deployment_profile.yaml"
)
PROFILE_ENV_VAR = "DEPLOYMENT_PROFILE"


class DeploymentProfileError(ValueError):
    """The profile file is malformed or the requested profile does not exist."""


@dataclass(frozen=True)
class DeploymentProfile:
    """One deployment profile.

    Attributes:
        name: Profile name (e.g. "airgapped").
        llm_provider: Default LLM provider for the profile, "local" or "cloud".
        allow_external_network: Whether components may use networks outside the
            deployment. False means anything needing one must refuse to start.
        note: Description of the intended context of use.
    """

    name: str
    llm_provider: str
    allow_external_network: bool
    note: str


def load_deployment_profile(
    name: str | None = None, path: Path | str = DEFAULT_PROFILE_PATH
) -> DeploymentProfile:
    """Load a profile by name.

    When `name` is None it is read from the DEPLOYMENT_PROFILE environment
    variable, falling back to `default_profile` in the file.
    """
    path = Path(path)
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict) or not isinstance(data.get("profiles"), dict):
        raise DeploymentProfileError(f"{path.name}: expected a top-level 'profiles' mapping")

    selected = (name or os.environ.get(PROFILE_ENV_VAR) or data.get("default_profile") or "")
    selected = selected.strip().lower()
    profiles = data["profiles"]
    if selected not in profiles:
        raise DeploymentProfileError(
            f"unknown deployment profile {selected!r}; known profiles: {', '.join(sorted(profiles))}"
        )

    raw = profiles[selected]
    if raw.get("llm_provider") not in ("local", "cloud"):
        raise DeploymentProfileError(
            f"profile {selected!r}: llm_provider must be 'local' or 'cloud'"
        )
    if not isinstance(raw.get("allow_external_network"), bool):
        raise DeploymentProfileError(
            f"profile {selected!r}: allow_external_network must be a boolean"
        )
    return DeploymentProfile(
        name=selected,
        llm_provider=raw["llm_provider"],
        allow_external_network=raw["allow_external_network"],
        note=" ".join(str(raw.get("note", "")).split()),
    )
