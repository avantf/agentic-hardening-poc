"""Helpers shared by the testbed services for their /status endpoints.

Values are read live on every request, so a remediation that changes the state
of a running container is visible without restarting it.
"""

import os
from pathlib import Path


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def is_privileged() -> bool:
    """True if the container holds every Linux capability, as `privileged: true` grants.

    Reads the effective capability set of this process, so it needs no access
    to the Docker API.
    """
    cap_last = int(Path("/proc/sys/kernel/cap_last_cap").read_text().strip())
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("CapEff:"):
            return int(line.split()[1], 16) == (1 << (cap_last + 1)) - 1
    return False


def file_state(path: str) -> dict:
    """Owner and octal mode of `path`, or exists=False."""
    p = Path(path)
    if not p.exists():
        return {"path": path, "exists": False}
    st = p.stat()
    owner = "root" if st.st_uid == 0 else str(st.st_uid)
    return {"path": path, "exists": True, "owner": owner, "mode": f"{st.st_mode & 0o7777:04o}"}


def runtime_state() -> dict:
    return {"privileged": is_privileged()}
