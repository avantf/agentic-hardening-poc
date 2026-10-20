"""bastion: minimal /health and /status endpoint for the SSH jump host.

The SSH state is read live from sshd_config and from `sshd -T` (the effective
configuration), so a remediation that edits sshd_config and reloads sshd is
visible without restarting the container.
"""

import json
import re
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from testbed_status import runtime_state

SSHD_CONFIG = "/etc/ssh/sshd_config"


def configured_password_auth() -> str | None:
    for line in Path(SSHD_CONFIG).read_text().splitlines():
        match = re.match(r"\s*PasswordAuthentication\s+(\S+)", line, re.IGNORECASE)
        if match:
            return match.group(1).lower()
    return None


def effective_password_auth() -> str | None:
    result = subprocess.run(["/usr/sbin/sshd", "-T"], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        key, _, value = line.partition(" ")
        if key == "passwordauthentication":
            return value
    return None


def sshd_running() -> bool:
    return subprocess.run(["pgrep", "-x", "sshd"], capture_output=True).returncode == 0


def status() -> dict:
    return {
        "service": "bastion",
        "ssh": {
            "running": sshd_running(),
            "config_path": SSHD_CONFIG,
            "password_authentication": configured_password_auth(),
            "effective_password_authentication": effective_password_auth(),
        },
        "runtime": runtime_state(),
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body, code = {"status": "ok" if sshd_running() else "sshd_down"}, 200 if sshd_running() else 503
        elif self.path == "/status":
            body, code = status(), 200
        else:
            body, code = {"error": "not found"}, 404
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
