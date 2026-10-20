"""vuln-web: externally exposed web application of the testbed.

Relevant state (env):
  ADMIN_PASSWORD          Admin password. /status reports only whether it is a
                          well-known default, never the value.
  DEBUG_PORT_ENABLED      When true, a debug console listens on DEBUG_PORT (9000).
  TLS_SIGNATURE_ALGORITHM Simulated signature algorithm of the TLS certificate.
Package versions are read from the installed distributions.
"""

import os
import threading
from importlib.metadata import version

from flask import Flask, jsonify

from testbed_status import env_bool, env_int, runtime_state

DEFAULT_PASSWORDS = {"admin", "password", "administrator", "changeme", "123456"}
DEBUG_PORT = env_int("DEBUG_PORT", 9000)

app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/status")
def status():
    return jsonify(
        service="vuln-web",
        admin_password_is_default=os.environ.get("ADMIN_PASSWORD", "") in DEFAULT_PASSWORDS,
        debug_port={"enabled": env_bool("DEBUG_PORT_ENABLED", False), "port": DEBUG_PORT},
        tls={
            "signature_algorithm": os.environ.get("TLS_SIGNATURE_ALGORITHM", "sha256WithRSAEncryption"),
            "simulated": True,
        },
        packages={name: version(name) for name in ("flask", "werkzeug")},
        runtime=runtime_state(),
    )


debug_app = Flask("debug-console")


@debug_app.get("/")
def debug_console():
    return jsonify(console="debug", warning="administrative interface")


if __name__ == "__main__":
    if env_bool("DEBUG_PORT_ENABLED", False):
        threading.Thread(
            target=lambda: debug_app.run(host="0.0.0.0", port=DEBUG_PORT), daemon=True
        ).start()
    app.run(host="0.0.0.0", port=8080)
