"""identity-service: mock identity / authentication service (internal network only).

Relevant state (env): PASSWORD_MIN_LENGTH, MFA_REQUIRED.
"""

from flask import Flask, jsonify

from testbed_status import env_bool, env_int, runtime_state

app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/status")
def status():
    return jsonify(
        service="identity-service",
        auth_policy={
            "password_min_length": env_int("PASSWORD_MIN_LENGTH", 12),
            "mfa_required": env_bool("MFA_REQUIRED", True),
        },
        runtime=runtime_state(),
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
