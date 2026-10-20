"""storage-service: mock storage service holding sensitive data (internal network only).

Relevant state:
  ENCRYPTION_AT_REST  true/false, simulated encryption of the data volume.
  CONFIG_PATH         Configuration file whose owner and mode are reported live
                      (set by entrypoint.sh from CONFIG_FILE_MODE).
"""

import os

from flask import Flask, jsonify

from testbed_status import env_bool, file_state, runtime_state

CONFIG_PATH = os.environ.get("CONFIG_PATH", "/etc/storage/storage.conf")

app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/status")
def status():
    return jsonify(
        service="storage-service",
        encryption_at_rest=env_bool("ENCRYPTION_AT_REST", True),
        config_file=file_state(CONFIG_PATH),
        runtime=runtime_state(),
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
