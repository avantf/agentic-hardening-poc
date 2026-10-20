#!/usr/bin/env bash
# Destroy the testbed (containers, networks, volumes) and bring it back up in
# the compliant baseline, without any drift scenario.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
docker compose -f "$ROOT/testbed/docker-compose.yml" down --volumes --remove-orphans

# Do not inherit drift variables exported in the calling shell.
for var in ADMIN_PASSWORD DEBUG_PORT_ENABLED TLS_SIGNATURE_ALGORITHM WERKZEUG_VERSION \
           PASSWORD_MIN_LENGTH MFA_REQUIRED ENCRYPTION_AT_REST CONFIG_FILE_MODE SSH_PASSWORD_AUTH \
           VULN_WEB_PRIVILEGED IDENTITY_SERVICE_PRIVILEGED STORAGE_SERVICE_PRIVILEGED BASTION_PRIVILEGED; do
  unset "$var"
done

exec "$ROOT/scripts/setup_testbed.sh"
