#!/usr/bin/env bash
# Build and start the testbed, then wait until every service is healthy.
#
#   scripts/setup_testbed.sh                         compliant baseline
#   scripts/setup_testbed.sh --scenario DS-004 ...   inject drift scenarios
#
# Environment: HEALTH_TIMEOUT (seconds, default 180).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/testbed/docker-compose.yml")
SCENARIOS_FILE="$ROOT/config/drift_scenarios.yaml"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-180}"

PYTHON="$ROOT/venv/bin/python"
[ -x "$PYTHON" ] || PYTHON=python3

scenarios=()
while [ $# -gt 0 ]; do
  case "$1" in
    --scenario) scenarios+=("${2:?--scenario needs an id}"); shift 2 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ ${#scenarios[@]} -gt 0 ]; then
  # Prints KEY=VALUE lines for the requested scenarios; fails on unknown ids.
  assignments="$("$PYTHON" - "$SCENARIOS_FILE" "${scenarios[@]}" <<'EOF'
import re, sys, yaml
path, wanted = sys.argv[1], sys.argv[2:]
known = {s["id"]: s for s in yaml.safe_load(open(path, encoding="utf-8"))["scenarios"]}
missing = [w for w in wanted if w not in known]
if missing:
    sys.exit(f"unknown scenario(s): {', '.join(missing)}; known: {', '.join(known)}")
for w in wanted:
    for key, value in known[w]["variables"].items():
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", key):
            sys.exit(f"{w}: invalid variable name {key!r}")
        print(f"{key}={str(value).lower() if isinstance(value, bool) else value}")
EOF
)"
  while IFS='=' read -r key value; do
    export "$key=$value"
    echo "drift: $key=$value"
  done <<< "$assignments"
fi

"${COMPOSE[@]}" up -d --build --remove-orphans

echo "waiting for health checks (timeout ${HEALTH_TIMEOUT}s)..."
deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
while :; do
  pending=()
  for id in $("${COMPOSE[@]}" ps -q); do
    read -r name health < <(docker inspect -f '{{.Name}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$id")
    [ "$health" = healthy ] || pending+=("${name#/}:$health")
  done
  if [ ${#pending[@]} -eq 0 ]; then
    echo "all services healthy"
    break
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "timed out waiting for: ${pending[*]}" >&2
    "${COMPOSE[@]}" ps >&2
    exit 1
  fi
  sleep 2
done
