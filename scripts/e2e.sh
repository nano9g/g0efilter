#!/usr/bin/env bash
# E2e suite runner, used by CI and runnable locally:
#   FILTER_MODE=https scripts/e2e.sh
#   FILTER_MODE=dns   scripts/e2e.sh
# Requires docker compose. Brings the examples/build stack up, runs every phase
# in tests/e2e/, dumps logs on failure, and tears down.
E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../tests/e2e" && pwd)"
source "$E2E_DIR/lib.sh"

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    log "FAILED (exit $status) - dumping container logs"
    dump_logs
  fi
  baseline_policy
  stack_down
  exit "$status"
}
trap cleanup EXIT

log "Starting e2e suite in $FILTER_MODE mode"

baseline_policy
stack_up
wait_ready

for phase in "$E2E_DIR"/[0-9][0-9]_*.sh; do
  log ">>> Running $(basename "$phase")"
  bash "$phase"
done

log "All e2e phases passed in $FILTER_MODE mode"
