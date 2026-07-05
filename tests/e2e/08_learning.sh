#!/usr/bin/env bash
# Phase 6: learning mode - nothing is blocked, observed domains/IPs are appended to the policy.
# Requires a container recreate (LEARNING_MODE is env-based).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

log "=== Phase 6: learning mode [$FILTER_MODE mode] ==="

baseline_policy
stack_up LEARNING_MODE=true
wait_ready

log "[Learn] Non-allowlisted domain must pass in learning mode"
assert_allowed https://google.com

if [ "$FILTER_MODE" = "https" ]; then
  log "[Learn] Direct-to-IP (no SNI is sent for IP URLs) must pass and learn the IP"
  assert_allowed https://1.0.0.1
fi

log "[Learn] Waiting for learner flush + policy write..."
sleep 8

grep -q 'google.com' "$POLICY_FILE" || { cat "$POLICY_FILE"; fail "google.com was not learned into policy.yaml"; }
log "OK: google.com learned into policy.yaml"

if [ "$FILTER_MODE" = "https" ]; then
  grep -q '1.0.0.1' "$POLICY_FILE" || { cat "$POLICY_FILE"; fail "1.0.0.1 was not learned into policy.yaml"; }
  log "OK: 1.0.0.1 learned into policy.yaml"
fi

log "[Learn] Traffic still passes after the learning-triggered policy reload"
wait_for_policy_reload
assert_allowed https://github.com

log "OK: learning mode verified"
