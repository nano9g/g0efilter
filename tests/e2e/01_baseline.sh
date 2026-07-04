#!/usr/bin/env bash
# Phase 1: baseline allow/block filtering. Assumes the stack is up with the baseline policy.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

log "=== Phase 1: baseline policy (github.com + 1.1.1.1 allowed) [$FILTER_MODE mode] ==="

assert_allowed https://github.com
assert_allowed http://github.com

if [ "$FILTER_MODE" = "https" ]; then
  assert_allowed https://1.1.1.1
  assert_allowed http://1.1.1.1
else
  log "[IP] Skipping IP tests in DNS mode (IPs bypass DNS filtering)"
fi

assert_blocked https://google.com
assert_blocked http://google.com

if [ "$FILTER_MODE" = "https" ]; then
  assert_blocked https://1.0.0.1
  assert_blocked http://1.0.0.1
else
  log "[IP] Skipping blocked IP tests in DNS mode"
fi
