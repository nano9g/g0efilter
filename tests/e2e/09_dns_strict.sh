#!/usr/bin/env bash
# Phase 7: dns-strict mode - connection-time enforcement via kernel timeout sets.
# Unlike plain dns mode, connections to IPs never resolved through the proxy are dropped.
# Recreates the container with FILTER_MODE=dns-strict; runs in the dns CI matrix only.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [ "$FILTER_MODE" != "dns" ]; then
  log "Skipping dns-strict phase in $FILTER_MODE matrix (runs once, in the dns lane)"
  exit 0
fi

log "=== Phase 7: dns-strict connection-time enforcement ==="

baseline_policy
stack_up FILTER_MODE=dns-strict
wait_ready

nft_contains ip g0efilter_v4 "policy drop" "dns-strict v4 chain is policy drop"
nft_contains ip g0efilter_v4 "resolved_allow_v4" "resolved_allow_v4 set present"
nft_contains ip6 g0efilter_v6 "resolved_allow_v6" "resolved_allow_v6 set present"

log "[Strict] Allowed domain resolves and connects"
assert_allowed https://github.com

log "[Strict] Resolved IPs were pushed into the kernel set with a timeout"
$COMPOSE exec g0efilter nft list set ip g0efilter_v4 resolved_allow_v4 | grep -q "timeout" \
  || fail "resolved_allow_v4 has no timeout entries after an allowed resolution"
log "OK: resolved_allow_v4 populated"

log "[Strict] Blocked domain is sinkholed at DNS"
assert_blocked https://google.com

log "[Strict] Hardcoded IP never resolved through the proxy must be DROPPED"
# This is the enforcement gap vs plain dns mode: there this connection would succeed.
assert_blocked https://1.0.0.1

log "[Strict] Statically allow-listed IP still connects"
assert_allowed https://1.1.1.1

log "[Strict] Second lookup of the allowed domain still works (set refresh path)"
run_curl "curl -sS --max-time 10 -H 'Cache-Control: no-cache' https://github.com -o /dev/null" \
  || fail "repeat request to allowed domain failed"
log "OK: repeat resolution/connection works"

log "OK: dns-strict mode verified"
