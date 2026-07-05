#!/usr/bin/env bash
# Phase 1.5: IPv6 egress blocked when no IPv6 entries are in the policy (https mode only).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [ "$FILTER_MODE" != "https" ]; then
  log "Skipping IPv6 egress phase in $FILTER_MODE mode"
  exit 0
fi

log "=== Phase 1.5: IPv6 egress filtering (no IPv6 in policy) ==="

nft_contains ip6 g0efilter_v6 "policy drop" "ip6 filter table loaded with policy drop"
nft_contains ip6 g0efilter_v6 "allow_daddr_v6" "allow_daddr_v6 set present (::1 placeholder)"

log "[IPv6] Verify ip6 NAT table exists"
$COMPOSE exec g0efilter nft list tables | grep -q "g0efilter_nat_v6" \
  || fail "g0efilter_nat_v6 table not found"
log "OK: g0efilter_nat_v6 table present"

log "[IPv6] curl -6 should FAIL (no IPv6 in policy)"
if run_curl "curl -6 -sS --max-time 5 https://google.com -o /dev/null 2>&1"; then
  fail "IPv6 connection succeeded but should be blocked"
fi
log "OK: IPv6 egress blocked by proxy"
