# End-to-end tests

Version-controlled e2e suite, run by CI (`.github/workflows/test.yaml`) and runnable locally.

## Run locally

Requires Docker with the compose plugin. From the repo root:

```sh
FILTER_MODE=https scripts/e2e.sh
FILTER_MODE=dns   scripts/e2e.sh
```

`scripts/e2e.sh` builds and starts the `examples/build` stack, runs every phase, dumps
container logs on failure, and tears down (restoring the baseline policy file).

## Phases

| Script | Covers |
|---|---|
| `01_baseline.sh` | allow/block for domains and IPs against the baseline policy |
| `02_ipv6_egress.sh` | IPv6 egress blocked with no IPv6 policy entries (https mode) |
| `03_unblock_reload.sh` | dashboard remote-unblock API -> live policy reload, API error paths |
| `04_ipv6_unblock.sh` | IPv6 remote unblock -> nftables set update (https mode) |
| `05_dashboard_logs.sh` | proxy -> dashboard log ingestion end-to-end |
| `06_regex.sh` | `/regex/` and mid-name wildcard (`www.*.com`) domain patterns |
| `07_default_allow.sh` | `default_action: allow` + denylist (domains, IPs, allowlist override) |
| `08_learning.sh` | learning mode: nothing blocked, observed domains/IPs appended to policy |
| `09_dns_strict.sh` | dns-strict: resolved IPs land in kernel timeout sets, never-resolved IPs dropped (dns lane only) |
| `10_audit.sh` | audit (dry-run) enforcement: would-be-blocked traffic passes and reaches the dashboard as AUDIT (https lane only) |

Individual phase scripts assume the stack is already up (except `08_learning.sh`,
which recreates the g0efilter container with `LEARNING_MODE=true`). Shared helpers
live in `lib.sh`.
