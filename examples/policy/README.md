# Example policies

The compose files mount this directory and g0efilter reads `policy.yaml`
(`POLICY_PATH=/app/policy/policy.yaml`). To try a different example, copy it over
`policy.yaml` - the file is live-reloaded, no container restart needed.

| File | Stance | What it shows |
|---|---|---|
| `policy.yaml` | default-deny (allowlist) | Block everything except listed IPs/CIDRs and domains - the classic g0efilter model |
| `policy-default-allow.yaml` | default-allow (denylist) | Allow everything except analytics/telemetry domains and the LAN, with an allowlist override |

## Domain entry forms

All domain lists (allowlist and denylist) accept three forms:

```yaml
domains:
  - "github.com"                          # exact
  - "*.example.com"                       # wildcard - any subdomain level
  - "bucket.*.r2.example.com"             # wildcard works mid-name too
  - '/^cache-[0-9]+\.example\.com$/'      # regex - anchored, case-insensitive
```

Each `*` matches one or more characters **including dots**, so `sub.*.example.com`
covers `sub.a.example.com` and `sub.a.b.example.com`. Reach for regex when you
need more precision than that (character classes, alternation, or a wildcard
that must stay within a single label, e.g. `/^sub\.\w+\.example\.com$/`).

Use **single quotes** around regex entries so YAML doesn't eat the backslashes.
Patterns are matched against the whole hostname (anchoring is automatic) and
compiled with Go's linear-time RE2 engine.

## Choosing the stance

`default_action` lives in the policy file (default `deny`), so flipping it is a
live-reload edit. The `DEFAULT_ACTION` environment variable only provides the
bootstrap default when the file doesn't set it. When `default_action: allow`:

- traffic passes unless it matches the `denylist`
- an `allowlist` match always overrides the denylist
- denylisted IPs are dropped in nftables; denylisted domains are enforced by the
  SNI/Host proxies (https mode) or the DNS sinkhole (dns mode)

## Learning mode

To bootstrap an allowlist for a new container, set `LEARNING_MODE=true` on the
g0efilter container: nothing is blocked, and every observed domain (or
destination IP when no SNI/Host is available) not already covered is appended to
`policy.yaml` automatically. Run it for a representative period, prune the result,
then unset the variable to return to enforcement.
