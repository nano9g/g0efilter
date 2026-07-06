# Policy

## Allowlist policy

```yaml
allowlist:
  ips:
    - "1.1.1.1"
    - "192.168.0.0/16"
  domains:
    - "github.com"                                 # exact
    - "*.alpinelinux.org"                          # wildcard, any subdomain level
    - "bucket.*.r2.cloudflarestorage.com"          # wildcard works mid-name too
    - '/^cache-[0-9]+\.example\.com$/'             # regex (single-quote it in YAML)
```

Each `*` matches one or more characters including dots. Regex entries are slash-delimited, matched case-insensitively against the whole hostname (anchoring is automatic), and compiled with Go's linear-time RE2 engine. Ready-made example policies live in [examples/policy/](../examples/policy).

The policy file live-reloads: edits apply without restarting the container. Mount the policy *directory*, not the single file, or editors that use atomic save will silently break reloads:

```yaml
volumes:
  - ./policy/:/app/policy/   # correct
# NOT: - ./policy.yaml:/app/policy.yaml
```

Environment variables (`ALLOWLIST_IPS`, `ALLOWLIST_DOMAINS`, ...) can replace the policy file and take precedence when set. See [configuration.md](configuration.md) for environment variables.

## Default-allow denylist mode

Set `default_action: allow` in the policy file to invert the model: traffic passes unless it matches the `denylist`. Useful for containers that need broad internet access but should be kept away from analytics/telemetry endpoints or the LAN. An explicit allowlist match always overrides the denylist.

```yaml
default_action: allow
allowlist:
  domains:
    - "api.github.com"        # explicitly allow this host even though *.github.com is denylisted
denylist:
  ips:
    - "192.168.0.0/16"        # block LAN access
  domains:
    - "*.github.com"          # deny broad GitHub subdomains
    - "*.doubleclick.net"
    - "telemetry.example.com"
```

Because `default_action` lives in the policy file, flipping it is a live-reload edit. When it is `deny` (the default), the denylist is ignored.

## Learning mode

`LEARNING_MODE=true` runs g0efilter observe-only: nothing is blocked and every domain (or destination IP when no SNI/Host is present) not already covered is appended to the policy file. Run it for a representative period, prune the result, then switch back to enforcement.

## Audit mode

`ENFORCE=audit` is a dry run for an existing policy: would-be-blocked traffic is allowed through and logged with the `AUDIT` action (visible in the dashboard), so you can preview a policy's impact before enforcing it. Unlike learning mode, nothing is written to the policy file.

## Process attribution

`PROCESS_INFO=true` enriches flow logs with the owning process (`pid`, `process_name`, `cmdline`, `executable`), resolved via `/proc` and cached per flow. This requires g0efilter to share a PID namespace with the client processes (host deploy, `pid: host`, or `shareProcessNamespace: true`); in a plain network-only sidecar the fields degrade to `process_name=unknown`.
