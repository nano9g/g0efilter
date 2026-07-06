# Configuration

## Environment variables

### g0efilter

| Variable | Description | Default |
| --- | --- | --- |
| `FILTER_MODE` | `https`, `dns`, or `dns-strict` | `https` |
| `POLICY_PATH` | Path to policy file inside container. When unset, `/app/policy.yaml` is used if present, then `/app/policy/policy.yaml` (the directory-mount convention). The file is never auto-created. | `/app/policy.yaml` |
| `DEFAULT_ACTION` | `deny` (allowlist) or `allow` (denylist). Policy file `default_action` wins when set | `deny` |
| `ENFORCE` | `block` or `audit` (dry-run: log would-be blocks, allow traffic) | `block` |
| `LEARNING_MODE` | `true` to observe without blocking and auto-append seen domains/IPs to the policy | `false` |
| `PROCESS_INFO` | `true` to add pid/process fields to flow logs (needs shared PID namespace) | `false` |
| `ALLOWLIST_IPS` | Comma-separated allowed IPs/CIDRs (takes precedence over policy file) | unset |
| `ALLOWLIST_DOMAINS` | Comma-separated allowed domains (exact/wildcard/regex) | unset |
| `DENYLIST_IPS` | Comma-separated denied IPs/CIDRs (with `DEFAULT_ACTION=allow`) | unset |
| `DENYLIST_DOMAINS` | Comma-separated denied domains (with `DEFAULT_ACTION=allow`) | unset |
| `HTTP_PORT` | Local HTTP proxy port | `8080` |
| `HTTPS_PORT` | Local HTTPS proxy port | `8443` |
| `DNS_PORT` | DNS listen port | `53` |
| `DNS_UPSTREAMS` | Upstream DNS servers (comma-separated) | `127.0.0.11:53` |
| `DNS_HARDENING` | Anti-exfil checks in the DNS proxy: qname/label length caps, NULL and bulky-TXT answer rejection, per-source rate limiting | `true` |
| `DNS_RATE_QPS` | Hardening rate limiter: sustained queries/sec per source. All local traffic shares one source behind the NAT redirect, so this bounds the whole host | `50` |
| `DNS_RATE_BURST` | Hardening rate limiter: burst allowance per source | `100` |
| `LOG_LEVEL` | TRACE, DEBUG, INFO, WARN, ERROR | `INFO` |
| `LOG_FILE` | Optional path for a persistent log file | unset |
| `HOSTNAME` | Identifies this instance in shipped logs | unset |
| `DASHBOARD_HOST` | Dashboard URL for log shipping | unset |
| `DASHBOARD_API_KEY` | Must match `API_KEY` on the dashboard | unset |
| `DASHBOARD_QUEUE_SIZE` | Log buffer before shipping; drops when full | `1024` |
| `DASHBOARD_START_DELAY` | Delay before log shipping starts (`5s`, `1m`, ...) | `5s` |
| `ENABLE_REMOTE_UNBLOCK` | Poll dashboard for remote unblock requests | `false` |
| `UNBLOCK_POLL_INTERVAL` | Unblock poll interval | `10s` |
| `NOTIFICATION_HOST` | Gotify server URL for blocked-traffic alerts | unset |
| `NOTIFICATION_KEY` | Gotify application key | unset |
| `NOTIFICATION_BACKOFF_SECONDS` | Duplicate-alert backoff | `60` |
| `NOTIFICATION_IGNORE_DOMAINS` | Domains to skip for notifications (wildcards ok) | unset |
| `NFLOG_BUFSIZE` | Netfilter log buffer size | `96` |
| `NFLOG_QTHRESH` | Netfilter log queue threshold | `50` |

### g0efilter-dashboard

| Variable | Description | Default |
| --- | --- | --- |
| `PORT` | Listen address/port for UI and API | `:8081` |
| `API_KEY` | Authenticates log ingestion from g0efilter | unset |
| `LOG_LEVEL` | TRACE, DEBUG, INFO, WARN, ERROR | `INFO` |
| `BUFFER_SIZE` | In-memory event buffer; oldest dropped when full | `5000` |
| `READ_LIMIT` | Max events per API request | `5000` |
| `SSE_RETRY_MS` | SSE client retry interval (ms) | `2000` |
| `WRITE_TIMEOUT` | HTTP write timeout in seconds (0 = none, recommended for SSE) | `0` |
| `RATE_RPS` | Rate limit, requests per second | `50` |
| `RATE_BURST` | Rate limit burst | `100` |
