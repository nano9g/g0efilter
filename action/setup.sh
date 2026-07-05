#!/usr/bin/env bash
# Starts g0efilter on the runner host (host network + NET_ADMIN) and waits until
# the policy is applied. Inputs arrive as env vars via action/main.js.
set -euo pipefail

MODE="${FILTER_MODE:-https}"
POLICY="${EGRESS_POLICY:-block}"

# Default image: the release matching the action's tag, so pinning the action
# pins the filter too; :latest when used via a branch ref.
IMAGE="${G0EFILTER_IMAGE:-}"
if [ -z "$IMAGE" ]; then
  case "${GITHUB_ACTION_REF:-}" in
    v[0-9]*) IMAGE="docker.io/g0lab/g0efilter:${GITHUB_ACTION_REF}" ;;
    *) IMAGE="docker.io/g0lab/g0efilter:latest" ;;
  esac
fi

case "$MODE" in
  https|dns) ;;
  *) echo "::error::mode must be 'https' or 'dns' (got '$MODE')"; exit 1 ;;
esac
case "$POLICY" in
  block|audit) ;;
  *) echo "::error::egress-policy must be 'block' or 'audit' (got '$POLICY')"; exit 1 ;;
esac

WORKDIR="${RUNNER_TEMP:-/tmp}/g0efilter"
mkdir -p "$WORKDIR/policy"
POLICY_FILE="$WORKDIR/policy/policy.yaml"

# GitHub's documented runner communication domains
# (https://docs.github.com/actions/reference/runners/self-hosted-runners).
# Deliberately no ghcr.io / *.pkg.github.com: pulling packages or containers is
# a workflow concern, not runner baseline - add via allowed-domains if needed.
BASE_DOMAINS=(
  # Essential runner operation
  "github.com"
  "api.github.com"
  "*.actions.githubusercontent.com"

  # Downloading actions
  "codeload.github.com"

  # Job summaries, logs, workflow artifacts and caches
  "results-receiver.actions.githubusercontent.com"
  "*.blob.core.windows.net"

  # Release/object downloads
  "objects.githubusercontent.com"
  "objects-origin.githubusercontent.com"
  "github-releases.githubusercontent.com"
  "github-registry-files.githubusercontent.com"
)

# DNS must keep working under default-deny: allow the host's upstream resolvers
# and the Azure DNS/metadata endpoints GitHub-hosted runners depend on.
BASE_IPS=("168.63.129.16" "169.254.169.254")
RESOLV_SRC="/run/systemd/resolve/resolv.conf"
[ -f "$RESOLV_SRC" ] || RESOLV_SRC="/etc/resolv.conf"
while read -r ip; do
  BASE_IPS+=("$ip")
done < <(awk '/^nameserver/ {print $2}' "$RESOLV_SRC" 2>/dev/null || true)

# YAML single-quoted so regex/wildcard entries survive verbatim.
yaml_entry() {
  local v="${1//\'/\'\'}"
  printf "    - '%s'\n" "$v"
}

{
  echo "---"
  echo "allowlist:"
  echo "  domains:"
  for d in "${BASE_DOMAINS[@]}"; do yaml_entry "$d"; done
  while read -r d; do
    [ -n "$d" ] && yaml_entry "$d"
  done <<< "${ALLOWED_DOMAINS:-}"
  echo "  ips:"
  for ip in "${BASE_IPS[@]}"; do yaml_entry "$ip"; done
  while read -r ip; do
    [ -n "$ip" ] && yaml_entry "$ip"
  done <<< "${ALLOWED_IPS:-}"
} > "$POLICY_FILE"

ENFORCE="block"
[ "$POLICY" = "audit" ] && ENFORCE="audit"

echo "Starting g0efilter (image: $IMAGE, mode: $MODE, egress-policy: $POLICY)"

DOCKER_ARGS=(
  -d --name g0efilter
  --network host
  --cap-drop ALL --cap-add NET_ADMIN
  --security-opt no-new-privileges
  -v "$WORKDIR/policy/:/app/policy/"
  -e POLICY_PATH=/app/policy/policy.yaml
  -e FILTER_MODE="$MODE"
  -e ENFORCE="$ENFORCE"
  -e LOG_LEVEL="${LOG_LEVEL:-INFO}"
)

# Port 53 on the host is taken by systemd-resolved; the NAT redirect still
# captures all DNS and sends it to the proxy's alternate port.
[ "$MODE" = "dns" ] && DOCKER_ARGS+=(-e DNS_PORT=5353)

docker run "${DOCKER_ARGS[@]}" "$IMAGE"

echo "Waiting for policy to be applied..."
for _ in $(seq 1 60); do
  if docker logs g0efilter 2>&1 | grep -q "policy.applied"; then
    echo "g0efilter is active - egress is now filtered ($POLICY mode)"
    exit 0
  fi
  if [ -z "$(docker ps -q --filter name=g0efilter)" ]; then
    break
  fi
  sleep 1
done

echo "::error::g0efilter failed to start - egress filtering is NOT active"
docker logs g0efilter 2>&1 | tail -50 || true
docker rm -f g0efilter > /dev/null 2>&1 || true
exit 1
