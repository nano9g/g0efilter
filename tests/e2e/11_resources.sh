#!/usr/bin/env bash
# Resource guardrail: catch runaway CPU and obvious memory growth. This is a
# smoke test, not a benchmark; thresholds are intentionally conservative for CI.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

MAX_MEMORY_MIB="${E2E_MAX_MEMORY_MIB:-256}"
MAX_MEMORY_GROWTH_MIB="${E2E_MAX_MEMORY_GROWTH_MIB:-64}"
MAX_IDLE_CPU_PERCENT="${E2E_MAX_IDLE_CPU_PERCENT:-25}"
CPU_SAMPLE_SECONDS="${E2E_CPU_SAMPLE_SECONDS:-6}"

log "=== Phase 9: resource guardrails [$FILTER_MODE mode] ==="

container_memory_bytes() {
  local bytes

  bytes=$($COMPOSE exec g0efilter sh -lc '
    if [ -r /sys/fs/cgroup/memory.current ]; then
      cat /sys/fs/cgroup/memory.current
    elif [ -r /sys/fs/cgroup/memory/memory.usage_in_bytes ]; then
      cat /sys/fs/cgroup/memory/memory.usage_in_bytes
    else
      exit 2
    fi
  ') || return 1

  bytes=$(printf '%s' "$bytes" | tr -dc '0-9')
  [ -n "$bytes" ] || return 1
  echo "$bytes"
}

container_cpu_usage_ns() {
  local ns

  ns=$($COMPOSE exec g0efilter sh -lc '
    if [ -r /sys/fs/cgroup/cpu.stat ]; then
      while read -r key value _; do
        if [ "$key" = "usage_usec" ]; then
          echo $((value * 1000))
          exit 0
        fi
      done < /sys/fs/cgroup/cpu.stat
      exit 2
    elif [ -r /sys/fs/cgroup/cpuacct/cpuacct.usage ]; then
      cat /sys/fs/cgroup/cpuacct/cpuacct.usage
    else
      exit 2
    fi
  ') || return 1

  ns=$(printf '%s' "$ns" | tr -dc '0-9')
  [ -n "$ns" ] || return 1
  echo "$ns"
}

now_ns() {
  local ns

  ns=$(date +%s%N) || return 1
  case "$ns" in
    *[!0-9]*|"") return 1 ;;
  esac

  echo "$ns"
}

bytes_to_mib() {
  echo $(( ($1 + 1048575) / 1048576 ))
}

idle_cpu_percent_tenths() {
  local cpu_start wall_start cpu_end wall_end cpu_delta wall_delta

  cpu_start=$(container_cpu_usage_ns) || return 1
  wall_start=$(now_ns) || return 1
  sleep "$CPU_SAMPLE_SECONDS"
  cpu_end=$(container_cpu_usage_ns) || return 1
  wall_end=$(now_ns) || return 1

  cpu_delta=$((cpu_end - cpu_start))
  wall_delta=$((wall_end - wall_start))
  [ "$wall_delta" -gt 0 ] || return 1

  echo $((cpu_delta * 1000 / wall_delta))
}

format_tenths() {
  printf '%d.%d' "$(($1 / 10))" "$(($1 % 10))"
}

baseline_policy
stack_up
wait_ready

log "[Resources] Capturing baseline memory"
MEM_BEFORE=$(container_memory_bytes) || fail "could not read baseline g0efilter memory usage from cgroup"
log "Baseline memory: $(bytes_to_mib "$MEM_BEFORE") MiB"

log "[Resources] Generating modest allowed/blocked traffic"
for _ in $(seq 1 6); do
  assert_allowed https://github.com 10
  assert_blocked https://google.com 3
done

sleep 3

log "[Resources] Checking memory ceiling and growth"
MEM_AFTER=$(container_memory_bytes) || fail "could not read final g0efilter memory usage from cgroup"
MEM_AFTER_MIB=$(bytes_to_mib "$MEM_AFTER")
MEM_GROWTH=$((MEM_AFTER - MEM_BEFORE))
[ "$MEM_GROWTH" -lt 0 ] && MEM_GROWTH=0
MEM_GROWTH_MIB=$(bytes_to_mib "$MEM_GROWTH")

log "Memory after traffic: ${MEM_AFTER_MIB} MiB (growth ${MEM_GROWTH_MIB} MiB)"

if [ "$MEM_AFTER" -gt "$((MAX_MEMORY_MIB * 1024 * 1024))" ]; then
  fail "g0efilter memory ${MEM_AFTER_MIB} MiB exceeds ${MAX_MEMORY_MIB} MiB"
fi

if [ "$MEM_GROWTH" -gt "$((MAX_MEMORY_GROWTH_MIB * 1024 * 1024))" ]; then
  fail "g0efilter memory grew ${MEM_GROWTH_MIB} MiB, limit ${MAX_MEMORY_GROWTH_MIB} MiB"
fi

log "[Resources] Measuring idle CPU over ${CPU_SAMPLE_SECONDS}s"
CPU_TENTHS=$(idle_cpu_percent_tenths) || fail "could not sample g0efilter CPU usage from cgroup"
MAX_CPU_TENTHS=$((MAX_IDLE_CPU_PERCENT * 10))
log "Idle CPU: $(format_tenths "$CPU_TENTHS")% (limit ${MAX_IDLE_CPU_PERCENT}%)"

if [ "$CPU_TENTHS" -gt "$MAX_CPU_TENTHS" ]; then
  fail "g0efilter idle CPU $(format_tenths "$CPU_TENTHS")% exceeds ${MAX_IDLE_CPU_PERCENT}%"
fi

log "OK: resource guardrails passed"
