#!/usr/bin/env bash
# infra-doctor — one-file SRE-ish preflight checker
# Usage:
#   ./infra-doctor check all --target example.com
#   ./infra-doctor check dns ssl http --target example.com
#   ./infra-doctor check disk mem cpu
#   ./infra-doctor list
#   ./infra-doctor --help

set -u
set -o pipefail

APP="infra-doctor"
VERSION="0.1.0"

# -----------------------------
# Defaults
# -----------------------------
TARGET=""
TIMEOUT_SEC=4
NO_COLOR=0
FAIL_FAST=0
VERBOSE=0

# status codes inside checks
S_OK=0
S_WARN=1
S_FAIL=2
S_SKIP=3

# global aggregated status
GLOBAL_STATUS=$S_OK

# results storage
RESULTS_NAME=()
RESULTS_STATUS=()
RESULTS_MSG=()

# -----------------------------
# Colors
# -----------------------------
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'
  C_DIM=$'\033[2m'
  C_RED=$'\033[31m'
  C_YEL=$'\033[33m'
  C_GRN=$'\033[32m'
  C_BLU=$'\033[34m'
else
  C_RESET="" C_DIM="" C_RED="" C_YEL="" C_GRN="" C_BLU=""
fi

if [[ "$NO_COLOR" -eq 1 ]]; then
  C_RESET="" C_DIM="" C_RED="" C_YEL="" C_GRN="" C_BLU=""
fi

badge() {
  local s="$1"
  case "$s" in
    "$S_OK")   printf "%s[OK]%s"   "$C_GRN" "$C_RESET" ;;
    "$S_WARN") printf "%s[WARN]%s" "$C_YEL" "$C_RESET" ;;
    "$S_FAIL") printf "%s[FAIL]%s" "$C_RED" "$C_RESET" ;;
    "$S_SKIP") printf "%s[SKIP]%s" "$C_DIM" "$C_RESET" ;;
    *)         printf "[?]" ;;
  esac
}

# -----------------------------
# Utils
# -----------------------------
have() { command -v "$1" >/dev/null 2>&1; }

die() { echo "$APP: $*" >&2; exit 2; }

log() { echo "$*"; }

vlog() { [[ "$VERBOSE" -eq 1 ]] && echo "${C_DIM}>>${C_RESET} $*" >&2 || true; }

trim() {
  local x="$*"
  # shellcheck disable=SC2001
  echo "$x" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

run_timeout() {
  # run_timeout <seconds> <cmd...>
  local t="$1"; shift
  if have timeout; then
    timeout "${t}s" "$@"
  else
    # fallback: no hard timeout, just run
    "$@"
  fi
}

add_result() {
  local name="$1" status="$2" msg="$3"
  RESULTS_NAME+=("$name")
  RESULTS_STATUS+=("$status")
  RESULTS_MSG+=("$msg")

  # aggregate
  if [[ "$status" -gt "$GLOBAL_STATUS" ]]; then
    # SKIP shouldn't upgrade the overall result
    if [[ "$status" -ne "$S_SKIP" ]]; then
      GLOBAL_STATUS="$status"
    fi
  fi

  printf "%-14s %s %s\n" "$name" "$(badge "$status")" "$msg"

  if [[ "$FAIL_FAST" -eq 1 && "$status" -eq "$S_FAIL" ]]; then
    exit 2
  fi
}

dep_skip() {
  local name="$1" dep="$2"
  add_result "$name" "$S_SKIP" "missing dependency: $dep"
}

is_ip() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

# -----------------------------
# Checks
# -----------------------------

check_dns() {
  local name="dns"
  local t="${TARGET:-}"
  if [[ -z "$t" ]]; then
    add_result "$name" "$S_SKIP" "--target is empty"
    return
  fi

  if have dig; then
    vlog "dig +short $t"
    local out
    out="$(run_timeout "$TIMEOUT_SEC" dig +short "$t" A 2>/dev/null | head -n1 || true)"
    if [[ -n "$out" ]]; then
      add_result "$name" "$S_OK" "$t -> $out"
    else
      add_result "$name" "$S_FAIL" "no A record for $t"
    fi
  elif have nslookup; then
    local out
    out="$(run_timeout "$TIMEOUT_SEC" nslookup "$t" 2>/dev/null | awk '/Address: /{print $2}' | tail -n1 || true)"
    if [[ -n "$out" ]]; then
      add_result "$name" "$S_OK" "$t -> $out"
    else
      add_result "$name" "$S_FAIL" "nslookup failed for $t"
    fi
  else
    dep_skip "$name" "dig|nslookup"
  fi
}

check_ping() {
  local name="ping"
  local t="${TARGET:-}"
  if [[ -z "$t" ]]; then
    add_result "$name" "$S_SKIP" "--target is empty"
    return
  fi
  if ! have ping; then
    dep_skip "$name" "ping"
    return
  fi

  # ping domain or IP
  vlog "ping -c1 -W1 $t"
  if run_timeout "$TIMEOUT_SEC" ping -c1 -W1 "$t" >/dev/null 2>&1; then
    add_result "$name" "$S_OK" "$t reachable"
  else
    add_result "$name" "$S_WARN" "$t ping failed (ICMP может быть закрыт — это не всегда проблема)"
  fi
}

check_http() {
  local name="http"
  local t="${TARGET:-}"
  if [[ -z "$t" ]]; then
    add_result "$name" "$S_SKIP" "--target is empty"
    return
  fi
  if ! have curl; then
    dep_skip "$name" "curl"
    return
  fi

  # try https first, then http
  local url status time_total
  for url in "https://$t" "http://$t"; do
    vlog "curl -sS -o /dev/null -w %{http_code} $url"
    status="$(run_timeout "$TIMEOUT_SEC" curl -sS -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || true)"
    time_total="$(run_timeout "$TIMEOUT_SEC" curl -sS -o /dev/null -w "%{time_total}" "$url" 2>/dev/null || true)"
    status="$(trim "$status")"
    time_total="$(trim "$time_total")"

    if [[ "$status" =~ ^[0-9]{3}$ ]]; then
      if [[ "$status" -ge 200 && "$status" -lt 400 ]]; then
        add_result "$name" "$S_OK" "$url -> $status (${time_total}s)"
      elif [[ "$status" -ge 400 && "$status" -lt 500 ]]; then
        add_result "$name" "$S_WARN" "$url -> $status (${time_total}s)"
      else
        add_result "$name" "$S_FAIL" "$url -> $status (${time_total}s)"
      fi
      return
    fi
  done

  add_result "$name" "$S_FAIL" "curl failed to get status from https/http"
}

check_ssl() {
  local name="ssl"
  local t="${TARGET:-}"
  if [[ -z "$t" ]]; then
    add_result "$name" "$S_SKIP" "--target is empty"
    return
  fi
  if ! have openssl; then
    dep_skip "$name" "openssl"
    return
  fi

  # connect and parse notAfter
  # Note: this is a best-effort check; some hosts require SNI, we set -servername
  local not_after
  not_after="$(run_timeout "$TIMEOUT_SEC" bash -c \
    "echo | openssl s_client -servername \"$t\" -connect \"$t:443\" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null" \
    || true)"

  not_after="$(trim "$not_after")"
  if [[ "$not_after" != notAfter=* ]]; then
    add_result "$name" "$S_WARN" "can't read cert (443 closed / no TLS / blocked)"
    return
  fi

  local date_str
  date_str="${not_after#notAfter=}"

  if have date; then
    local exp_epoch now_epoch days_left
    # macOS date parsing differs; try GNU first, then BSD-ish
    if exp_epoch="$(date -d "$date_str" +%s 2>/dev/null)"; then
      :
    else
      exp_epoch="$(date -j -f "%b %e %T %Y %Z" "$date_str" +%s 2>/dev/null || true)"
    fi

    now_epoch="$(date +%s)"
    if [[ -n "$exp_epoch" ]]; then
      days_left=$(( (exp_epoch - now_epoch) / 86400 ))
      if (( days_left >= 14 )); then
        add_result "$name" "$S_OK" "cert expires in ${days_left}d ($date_str)"
      elif (( days_left >= 3 )); then
        add_result "$name" "$S_WARN" "cert expires in ${days_left}d ($date_str)"
      else
        add_result "$name" "$S_FAIL" "cert expires in ${days_left}d ($date_str)"
      fi
    else
      add_result "$name" "$S_OK" "cert enddate: $date_str"
    fi
  else
    add_result "$name" "$S_OK" "cert enddate: $date_str"
  fi
}

check_disk() {
  local name="disk"
  if ! have df; then
    dep_skip "$name" "df"
    return
  fi

  # check root filesystem usage
  local usep
  usep="$(df -P / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5}' || true)"
  if [[ -z "$usep" ]]; then
    add_result "$name" "$S_WARN" "can't read df /"
    return
  fi

  if (( usep < 80 )); then
    add_result "$name" "$S_OK" "root usage ${usep}%"
  elif (( usep < 90 )); then
    add_result "$name" "$S_WARN" "root usage ${usep}% (поджимает)"
  else
    add_result "$name" "$S_FAIL" "root usage ${usep}% (горит)"
  fi

  # inode usage (nice-to-have)
  if have df; then
    local iusep
    iusep="$(df -Pi / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5}' || true)"
    if [[ -n "$iusep" ]]; then
      if (( iusep >= 90 )); then
        add_result "inodes" "$S_WARN" "inode usage ${iusep}%"
      else
        add_result "inodes" "$S_OK" "inode usage ${iusep}%"
      fi
    fi
  fi
}

check_mem() {
  local name="mem"
  if have free; then
    local mem_total mem_used mem_free mem_usep
    read -r _ mem_total mem_used mem_free _ < <(free -m | awk '/^Mem:/{print $1,$2,$3,$4,$5}')
    if [[ -n "${mem_total:-}" && "$mem_total" -gt 0 ]]; then
      mem_usep=$(( mem_used * 100 / mem_total ))
      if (( mem_usep < 80 )); then
        add_result "$name" "$S_OK" "mem ${mem_usep}% (${mem_used}MB/${mem_total}MB)"
      elif (( mem_usep < 90 )); then
        add_result "$name" "$S_WARN" "mem ${mem_usep}% (${mem_used}MB/${mem_total}MB)"
      else
        add_result "$name" "$S_FAIL" "mem ${mem_usep}% (${mem_used}MB/${mem_total}MB)"
      fi
    else
      add_result "$name" "$S_WARN" "free output looks weird"
    fi
  elif have vm_stat; then
    # macOS-ish fallback
    add_result "$name" "$S_OK" "vm_stat available (macOS). detailed % not implemented"
  else
    dep_skip "$name" "free|vm_stat"
  fi
}

check_cpu() {
  local name="cpu"
  if have uptime; then
    local la
    la="$(uptime 2>/dev/null | awk -F'load averages?: ' '{print $2}' | awk '{print $1}' | tr -d ',' || true)"
    if [[ -n "$la" ]]; then
      add_result "$name" "$S_OK" "loadavg(1m) $la"
    else
      add_result "$name" "$S_WARN" "can't parse uptime"
    fi
  else
    dep_skip "$name" "uptime"
  fi
}

check_docker() {
  local name="docker"
  if ! have docker; then
    dep_skip "$name" "docker"
    return
  fi

  if ! docker info >/dev/null 2>&1; then
    add_result "$name" "$S_WARN" "docker not accessible (daemon down or no permissions)"
    return
  fi

  # unhealthy containers count
  local unhealthy
  unhealthy="$(docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null | awk 'tolower($0) ~ /unhealthy/{c++} END{print c+0}' || true)"
  if [[ -z "$unhealthy" ]]; then unhealthy=0; fi

  if (( unhealthy == 0 )); then
    add_result "$name" "$S_OK" "docker ok, unhealthy=0"
  else
    add_result "$name" "$S_WARN" "docker ok, unhealthy=$unhealthy"
  fi
}

# -----------------------------
# Registry
# -----------------------------
ALL_CHECKS=(dns ping ssl http disk mem cpu docker)

run_check() {
  local c="$1"
  case "$c" in
    dns)    check_dns ;;
    ping)   check_ping ;;
    ssl)    check_ssl ;;
    http)   check_http ;;
    disk)   check_disk ;;
    mem)    check_mem ;;
    cpu)    check_cpu ;;
    docker) check_docker ;;
    *) add_result "$c" "$S_SKIP" "unknown check" ;;
  esac
}

list_checks() {
  printf "%s checks:\n" "$APP"
  for c in "${ALL_CHECKS[@]}"; do
    echo "  - $c"
  done
}

# -----------------------------
# Help
# -----------------------------
usage() {
  cat <<EOF
$APP $VERSION

Commands:
  $APP check all [--target HOST] [--timeout N] [--no-color] [--fail-fast] [--verbose]
  $APP check <name...> [--target HOST] [--timeout N] [--no-color] [--fail-fast] [--verbose]
  $APP list
  $APP version
  $APP --help

Examples:
  $APP check all --target example.com
  $APP check dns ssl http --target api.example.com --timeout 5
  $APP check disk mem cpu

Exit codes:
  0 - OK
  1 - WARN
  2 - FAIL
EOF
}

# -----------------------------
# Arg parse
# -----------------------------
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || "${1:-}" == "" ]]; then
  usage
  exit 0
fi

CMD="${1:-}"; shift || true

CHECKS_TO_RUN=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)   TARGET="${2:-}"; shift 2 ;;
    --timeout)  TIMEOUT_SEC="${2:-4}"; shift 2 ;;
    --no-color) NO_COLOR=1; shift ;;
    --fail-fast) FAIL_FAST=1; shift ;;
    --verbose|-v) VERBOSE=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *)
      # positional args will be handled depending on CMD
      CHECKS_TO_RUN+=("$1")
      shift
      ;;
  esac
done

# re-apply color disable after parsing
if [[ "$NO_COLOR" -eq 1 ]]; then
  C_RESET="" C_DIM="" C_RED="" C_YEL="" C_GRN="" C_BLU=""
fi

# -----------------------------
# Main
# -----------------------------
case "$CMD" in
  version)
    echo "$APP $VERSION"
    exit 0
    ;;
  list)
    list_checks
    exit 0
    ;;
  check)
    if [[ "${#CHECKS_TO_RUN[@]}" -eq 0 ]]; then
      die "no checks specified (use: '$APP check all' or '$APP list')"
    fi

    if [[ "${CHECKS_TO_RUN[0]}" == "all" ]]; then
      CHECKS_TO_RUN=("${ALL_CHECKS[@]}")
    fi

    echo "${C_BLU}$APP${C_RESET} ${C_DIM}timeout=${TIMEOUT_SEC}s target=${TARGET:-<none>}${C_RESET}"
    echo

    for c in "${CHECKS_TO_RUN[@]}"; do
      run_check "$c"
    done

    echo
    case "$GLOBAL_STATUS" in
      "$S_OK")   echo "INFRA STATUS: ${C_GRN}OK${C_RESET}"; exit 0 ;;
      "$S_WARN") echo "INFRA STATUS: ${C_YEL}DEGRADED${C_RESET}"; exit 1 ;;
      "$S_FAIL") echo "INFRA STATUS: ${C_RED}FAIL${C_RESET}"; exit 2 ;;
      *)         echo "INFRA STATUS: UNKNOWN"; exit 2 ;;
    esac
    ;;
  *)
    die "unknown command: $CMD (try --help)"
    ;;
esac
