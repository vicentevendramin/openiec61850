#!/usr/bin/env bash
# Reverse interop (ADR 0007): drives the interactive IEC61850bean console client against an
# IEC 61850 server (normally openiec61850-server serving interop/server/simpleIO.icd) and turns what
# it prints into PASS / FAIL lines plus a summary.
#
#   run_client.sh [--timeout SECONDS] HOST [PORT]
#
# Clean-room (ADR 0001): the prompts below come only from running the application (--help and its
# menus), never from its sources. Its menu has no write and no control action, and it refuses BRCBs
# ("not yet supported by the console application"), so those are only covered in the other
# direction. An invalid answer makes it exit, so every prompt is awaited before answering.
#
# Environment: BEAN_LIB (directory of the jars), JAVA (default java), LOG_DIR (default: a temporary
# directory). Exit status: 0 when nothing FAILed, 1 otherwise, 2 on usage errors.
set -uo pipefail

timeout_s=8
while [[ $# -gt 0 && "$1" == --* ]]; do
  case "$1" in
    --timeout) timeout_s="$2"; shift 2 ;;
    *) echo "usage: $0 [--timeout SECONDS] HOST [PORT]" >&2; exit 2 ;;
  esac
done
[[ $# -ge 1 ]] || { echo "usage: $0 [--timeout SECONDS] HOST [PORT]" >&2; exit 2; }
host="$1"
port="${2:-102}"
target="${host}:${port}"
ld=simpleIOGenericIO
logs="${LOG_DIR:-$(mktemp -d)}"
mkdir -p "${logs}"
log="${logs}/console-client.log"
fifo="${logs}/console-client.stdin"

pass=0
fail=0
offset=0  # lines of ${log} already consumed by expect

result() {
  if [[ "$2" == PASS ]]; then
    printf '[%s] %-34s PASS %s\n' "${target}" "$1" "${3:-}"
    pass=$((pass + 1))
  else
    printf '[%s] %-34s FAIL %s\n' "${target}" "$1" "${3:-}"
    fail=$((fail + 1))
  fi
}

# expect REGEX: waits for a line after the last match; consumes the output up to it.
expect() {
  local deadline=$((SECONDS + timeout_s)) line
  while ((SECONDS < deadline)); do
    line="$(tail -n "+$((offset + 1))" "${log}" | grep -n -m 1 -E -- "$1" | cut -d: -f1)"
    if [[ -n "${line}" ]]; then
      offset=$((offset + line))
      return 0
    fi
    kill -0 "${client}" 2> /dev/null || return 1
    sleep 0.1
  done
  return 1
}

# Counts lines matching REGEX after the current position, without consuming them.
count() { tail -n "+$((offset + 1))" "${log}" | grep -c -E -- "$1"; }

say() { printf '%s\n' "$1" >&3; }

# step NAME REGEX: one check; a client that has exited fails everything after it.
step() {
  if expect "$2"; then
    result "$1" PASS
  else
    result "$1" FAIL "no /$2/ within ${timeout_s}s"
    return 1
  fi
}

# read_value REF FC: the "g" action, GetDataValues of one attribute.
read_value() {
  expect '^\*\* Enter action key' && say g &&
    expect '^Enter reference' && say "$1" &&
    expect '^Enter functional constraint' && say "$2"
}

# report_session NAME RCB: enable, integrity reports, GI, disable, as the RCB menu offers them.
report_session() {
  local name="$1" rcb="$2"
  expect '^\*\* Enter action key' && say r && expect '^Enter the URCB reference' && say "${rcb}"
  expect '^0 - quit' && say 3
  # From here reports and the menu interleave, so its prompt cannot be awaited: the application
  # is simply blocked on stdin between the answers.
  step "${name}/enable" '^Enabling reporting\.\.done' || return 1
  step "${name}/integrity" 'reason: integrity$' || return 1
  say 8
  step "${name}/gi" 'reason: general-interrogation$' || return 1
  say 4
  step "${name}/disable" '^Disabling reporting\.\.done' || return 1
  say 0
}

session() {
  step discovery/connect '^successfully connected$' || return
  step discovery/model '^successfully read model$' || return
  expect '^\*\* Enter action key' && say m
  step discovery/data-object "^${ld}/GGIO1\.SPCSO1\.stVal: " || return
  step discovery/urcb "^${ld}/LLN0\.EventsRCB01 \[RP\]\$" || return
  step discovery/brcb "^${ld}/LLN0\.EventsBRCB01 \[BR\]\$" || return
  step discovery/data-set "^${ld}/LLN0\.Events" || return

  expect '^\*\* Enter action key' && say ga
  step read/all '^Reading all data\.\.\.done$' || return
  read_value "${ld}/GGIO1.AnIn1.mag.f" MX
  step read/value "^${ld}/GGIO1\.AnIn1\.mag\.f: -?[0-9]" || return

  expect '^\*\* Enter action key' && say cds
  expect '^Enter the reference of the data set' && say "${ld}/LLN0.BeanDyn"
  expect '^How many entries' && say 2
  expect '^Enter reference' && say "${ld}/GGIO1.SPCSO1.stVal"
  expect '^Enter functional constraint' && say ST
  expect '^Enter reference' && say "${ld}/GGIO1.AnIn1.mag.f"
  expect '^Enter functional constraint' && say MX
  step data-set/create '^Creating data set\.\.done$' || return
  expect '^\*\* Enter action key' && say dds
  expect '^Enter the reference of the data set' && say "${ld}/LLN0.BeanDyn"
  step data-set/delete '^Deleting data set\.\.done$' || return

  report_session report/urcb "${ld}/LLN0.EventsRCB01" || return
  report_session report/indexed-urcb "${ld}/LLN0.EventsIndexed02" || return

  expect '^\*\* Enter action key' && say q
  local deadline=$((SECONDS + timeout_s))
  while kill -0 "${client}" 2> /dev/null && ((SECONDS < deadline)); do sleep 0.1; done
  if kill -0 "${client}" 2> /dev/null; then
    result quit FAIL "still running ${timeout_s}s after q"
  else
    result quit PASS
  fi
}

rm -f "${fifo}"
mkfifo "${fifo}"
: > "${log}"
"${JAVA:-java}" -cp "${BEAN_LIB}/*" com.beanit.iec61850bean.app.ConsoleClient -h "${host}" -p "${port}" \
  < "${fifo}" > "${log}" 2>&1 &
client=$!
exec 3> "${fifo}"
session
if kill -0 "${client}" 2> /dev/null; then kill "${client}" 2> /dev/null; fi
exec 3>&-
wait "${client}" 2> /dev/null
rm -f "${fifo}"

if grep -q -E 'Exception|Error' "${log}"; then
  result console-errors FAIL "exception in ${log}:"
  grep -m 5 -E 'Exception|Error' "${log}" | sed 's/^/    | /'
fi

echo
echo "Summary (IEC61850bean client -> ${target}): ${pass} PASS, ${fail} FAIL (log in ${log})"
[[ ${fail} -eq 0 ]]
