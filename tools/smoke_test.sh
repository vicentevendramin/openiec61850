#!/usr/bin/env bash
# CTest smoke test of the command-line tools: starts openiec61850-server on an ephemeral port,
# drives it with openiec61850-client and checks exit codes and output, then stops the server
# with SIGTERM and checks that it exits cleanly.
#
#   smoke_test.sh SERVER_EXE CLIENT_EXE SCL_FILE
set -uo pipefail

server="$1" client="$2" scl="$3"
work="$(mktemp -d)"
pid=""
cleanup() {
  [[ -n "${pid}" ]] && kill -KILL "${pid}" 2> /dev/null
  rm -rf "${work}"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  echo "--- server stderr" >&2
  cat "${work}/server.err" >&2
  exit 1
}

"${server}" --scl "${scl}" --bind 127.0.0.1 --port 0 --password secret --simulate --period 100 \
  --control-delay 50 --verbose > "${work}/server.out" 2> "${work}/server.err" &
pid=$!

port=""
for _ in $(seq 100); do
  port="$(sed -n 's/^listening on 127\.0\.0\.1:\([0-9]*\).*/\1/p' "${work}/server.out")"
  [[ -n "${port}" ]] && break
  kill -0 "${pid}" 2> /dev/null || fail "server exited early"
  sleep 0.05
done
[[ -n "${port}" ]] || fail "server did not print its port"

c() { "${client}" --host 127.0.0.1 --port "${port}" --password secret --timeout 5 "$@"; }
ld=simpleIOGenericIO

out="$(c discover)" || fail "discover"
grep -q "LD ${ld}" <<< "${out}" || fail "discover: no LD"
grep -q "RP EventsRCB01" <<< "${out}" || fail "discover: no URCB"

out="$(c read "${ld}/GGIO1.AnIn1.mag.f[MX]")" || fail "read"
grep -q "AnIn1.mag.f\[MX\] = " <<< "${out}" || fail "read output: ${out}"

c write "${ld}/GGIO1.NamPlt.d[DC]" smoke > /dev/null || fail "write"
out="$(c read "${ld}/GGIO1.NamPlt.d[DC]")" || fail "read back"
grep -q '"smoke"' <<< "${out}" || fail "write not applied: ${out}"

for i in 1 2 3 4; do
  c operate "${ld}/GGIO1.SPCSO${i}" true > /dev/null || fail "operate SPCSO${i}"
  # --control-delay: normal security completes after the Write response, so poll briefly.
  for _ in $(seq 20); do
    out="$(c read "${ld}/GGIO1.SPCSO${i}.stVal[ST]")" || fail "read stVal"
    grep -q "= true" <<< "${out}" && break
    sleep 0.05
  done
  grep -q "= true" <<< "${out}" || fail "stVal did not follow ctlVal: ${out}"
done

out="$(c --count 1 reports "${ld}/LLN0.EventsRCB01[RP]")" || fail "reports"
grep -q "1 report(s) received" <<< "${out}" || fail "reports output: ${out}"

"${client}" --host 127.0.0.1 --port "${port}" --timeout 5 read "${ld}/LLN0.Mod.stVal[ST]" \
  > /dev/null 2>&1 && fail "association without the password was accepted"
c read "${ld}/GGIO1.Nope.stVal[ST]" > /dev/null 2>&1 && fail "read of a missing object succeeded"
"${client}" bogus > /dev/null 2>&1
[[ $? -eq 2 ]] || fail "usage error exit status"

kill -TERM "${pid}"
wait "${pid}"
status=$?
pid=""
[[ ${status} -eq 0 ]] || fail "server exit status ${status} after SIGTERM"
echo "tools smoke test passed (port ${port})"
