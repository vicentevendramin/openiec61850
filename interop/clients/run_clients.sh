#!/usr/bin/env bash
# Reverse interop (ADR 0007): runs the libiec61850 example clients against an IEC 61850 server
# (normally openiec61850-server serving interop/server/simpleIO.icd) and turns their exit status
# and output into PASS / FAIL lines plus a summary.
#
#   run_clients.sh [--timeout SECONDS] HOST [PORT]
#
# Runs inside the libiec61850 image (interop/libiec61850/Dockerfile), which holds the example
# executables. Clean-room (ADR 0001): the expectations below come only from running those
# executables (their command line and printed output, also against the libiec61850 example
# servers as a reference), never from their sources. Clients that run until interrupted get
# SIGINT after the timeout; for them the output decides.
#
# Exit status: 0 when nothing FAILed, 1 otherwise, 2 on usage errors.
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

pass=0
fail=0

# check NAME EXPECTED_EXIT(any|0|...) -- command...   then the patterns as "count:regex" lines
# on stdin: each regex must match at least `count` output lines.
check() {
  local name="$1" expect="$2"
  shift 3
  local out="${logs}/${name//[^A-Za-z0-9_.-]/_}.log"
  timeout -s INT -k 5 "${timeout_s}" stdbuf -oL -eL "$@" > "${out}" 2>&1
  local status=$?
  local problems=()
  if [[ "${expect}" == "0" && ${status} -ne 0 ]]; then
    problems+=("exit status ${status}")
  elif [[ "${expect}" == "interrupted" && ${status} -ne 0 && ${status} -ne 124 ]]; then
    problems+=("exit status ${status}")
  fi
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    local count="${line%%:*}" regex="${line#*:}"
    local got
    got=$(grep -cE -- "${regex}" "${out}")
    if [[ ${got} -lt ${count} ]]; then
      problems+=("expected ${count}x /${regex}/, got ${got}")
    fi
  done
  if [[ ${#problems[@]} -eq 0 ]]; then
    printf '[%s] %-34s PASS exit %d\n' "${target}" "${name}" "${status}"
    pass=$((pass + 1))
  else
    printf '[%s] %-34s FAIL %s\n' "${target}" "${name}" "$(IFS=';'; echo "${problems[*]}")"
    sed 's/^/    | /' "${out}" | head -n 40
    fail=$((fail + 1))
  fi
}

# MMS-level utility: identify, domain list, domain directory, read of a whole LN.
check mms_utility/identify 0 -- mms_utility -h "${host}" -p "${port}" -i <<'EOF'
1:Server identity
1:vendor:
EOF
check mms_utility/domains 0 -- mms_utility -h "${host}" -p "${port}" -d <<EOF
1:^${ld}\$
EOF
check mms_utility/directory 0 -- mms_utility -h "${host}" -p "${port}" -t "${ld}" <<'EOF'
1:^  GGIO1\$MX\$AnIn1\$mag\$f$
1:^  LLN0\$RP\$EventsRCB01$
1:^  LLN0\$BR\$Measurements01$
EOF
check mms_utility/read 0 -- mms_utility -h "${host}" -p "${port}" -a "${ld}" -r 'GGIO1$MX$AnIn1$mag$f' <<'EOF'
1:Read SUCCESS
EOF

# ACSI directory services: logical devices, nodes, data objects, data sets, RCBs.
check client_example2/discovery 0 -- iec61850_client_example2 "${host}" "${port}" <<EOF
1:^LD: ${ld}\$
3:^  LN: (GGIO1|LLN0|LPHD1)\$
1:^    DO: SPCSO1\$
1:^    Data set: Events \(not deletable\)\$
4:^      ${ld}/GGIO1\.SPCSO[1-4]\.stVal\[ST\]\$
1:^    RP: EventsRCB01\$
1:^    BR: Measurements01\$
EOF

# Read of the data set Measurements (four AnIn mag.f values).
check client_example4/dataset 0 -- iec61850_client_example4 "${host}" "${port}" <<'EOF'
4:^  GGIO1\.AnIn[0-9]\.mag\.f: -?[0-9]
EOF

# Read, URCB EventsRCB01 enabled with GI, reports received.
check client_example1/read+report interrupted -- iec61850_client_example1 "${host}" "${port}" <<'EOF'
1:^Connected$
1:^read float value: -?[0-9]
1:^received report for
4:stVal: [01] \(included for reason
EOF

# Reporting: URCB with RptID Events1, reports with timestamps and member references.
check client_example_reporting/reports interrupted -- iec61850_client_example_reporting "${host}" "${port}" <<EOF
1:^received report for .* with rptId Events1\$
4:^  ${ld}/GGIO1\.SPCSO[1-4]\.stVal\[ST\] \(included for reason [0-9]+\): (true|false)\$
EOF

# Asynchronous API: reads, data set values, RCB values.
check client_example_rcbAsync/rcb interrupted -- iec61850_client_example_rcbAsync "${host}" "${port}" <<EOF
1:^${ld}/GGIO1\.AnIn2\.mag\.f: -?[0-9]
1:^Data set has 4 entries\$
1:^RptEna = [01]\$
1:^RptID = Events1\$
EOF
check client_async/services 0 -- iec61850_client_async "${host}" "${port}" <<EOF
1:^LD: ${ld} variables:\$
1:^  ${ld}/GGIO1\\\$MX\\\$AnIn1\\\$mag\\\$f\$
1:^${ld}/GGIO1\.AnIn1\.mag\.f: -?[0-9]
1:^Data set has 4 entries\$
1:^control: .* success: 1\$
EOF

# Control: direct / SBO with normal and enhanced security, CommandTermination+.
check client_example_control/control 0 -- client_example_control "${host}" "${port}" <<EOF
1:^${ld}/GGIO1\.SPCSO1 operated successfully\$
1:^New status of ${ld}/GGIO1\.SPCSO1\.stVal: 1\$
1:^${ld}/GGIO1\.SPCSO2 operated successfully\$
1:^${ld}/GGIO1\.SPCSO3 operated successfully\$
1:^${ld}/GGIO1\.SPCSO4 operated successfully\$
1:^${ld}/GGIO1\.SPCSO9 operated successfully\$
3:^Received CommandTermination\+\.\$
EOF

echo
echo "Summary (libiec61850 clients -> ${target}): ${pass} PASS, ${fail} FAIL (logs in ${logs})"
[[ ${fail} -eq 0 ]]
