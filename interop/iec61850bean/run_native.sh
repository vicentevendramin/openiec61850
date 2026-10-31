#!/usr/bin/env bash
# Interop with IEC61850bean without Docker (ADR 0007), in both directions:
#   1. server: the openiec61850 client (interop/runner) against the bean console server
#   2. client: the bean console client against the openiec61850-server tool
# Clean-room (ADR 0001): IEC61850bean is only downloaded as binary jars and executed.
# Exit status: 0 when neither suite has a FAIL.
#
# Needs a C++ toolchain, cmake, ninja, curl, VCPKG_ROOT, and java or a download of the pinned JDK.
#
# Environment: JAVA (default: java from PATH, else a JDK downloaded into WORK_DIR), INTEROP_TIMEOUT
# (s, per runner request), CLIENT_TIMEOUT (s, per console prompt), ONLY=server|client to run one
# direction, BEAN_PORT, OPENIEC61850_PORT, WORK_DIR (default build/interop-native; downloads, builds
# and logs, reused by later runs).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
interop="$(dirname "${here}")"
root="$(dirname "${interop}")"
work="${WORK_DIR:-${root}/build/interop-native}"
bean_port="${BEAN_PORT:-10105}"
server_port="${OPENIEC61850_PORT:-10104}"
only="${ONLY:-all}"
pids=()

cleanup() {
  if [[ ${#pids[@]} -gt 0 ]]; then
    kill "${pids[@]}" 2> /dev/null || true
    wait "${pids[@]}" 2> /dev/null || true
  fi
}
trap cleanup EXIT

export BEAN_LIB="${work}/iec61850bean"
if [[ -z "${JAVA:-}" ]] && command -v java > /dev/null; then
  JAVA="$(command -v java)"
fi
if [[ -z "${JAVA:-}" ]]; then
  "${here}/fetch.sh" --jdk "${work}/jdk" "${BEAN_LIB}"
  JAVA="${work}/jdk/bin/java"
else
  "${here}/fetch.sh" "${BEAN_LIB}"
fi
export JAVA

cmake -S "${root}" -B "${work}/tools" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DOPENIEC61850_BUILD_TESTS=OFF -DOPENIEC61850_BUILD_TOOLS=ON \
  -DCMAKE_TOOLCHAIN_FILE="${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" > /dev/null
cmake --build "${work}/tools" --target openiec61850_server_tool > /dev/null
cmake -S "${interop}/runner" -B "${work}/runner" -G Ninja -DCMAKE_BUILD_TYPE=Release > /dev/null
cmake --build "${work}/runner" > /dev/null
mkdir -p "${work}/logs"

# start NAME PORT -- command...: runs a server in the background, waits until it accepts.
start() {
  local name="$1" port="$2"
  shift 3
  "$@" > "${work}/logs/${name}.log" 2>&1 &
  pids+=("$!")
  local i
  for i in {1..60}; do
    if (exec 3<> "/dev/tcp/127.0.0.1/${port}") 2> /dev/null; then return; fi
    sleep 0.5
  done
  echo "interop: ${name} is not listening on ${port}" >&2
  cat "${work}/logs/${name}.log" >&2
  exit 1
}

server_status=skipped
client_status=skipped
failed=0

if [[ "${only}" == all || "${only}" == server ]]; then
  echo "== openiec61850 client -> IEC61850bean console server"
  start bean-server "${bean_port}" -- "${here}/server.sh" "${interop}/server/simpleIO.icd" "${bean_port}"
  status=0
  "${work}/runner/openiec61850_interop" --timeout "${INTEROP_TIMEOUT:-5}" --expect-dchg --bean-defects \
    "127.0.0.1:${bean_port}" || status=$?
  if [[ ${status} -ne 0 ]]; then
    server_status="FAIL (exit ${status})"
    failed=1
    echo "interop: runner failed (exit ${status}); server log in ${work}/logs" >&2
  else
    server_status=PASS
  fi
fi

if [[ "${only}" == all || "${only}" == client ]]; then
  echo "== IEC61850bean console client -> openiec61850-server"
  start openiec61850-server "${server_port}" -- "${work}/tools/tools/openiec61850-server" \
    --scl "${interop}/server/simpleIO.icd" --port "${server_port}" --bind 127.0.0.1 --simulate --verbose
  status=0
  LOG_DIR="${work}/logs/bean-client" "${here}/run_client.sh" --timeout "${CLIENT_TIMEOUT:-8}" \
    127.0.0.1 "${server_port}" || status=$?
  if [[ ${status} -ne 0 ]]; then
    client_status="FAIL (exit ${status})"
    failed=1
    echo "interop: bean client failed (exit ${status}); logs in ${work}/logs" >&2
  else
    client_status=PASS
  fi
fi

echo
echo "Interop summary:"
echo "  openiec61850 client  -> IEC61850bean server: ${server_status}"
echo "  IEC61850bean client  -> openiec61850-server: ${client_status}"
exit "${failed}"
