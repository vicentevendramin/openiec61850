#!/usr/bin/env bash
# run.sh without Docker (ADR 0007): the same two suites and the same peers, built and run directly
# on this machine, for hosts that cannot run containers:
#   1. runner:  the openiec61850 client against the libiec61850 example servers
#   2. clients: the libiec61850 example clients against the openiec61850-server tool
# Clean-room rule (ADR 0001): libiec61850 is only downloaded, built by its own build system and
# executed. Nothing here reads its sources; when its build fails, work from the build log only.
# Port 102 needs root, so everything listens on the high ports compose.yaml publishes; the example
# servers take the port as their first argument. Exit status: 0 when neither suite has a FAIL.
#
# Needs a C/C++ toolchain, cmake, ninja, curl, VCPKG_ROOT and GNU timeout: run_clients.sh relies on
# its exit status 124, and the uutils timeout (default since Ubuntu 25.10) returns 137 instead, even
# for a command that dies on the signal. Its GNU build is used under the name gnutimeout if present.
#
# Environment: LIBIEC61850_VERSION (default 1.6.0), LIBIEC61850_SHA256, INTEROP_TIMEOUT (s, per
# runner request), CLIENT_TIMEOUT (s, per example client), ONLY=runner|clients to run one suite,
# BASIC_IO_PORT, CONTROL_PORT, OPENIEC61850_PORT, WORK_DIR (default build/interop-native; downloads,
# builds and logs, reused by later runs).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "${here}")"
version="${LIBIEC61850_VERSION:-1.6.0}"
work="${WORK_DIR:-${root}/build/interop-native}"
peer="${work}/libiec61850-${version}"
basic_io_port="${BASIC_IO_PORT:-10102}"
control_port="${CONTROL_PORT:-10103}"
server_port="${OPENIEC61850_PORT:-10104}"
only="${ONLY:-all}"
examples=(server_example_basic_io server_example_control
  iec61850_client_example1 iec61850_client_example2 iec61850_client_example4
  iec61850_client_example_reporting iec61850_client_example_rcbAsync iec61850_client_async
  client_example_control mms_utility)
pids=()

cleanup() {
  if [[ ${#pids[@]} -gt 0 ]]; then
    kill "${pids[@]}" 2> /dev/null || true
    wait "${pids[@]}" 2> /dev/null || true
  fi
}
trap cleanup EXIT

build_peer() {
  [[ -x "${peer}/bin/mms_utility" ]] && return
  local tree="${work}/libiec61850-${version}-build"
  rm -rf "${tree}"
  mkdir -p "${tree}/src" "${peer}/bin" "${peer}/lib"
  curl -fsSL -o "${tree}/libiec61850.tar.gz" \
    "https://github.com/mz-automation/libiec61850/archive/refs/tags/v${version}.tar.gz"
  if [[ -n "${LIBIEC61850_SHA256:-}" ]]; then
    echo "${LIBIEC61850_SHA256}  ${tree}/libiec61850.tar.gz" | sha256sum -c -
  fi
  tar -xzf "${tree}/libiec61850.tar.gz" -C "${tree}/src" --strip-components=1
  cmake -S "${tree}/src" -B "${tree}/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_EXAMPLES=ON > /dev/null
  cmake --build "${tree}/build" --parallel "$(nproc)" > /dev/null
  local name exe
  for name in "${examples[@]}"; do
    exe="$(find "${tree}/build" -type f -perm -u+x -name "${name}" | head -n 1)"
    if [[ -z "${exe}" ]]; then
      echo "example ${name} was not built" >&2
      exit 1
    fi
    cp "${exe}" "${peer}/bin/"
  done
  find "${tree}/build" -name 'lib*.so*' -exec cp -P {} "${peer}/lib/" \;
}

build_ours() {
  cmake -S "${root}" -B "${work}/tools" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DOPENIEC61850_BUILD_TESTS=OFF -DOPENIEC61850_BUILD_TOOLS=ON \
    -DCMAKE_TOOLCHAIN_FILE="${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" > /dev/null
  cmake --build "${work}/tools" --target openiec61850_server_tool > /dev/null
  cmake -S "${here}/runner" -B "${work}/runner" -G Ninja -DCMAKE_BUILD_TYPE=Release > /dev/null
  cmake --build "${work}/runner" > /dev/null
}

# Puts a GNU timeout first in PATH, for run_clients.sh.
use_gnu_timeout() {
  timeout --version | grep -q 'GNU coreutils' && return
  local gnu
  if ! gnu="$(command -v gnutimeout)"; then
    echo "interop: GNU timeout not found (see the header of this script)" >&2
    exit 1
  fi
  mkdir -p "${work}/shims"
  ln -sf "${gnu}" "${work}/shims/timeout"
  export PATH="${work}/shims:${PATH}"
}

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

build_peer
build_ours
use_gnu_timeout
mkdir -p "${work}/logs"
export PATH="${peer}/bin:${PATH}" LD_LIBRARY_PATH="${peer}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

runner_status=skipped
clients_status=skipped
failed=0

if [[ "${only}" == all || "${only}" == runner ]]; then
  echo "== openiec61850 client -> libiec61850 example servers"
  start basic-io "${basic_io_port}" -- server_example_basic_io "${basic_io_port}"
  start control "${control_port}" -- server_example_control "${control_port}"
  status=0
  "${work}/runner/openiec61850_interop" --timeout "${INTEROP_TIMEOUT:-5}" \
    "127.0.0.1:${basic_io_port}" "127.0.0.1:${control_port}" || status=$?
  if [[ ${status} -ne 0 ]]; then
    runner_status="FAIL (exit ${status})"
    failed=1
    echo "interop: runner failed (exit ${status}); server logs in ${work}/logs" >&2
  else
    runner_status=PASS
  fi
fi

if [[ "${only}" == all || "${only}" == clients ]]; then
  echo "== libiec61850 example clients -> openiec61850-server"
  start openiec61850-server "${server_port}" -- "${work}/tools/tools/openiec61850-server" \
    --scl "${here}/server/simpleIO.icd" --port "${server_port}" --bind 127.0.0.1 --simulate --verbose
  status=0
  LOG_DIR="${work}/logs/clients" "${here}/clients/run_clients.sh" --timeout "${CLIENT_TIMEOUT:-8}" \
    127.0.0.1 "${server_port}" || status=$?
  if [[ ${status} -ne 0 ]]; then
    clients_status="FAIL (exit ${status})"
    failed=1
    echo "interop: example clients failed (exit ${status}); server log in ${work}/logs" >&2
  else
    clients_status=PASS
  fi
fi

echo
echo "Interop summary:"
echo "  openiec61850 client  -> libiec61850 servers: ${runner_status}"
echo "  libiec61850 clients  -> openiec61850-server: ${clients_status}"
exit "${failed}"
