#!/usr/bin/env bash
# Benchmark de referência (GLOSSARY, ADR 0008): openiec61850 against libiec61850 on this machine,
# over TCP loopback, without Docker or sudo. Method and limits: docs/guides/contributing.md.
#
# Clean-room rule (ADR 0001): libiec61850 is only downloaded, built by its own build system and
# executed through the command line and output of its prebuilt examples. Nothing here reads its
# sources or headers, and nothing is compiled against its API.
#
# Needs a C/C++ toolchain, cmake, ninja, curl, python3, taskset and VCPKG_ROOT.
#
# Environment: LIBIEC61850_VERSION (default 1.6.0), LIBIEC61850_SHA256, WORK_DIR (default
# build/reference; downloads, builds and results, reused by later runs), OUT (results directory,
# default WORK_DIR/results). Arguments go to harness.py (--rounds, --duration, --only...).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "${here}/../.." && pwd)"
version="${LIBIEC61850_VERSION:-1.6.0}"
work="${WORK_DIR:-${root}/build/reference}"
peer="${work}/libiec61850-${version}"
out="${OUT:-${work}/results}"
# The same optimisation flags on both sides, stated instead of inherited from either build system.
release_flags="-O3 -DNDEBUG"
examples=(server_example_basic_io iec61850_client_example2 iec61850_client_example4 mms_utility)

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
  sha256sum "${tree}/libiec61850.tar.gz" | cut -d' ' -f1 > "${peer}/source.sha256"
  tar -xzf "${tree}/libiec61850.tar.gz" -C "${tree}/src" --strip-components=1
  cmake -S "${tree}/src" -B "${tree}/build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS_RELEASE="${release_flags}" -DCMAKE_CXX_FLAGS_RELEASE="${release_flags}" \
    -DBUILD_EXAMPLES=ON > /dev/null
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
  # Only the executables are needed: drop the sources so later debugging cannot wander into them.
  rm -rf "${tree}"
}

build_ours() {
  cmake -S "${here}" -B "${work}/ours" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_FLAGS_RELEASE="${release_flags}" \
    -DCMAKE_TOOLCHAIN_FILE="${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" > /dev/null
  cmake --build "${work}/ours" --target reference > /dev/null
}

mkdir -p "${work}" "${out}"
build_peer
build_ours
LD_LIBRARY_PATH="${peer}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" exec python3 "${here}/harness.py" \
  --peer-bin "${peer}/bin" --peer-version "${version}" --ours-bin "${work}/ours" \
  --icd "${root}/interop/server/simpleIO.icd" --out "${out}" --flags "${release_flags}" "$@"
