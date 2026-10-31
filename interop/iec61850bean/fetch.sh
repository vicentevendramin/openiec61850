#!/usr/bin/env bash
# Downloads the IEC61850bean jars from Maven Central into DIR and, with --jdk JDK_DIR, a Temurin JDK
# for hosts without one. Every file is pinned by SHA-256 and the run stops on a mismatch.
#
#   fetch.sh [--jdk JDK_DIR] DIR
#
# Clean-room (ADR 0001): only the binary jars are fetched. Never add a -sources jar, and never read
# the IEC61850bean sources, not even to work out why a test fails.
set -euo pipefail

maven=https://repo1.maven.org/maven2
temurin=https://github.com/adoptium/temurin21-binaries/releases/download
jdk_file="jdk-21.0.13%2B9/OpenJDK21U-jdk_x64_linux_hotspot_21.0.13_9.tar.gz"
jdk_sha256=d7f5d5cf865a2902b70ff549b97586a7d3f234e016f041ab447ea740c7d66d1c

# Maven path, then SHA-256. The runtime dependencies are the ones in the iec61850bean 1.9.0 POM.
jars=(
  com/beanit/iec61850bean/1.9.0/iec61850bean-1.9.0.jar
  df114f512c4f9855ac977e52d204eb954d6e4f68842ac00f28ce9a678e879bcb
  com/beanit/asn1bean/1.12.0/asn1bean-1.12.0.jar
  9fa33202dcf1d00f84f289000b0f937aa910b74f771976a625fd638b6f270878
  org/slf4j/slf4j-api/1.7.25/slf4j-api-1.7.25.jar
  18c4a0095d5c1da6b817592e767bb23d29dd2f560ad74df75ff3961dbde25b79
  ch/qos/logback/logback-classic/1.2.3/logback-classic-1.2.3.jar
  fb53f8539e7fcb8f093a56e138112056ec1dc809ebb020b59d8a36a5ebac37e0
  ch/qos/logback/logback-core/1.2.3/logback-core-1.2.3.jar
  5946d837fe6f960c02a53eda7a6926ecc3c758bbdd69aa453ee429f858217f22
)

jdk_dir=""
if [[ "${1:-}" == --jdk ]]; then
  jdk_dir="$2"
  shift 2
fi
[[ $# -eq 1 ]] || { echo "usage: $0 [--jdk JDK_DIR] DIR" >&2; exit 2; }
dir="$1"
mkdir -p "${dir}"

# fetch URL FILE SHA256: leaves FILE in place only when it matches.
fetch() {
  if [[ -f "$2" ]] && echo "$3  $2" | sha256sum -c --status -; then return; fi
  curl -fsSL -o "$2.part" "$1"
  echo "$3  $2.part" | sha256sum -c --status - || {
    echo "checksum mismatch for $1" >&2
    rm -f "$2.part"
    exit 1
  }
  mv "$2.part" "$2"
}

for ((i = 0; i < ${#jars[@]}; i += 2)); do
  fetch "${maven}/${jars[i]}" "${dir}/$(basename "${jars[i]}")" "${jars[i + 1]}"
done

if [[ -n "${jdk_dir}" && ! -x "${jdk_dir}/bin/java" ]]; then
  [[ "$(uname -m)" == x86_64 ]] || { echo "no pinned JDK for $(uname -m); set JAVA" >&2; exit 1; }
  mkdir -p "${jdk_dir}"
  fetch "${temurin}/${jdk_file}" "${jdk_dir}/jdk.tar.gz" "${jdk_sha256}"
  tar -xzf "${jdk_dir}/jdk.tar.gz" -C "${jdk_dir}" --strip-components=1
  rm -f "${jdk_dir}/jdk.tar.gz"
fi
