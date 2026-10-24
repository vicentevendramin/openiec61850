#!/usr/bin/env bash
# Builds the libiec61850 example servers and the openiec61850 interop runner, runs the runner
# against every server and tears everything down. Exit status: the runner's (0 = no FAIL).
#
# Environment: LIBIEC61850_VERSION (default 1.6.0), LIBIEC61850_SHA256, INTEROP_TIMEOUT (s),
# KEEP_UP=1 to leave the servers running afterwards (published on 127.0.0.1:10102 / :10103).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose=(docker compose -f "${here}/compose.yaml")

cleanup() {
  if [[ "${KEEP_UP:-0}" != "1" ]]; then
    "${compose[@]}" down --remove-orphans --volumes > /dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

"${compose[@]}" build
"${compose[@]}" up --detach --wait basic-io control
status=0
"${compose[@]}" run --rm runner || status=$?
if [[ "${status}" -ne 0 ]]; then
  echo "interop: runner failed (exit ${status}); server logs follow" >&2
  "${compose[@]}" logs --no-color basic-io control >&2 || true
fi
exit "${status}"
