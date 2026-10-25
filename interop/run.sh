#!/usr/bin/env bash
# Interop with libiec61850 in both directions (ADR 0007):
#   1. runner:  the openiec61850 client against the libiec61850 example servers
#   2. clients: the libiec61850 example clients against the openiec61850-server tool
# Builds everything, runs both suites, prints a summary and tears everything down.
# Exit status: 0 when neither suite has a FAIL.
#
# Environment: LIBIEC61850_VERSION (default 1.6.0), LIBIEC61850_SHA256, INTEROP_TIMEOUT (s, per
# runner request), CLIENT_TIMEOUT (s, per example client), ONLY=runner|clients to run one suite,
# KEEP_UP=1 to leave the servers running afterwards (published on 127.0.0.1:10102 / :10103 for
# libiec61850, :10104 for openiec61850-server).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose=(docker compose -f "${here}/compose.yaml")
only="${ONLY:-all}"

cleanup() {
  if [[ "${KEEP_UP:-0}" != "1" ]]; then
    "${compose[@]}" down --remove-orphans --volumes > /dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# The clients image is built FROM the libiec61850 one (additional_contexts).
"${compose[@]}" build

runner_status=skipped
clients_status=skipped
failed=0

if [[ "${only}" == all || "${only}" == runner ]]; then
  echo "== openiec61850 client -> libiec61850 example servers"
  "${compose[@]}" up --detach --wait basic-io control
  status=0
  "${compose[@]}" run --rm runner || status=$?
  if [[ ${status} -ne 0 ]]; then
    runner_status="FAIL (exit ${status})"
    failed=1
    echo "interop: runner failed (exit ${status}); server logs follow" >&2
    "${compose[@]}" logs --no-color basic-io control >&2 || true
  else
    runner_status=PASS
  fi
fi

if [[ "${only}" == all || "${only}" == clients ]]; then
  echo "== libiec61850 example clients -> openiec61850-server"
  "${compose[@]}" up --detach --wait openiec61850-server
  status=0
  "${compose[@]}" run --rm clients || status=$?
  if [[ ${status} -ne 0 ]]; then
    clients_status="FAIL (exit ${status})"
    failed=1
    echo "interop: example clients failed (exit ${status}); server log follows" >&2
    "${compose[@]}" logs --no-color openiec61850-server >&2 || true
  else
    clients_status=PASS
  fi
fi

echo
echo "Interop summary:"
echo "  openiec61850 client  -> libiec61850 servers: ${runner_status}"
echo "  libiec61850 clients  -> openiec61850-server: ${clients_status}"
exit "${failed}"
