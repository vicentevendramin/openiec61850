#!/usr/bin/env bash
# The IEC61850bean console server, serving MODEL on PORT.
#
#   server.sh MODEL PORT
#
# The application reads actions from stdin and spins on end of input, so stdin stays open. Its only
# way of changing a value is the console's "w" action, and it has no process behind its control
# objects, so a member of the data set Events (stVal of SPCSO4, which nothing else touches) is toggled
# through that action every second: this is what lets interop_runner see a data-change report.
#
# Environment: BEAN_LIB (directory of the jars), JAVA (default java), TOGGLE_REF (data attribute to
# toggle), LOG_DIR (default: a temporary directory).
set -euo pipefail

[[ $# -eq 2 ]] || { echo "usage: $0 MODEL PORT" >&2; exit 2; }
ref="${TOGGLE_REF:-simpleIOGenericIO/GGIO1.SPCSO4.stVal}"
dir="$(mktemp -d)"
fifo="${dir}/stdin"
mkfifo "${fifo}"
"${JAVA:-java}" -cp "${BEAN_LIB}/*" com.beanit.iec61850bean.app.ConsoleServer -m "$1" -p "$2" < "${fifo}" &
server=$!
trap 'kill "${server}" 2> /dev/null || true; rm -rf "${dir}"' EXIT TERM INT
exec 3> "${fifo}"
value=true
while kill -0 "${server}" 2> /dev/null; do
  printf 'w\n%s\nST\n%s\n' "${ref}" "${value}" >&3
  [[ "${value}" == true ]] && value=false || value=true
  sleep 1
done
wait "${server}"
