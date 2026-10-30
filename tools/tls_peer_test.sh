#!/usr/bin/env bash
# CTest of the TLS layer against an independent implementation, the openssl command: s_client
# against openiec61850-server and s_server as the listener of openiec61850-client. The PKI (root,
# intermediate, leaves, CRL) is made here with short lifetimes, so no key lives in the repository.
# Exits 77 (CTest SKIP_RETURN_CODE) when the openssl command is absent.
#
#   tls_peer_test.sh SERVER_EXE CLIENT_EXE SCL_FILE
set -uo pipefail
export LC_ALL=C  # the logs hold binary data

command -v openssl > /dev/null || { echo "openssl command not found"; exit 77; }

server="$1" client="$2" scl="$3"
work="$(mktemp -d)"
pid=""
stop_pid() {
  [[ -n "${pid}" ]] && kill -KILL "${pid}" 2> /dev/null && wait "${pid}" 2> /dev/null
  pid=""
}
cleanup() {
  stop_pid
  rm -rf "${work}"
}
trap cleanup EXIT

last_log=/dev/null
fail() {
  echo "FAIL: $*" >&2
  echo "--- last peer output" >&2
  cat "${last_log}" >&2
  exit 1
}

# --- PKI ---------------------------------------------------------------------------------------

export OPENSSL_CONF="${work}/ca.cnf"
cat > "${OPENSSL_CONF}" << EOF
[ca]
default_ca = root
[root]
dir = ${work}/root
database = \$dir/index.txt
new_certs_dir = \$dir
serial = \$dir/serial
crlnumber = \$dir/crlnumber
certificate = \$dir/ca.pem
private_key = \$dir/ca.key
default_md = sha256
default_days = 1
default_crl_days = 1
policy = names
unique_subject = no
[inter]
dir = ${work}/inter
database = \$dir/index.txt
new_certs_dir = \$dir
serial = \$dir/serial
crlnumber = \$dir/crlnumber
certificate = \$dir/ca.pem
private_key = \$dir/ca.key
default_md = sha256
default_days = 1
default_crl_days = 1
policy = names
unique_subject = no
[names]
commonName = supplied
[req]
distinguished_name = dn
[dn]
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[v3_leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = \${ENV::SAN}
EOF
export SAN="IP:127.0.0.1"

newkey() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2> /dev/null; }

selfsigned() {  # NAME CN
  newkey "${work}/$1.key" && openssl req -x509 -new -key "${work}/$1.key" -subj "/CN=$2" -days 1 \
    -extensions v3_ca -out "${work}/$1.pem" 2> /dev/null
}

# issue CA NAME CN [extra arguments of openssl ca]: leaf (or CA) NAME.pem and NAME.key. SAN is the
# subject alternative name of a leaf.
issue() {
  local ca="$1" name="$2" cn="$3" ext=v3_leaf
  shift 3
  [[ "${name}" == inter ]] && ext=v3_ca
  newkey "${work}/${name}.key" || return 1
  openssl req -new -key "${work}/${name}.key" -subj "/CN=${cn}" -out "${work}/${name}.csr" 2> /dev/null \
    || return 1
  openssl ca -batch -notext -name "${ca}" -extensions "${ext}" -in "${work}/${name}.csr" \
    -out "${work}/${name}.pem" "$@" 2> /dev/null
}

for ca in root inter; do
  mkdir "${work}/${ca}"
  : > "${work}/${ca}/index.txt"
  echo 1000 > "${work}/${ca}/serial"
  echo 1000 > "${work}/${ca}/crlnumber"
done

selfsigned root "openiec61850 test root" || fail "root CA"
cp "${work}/root.pem" "${work}/root/ca.pem"
cp "${work}/root.key" "${work}/root/ca.key"
issue root inter "openiec61850 test intermediate" || fail "intermediate CA"
cp "${work}/inter.pem" "${work}/inter/ca.pem"
cp "${work}/inter.key" "${work}/inter/ca.key"
selfsigned rogue "rogue root" || fail "rogue CA"

issue inter srv "server" || fail "server certificate"
issue inter cli "client" || fail "client certificate"
issue inter revoked "revoked" || fail "revoked certificate"
issue inter expired "expired" -startdate 20200101000000Z -enddate 20200102000000Z || fail "expired certificate"
SAN="IP:192.0.2.1,DNS:other.example" issue inter other "other" || fail "other certificate"
SAN="DNS:ied.example" issue inter named "named" || fail "named certificate"
SAN="DNS:localhost" issue inter localhost "localhost" || fail "localhost certificate"
for name in srv cli revoked expired other named localhost; do
  cat "${work}/${name}.pem" "${work}/inter.pem" > "${work}/${name}.chain.pem"
done

# A certificate that looks the same as the good client's but comes from another CA.
newkey "${work}/forged.key" || fail "forged key"
openssl req -x509 -new -key "${work}/forged.key" -subj "/CN=client" -days 1 \
  -CA "${work}/rogue.pem" -CAkey "${work}/rogue.key" -extensions v3_leaf -out "${work}/forged.pem" \
  2> /dev/null || fail "forged certificate"

openssl ca -name inter -revoke "${work}/revoked.pem" 2> /dev/null || fail "revoke"
openssl ca -name inter -gencrl -out "${work}/inter.crl" 2> /dev/null || fail "CRL"

tls1_1=""
openssl s_client -help 2>&1 | grep -q -- '-tls1_1' && tls1_1=yes

# --- openssl s_client against openiec61850-server ----------------------------------------------

log="${work}/s_client.log"

start_server() {
  : > "${work}/server.out"
  "${server}" --scl "${scl}" --bind 127.0.0.1 --port 0 --tls --tls-ca "${work}/root.pem" \
    --tls-cert "${work}/srv.chain.pem" --tls-key "${work}/srv.key" "$@" \
    > "${work}/server.out" 2> "${work}/server.err" &
  pid=$!
  port=""
  for _ in $(seq 100); do
    port="$(sed -n 's/^listening on 127\.0\.0\.1:\([0-9]*\).*/\1/p' "${work}/server.out")"
    [[ -n "${port}" ]] && break
    kill -0 "${pid}" 2> /dev/null || { last_log="${work}/server.err"; fail "server exited early"; }
    sleep 0.05
  done
  [[ -n "${port}" ]] || fail "server did not print its port"
}

stop_server() {
  kill -TERM "${pid}"
  wait "${pid}"
  local status=$?
  pid=""
  last_log="${work}/server.err"
  [[ ${status} -eq 0 ]] || fail "server exit status ${status} after SIGTERM"
}

# A COTP connection request (ISO 8073 §13.3, TPDU size 1024, TSAPs 0001) inside TPKT (RFC 1006).
send_cr() {
  printf '\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x00\x01\xc2\x02\x00\x01'
  sleep 0.5  # s_client quits at the end of its input: leave time for the answer
}

# Connects, sends the CR and keeps the whole output in ${log}. The exit status is s_client's.
s_client() {
  last_log="${log}"
  send_cr | timeout 10 openssl s_client -connect "127.0.0.1:${port}" -CAfile "${work}/root.pem" \
    -verify_return_error -verify_ip 127.0.0.1 "$@" > "${log}" 2>&1
}

has() { grep -aq -- "$1" "${log}"; }
# True when the output carries a COTP connection confirm: the channel works past the handshake.
has_cc() { od -An -v -tx1 "${log}" | tr -d ' \n' | grep -Eq '030000[0-9a-f]{4}d0'; }

accepted() {  # WHAT VERSION [s_client arguments]
  local what="$1" version="$2"
  shift 2
  s_client "$@" || fail "${what}: s_client failed"
  has "Protocol *: *${version}\|New, ${version}" || fail "${what}: not ${version}"
  has "Verify return code: 0 (ok)" || fail "${what}: server certificate not verified"
  has_cc || fail "${what}: no COTP connection confirm over TLS"
}

refused() {  # WHAT [s_client arguments]
  local what="$1"
  shift
  s_client "$@"
  has_cc && fail "${what}: the server answered"
}

# s_client arguments that present NAME with its intermediate. The scratch path has no spaces.
chained() { echo -cert "${work}/$1.pem" -key "${work}/$1.key" -cert_chain "${work}/inter.pem"; }
good=($(chained cli))

start_server
accepted "TLS 1.3" TLSv1.3 -tls1_3 "${good[@]}"
accepted "TLS 1.2" TLSv1.2 -tls1_2 "${good[@]}"
accepted "TLS 1.2 AEAD" TLSv1.2 -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256 "${good[@]}"
has "ECDHE-ECDSA-AES128-GCM-SHA256" || fail "TLS 1.2 cipher not negotiated"
has "Peer signing digest\|Peer signature type" || fail "no peer signature reported"
has "Verification: OK" || fail "s_client did not report a verified server"

has "Compression: NONE" || fail "TLS compression negotiated"

# Sessions are never resumed, so every connection goes through the certificate checks.
last_log="${log}"
send_cr | timeout 10 openssl s_client -connect "127.0.0.1:${port}" -CAfile "${work}/root.pem" \
  -tls1_2 -reconnect "${good[@]}" > "${log}" 2>&1
has "New, TLSv1.2" || fail "reconnect: no handshake"
has "^Reused," && fail "TLS 1.2 session resumed"
s_client -tls1_3 "${good[@]}"
has "Post-Handshake New Session Ticket\|NewSessionTicket" && fail "TLS 1.3 session ticket issued"

# An idle TCP connection must not hold up the handshake of the next client.
exec 3<> "/dev/tcp/127.0.0.1/${port}" || fail "idle connection"
accepted "TLS next to an idle connection" TLSv1.3 -tls1_3 "${good[@]}"
exec 3<&- 3>&-

# Unauthenticated and unencrypted suites stay off whatever the peer offers.
for ciphers in 'aNULL:@SECLEVEL=0' 'eNULL:@SECLEVEL=0'; do
  refused "cipher ${ciphers}" -tls1_2 -cipher "${ciphers}" "${good[@]}"
  has "Cipher is (NONE)\|alert handshake failure\|no shared cipher\|no ciphers available" \
    || fail "cipher ${ciphers}: unexpected failure"
done

# The checks above trust only the root, so they need the intermediate that --tls-cert carries.
# Here s_client trusts another root, then expects another address.
last_log="${log}"
send_cr | timeout 10 openssl s_client -connect "127.0.0.1:${port}" -CAfile "${work}/rogue.pem" \
  -verify_return_error "${good[@]}" > "${log}" 2>&1 && fail "untrusted server certificate accepted"
s_client -verify_ip 192.0.2.1 "${good[@]}" && fail "server certificate accepted for a wrong address"

# In TLS 1.2 a client without a certificate fails its own handshake. In TLS 1.3 the client finishes
# first, so the refusal arrives as an alert and no COTP byte may follow.
refused "no client certificate, TLS 1.2" -tls1_2
has "alert handshake failure\|peer did not return a certificate" \
  || fail "no client certificate, TLS 1.2: unexpected failure"
refused "no client certificate, TLS 1.3" -tls1_3
has "alert certificate required" || fail "no client certificate, TLS 1.3: unexpected failure"
refused "client certificate of an unknown CA, TLS 1.2" -tls1_2 -cert "${work}/forged.pem" \
  -key "${work}/forged.key"
has "alert unknown ca" || fail "unknown CA, TLS 1.2: unexpected failure"
refused "client certificate of an unknown CA, TLS 1.3" -tls1_3 -cert "${work}/forged.pem" \
  -key "${work}/forged.key"
has "alert unknown ca" || fail "unknown CA, TLS 1.3: unexpected failure"
refused "client certificate without its chain" -tls1_2 -cert "${work}/cli.pem" -key "${work}/cli.key"
refused "expired client certificate" -tls1_2 $(chained expired)
has "alert certificate expired" || fail "expired client: unexpected failure"

# A peer offering only versions below the minimum (SECLEVEL=0 lets s_client send them).
if [[ -n "${tls1_1}" ]]; then
  refused "TLS 1.1" -tls1_1 -cipher 'ALL:@SECLEVEL=0' "${good[@]}"
  has "alert protocol version\|unsupported protocol\|wrong version\|no protocols available" \
    || fail "TLS 1.1: unexpected failure"
fi

# Plain RFC 1006 on the TLS port must get nothing back.
last_log="${log}"
exec 3<> "/dev/tcp/127.0.0.1/${port}" || fail "plain connection"
send_cr >&3
timeout 2 cat <&3 > "${log}"
exec 3<&- 3>&-
has_cc && fail "plain COTP was answered on the TLS port"
stop_server

start_server --tls-crl "${work}/inter.crl"
accepted "good client with a CRL" TLSv1.3 -tls1_3 "${good[@]}"
refused "revoked client certificate" -tls1_2 $(chained revoked)
has "alert certificate revoked" || fail "revoked client: unexpected failure"
stop_server

# --tls-peer-name on a server restricts which verified clients get in.
start_server --tls-peer-name ied.example
refused "client without the required name" -tls1_2 "${good[@]}"
accepted "client with the required name" TLSv1.2 -tls1_2 $(chained named)
stop_server

# With --tls-no-verify the server asks for nothing.
start_server --tls-no-verify
accepted "server without client authentication" TLSv1.3 -tls1_3
stop_server

# --- openiec61850-client against openssl s_server ----------------------------------------------

log="${work}/s_server.log"
clog="${work}/client.log"
# s_server stops at the end of its input: a FIFO held open here never ends.
mkfifo "${work}/stdin"
exec 4<> "${work}/stdin"

# start_s_server LEAF[.chain] [s_server arguments]: one connection on an ephemeral port; .chain
# also sends the intermediate.
start_s_server() {
  local leaf="${1%.chain}" chain=()
  [[ "$1" == *.chain ]] && chain=(-cert_chain "${work}/inter.pem")
  shift
  : > "${log}"
  last_log="${log}"
  openssl s_server -accept 127.0.0.1:0 -naccept 1 -cert "${work}/${leaf}.pem" \
    -key "${work}/${leaf}.key" "${chain[@]}" "$@" > "${log}" 2>&1 <&4 &
  pid=$!
  port=""
  for _ in $(seq 100); do
    port="$(sed -n 's/^ACCEPT .*:\([0-9]*\)$/\1/p' "${log}")"
    [[ -n "${port}" ]] && break
    kill -0 "${pid}" 2> /dev/null || fail "s_server exited early"
    sleep 0.05
  done
  [[ -n "${port}" ]] || fail "s_server did not print its port"
}

own=(--tls-cert "${work}/cli.chain.pem" --tls-key "${work}/cli.key")

# Runs the client. s_server speaks no COTP, so getting past TLS means waiting for the connection
# confirm until --timeout; a TLS failure ends sooner, with an error of its own. s_server ends when
# the client goes.
run_client() {
  "${client}" --host 127.0.0.1 --port "${port}" --timeout 1 --tls "$@" read "LD/LLN0.Mod.stVal[ST]" \
    > "${clog}" 2>&1
  local status=$?
  wait "${pid}" 2> /dev/null
  pid=""
  cat "${clog}" >> "${log}"
  return ${status}
}

# The COTP request arriving at s_server proves that the client finished its handshake and trusted
# the peer: it sends nothing before that. s_server shows received data verbatim.
tls_up() { grep -aq "CIPHER is\|Cipher is" "${log}" && grep -aq "$(printf '\xe0')" "${log}"; }

passes() {  # WHAT [client arguments]
  local what="$1"
  shift
  run_client "$@" && fail "${what}: read succeeded against a peer without MMS"
  grep -aq "timed out" "${clog}" || fail "${what}: the client did not reach COTP"
  tls_up || fail "${what}: no COTP request at s_server"
}

rejects() {  # WHAT [client arguments]
  local what="$1"
  shift
  run_client "$@" && fail "${what}: read succeeded"
  grep -aq "timed out" "${clog}" && fail "${what}: the client got past the handshake"
  tls_up && fail "${what}: COTP was sent to the peer"
  return 0
}

start_s_server srv.chain
passes "TLS against s_server" --tls-ca "${work}/root.pem" "${own[@]}"

start_s_server srv.chain -tls1_2
passes "TLS 1.2 only peer" --tls-ca "${work}/root.pem" "${own[@]}"
grep -aq "CIPHER is ECDHE" "${log}" || fail "TLS 1.2 only peer: other cipher family"

start_s_server srv.chain -tls1_3
passes "TLS 1.3 only peer" --tls-ca "${work}/root.pem" "${own[@]}"
grep -aq "CIPHER is TLS_" "${log}" || fail "TLS 1.3 only peer: other cipher family"

start_s_server srv.chain -tls1_2 -Verify 2 -CAfile "${work}/root.pem" -verify_return_error
passes "mutual authentication, TLS 1.2" --tls-ca "${work}/root.pem" "${own[@]}"
grep -aq "subject=.*CN *= *client" "${log}" || fail "s_server did not see the client certificate"

start_s_server srv.chain -tls1_3 -Verify 2 -CAfile "${work}/root.pem" -verify_return_error
passes "mutual authentication, TLS 1.3" --tls-ca "${work}/root.pem" "${own[@]}"
grep -aq "subject=.*CN *= *client" "${log}" || fail "s_server did not see the client certificate"

start_s_server srv.chain -tls1_2 -Verify 2 -CAfile "${work}/root.pem" -verify_return_error
rejects "peer that demands a client certificate" --tls-ca "${work}/root.pem"

# In TLS 1.3 the client finishes first, so the refusal is an alert in reply to the COTP request.
start_s_server srv.chain -tls1_3 -Verify 2 -CAfile "${work}/root.pem" -verify_return_error
run_client --tls-ca "${work}/root.pem" && fail "TLS 1.3 refusal: read succeeded"
grep -aq "timed out" "${clog}" && fail "TLS 1.3 refusal: alert not reported to the client"
grep -aq "alert" "${clog}" || fail "TLS 1.3 refusal: no alert in the client error"

start_s_server srv.chain -tls1_2 -Verify 2 -CAfile "${work}/rogue.pem" -verify_return_error
rejects "peer that does not trust the client" --tls-ca "${work}/root.pem" "${own[@]}"

for version in -tls1_2 -tls1_3; do
  start_s_server srv.chain "${version}"
  rejects "server of an unknown CA ${version}" --tls-ca "${work}/rogue.pem" "${own[@]}"
  grep -aq "certificate verify failed" "${clog}" || fail "unknown CA: no verification error"
done

start_s_server srv
rejects "server that omits the intermediate" --tls-ca "${work}/root.pem" "${own[@]}"

start_s_server expired.chain
rejects "expired server certificate" --tls-ca "${work}/root.pem" "${own[@]}"
grep -aq "certificate verify failed" "${clog}" || fail "expired: no verification error"

start_s_server revoked.chain
rejects "revoked server certificate" --tls-ca "${work}/root.pem" --tls-crl "${work}/inter.crl" "${own[@]}"
grep -aq "certificate verify failed" "${clog}" || fail "revoked: no verification error"

start_s_server srv.chain
passes "not revoked" --tls-ca "${work}/root.pem" --tls-crl "${work}/inter.crl" "${own[@]}"

start_s_server other.chain
rejects "server certificate of another address" --tls-ca "${work}/root.pem" "${own[@]}"
grep -aq "certificate verify failed" "${clog}" || fail "other address: no verification error"

start_s_server named.chain
passes "name of the host" --tls-ca "${work}/root.pem" --tls-peer-name ied.example "${own[@]}"

start_s_server localhost.chain
passes "name of the host connected to" --tls-ca "${work}/root.pem" --host localhost "${own[@]}"

start_s_server srv.chain
rejects "address certificate, host name" --tls-ca "${work}/root.pem" --host localhost "${own[@]}"

start_s_server other.chain
passes "expected name" --tls-ca "${work}/root.pem" --tls-peer-name other.example "${own[@]}"

start_s_server other.chain
rejects "wrong expected name" --tls-ca "${work}/root.pem" --tls-peer-name nope.example "${own[@]}"

start_s_server srv.chain
rejects "unknown CA, no client certificate" --tls-ca "${work}/rogue.pem"

start_s_server other.chain
passes "verification off" --tls-no-verify

if [[ -n "${tls1_1}" ]]; then
  start_s_server srv.chain -tls1_1 -cipher 'ALL:@SECLEVEL=0'
  rejects "peer limited to TLS 1.1" --tls-ca "${work}/root.pem" "${own[@]}"
fi

echo "TLS peer test passed against $(openssl version)"
