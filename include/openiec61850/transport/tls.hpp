#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "openiec61850/core/result.hpp"

namespace openiec61850::transport {

// IANA "secure-mms": ISO transport services (RFC 1006) inside TLS.
inline constexpr std::uint16_t default_tls_port = 3782;

enum class tls_version : std::uint8_t { tls1_2, tls1_3 };

// TLS parameters of one endpoint (IEC 62351-3). The defaults authenticate both sides: a client
// checks the server certificate and its name, a server requires a client certificate.
struct tls_config {
  // PEM files. certificate_file is the local chain, leaf first; required on a server and on a
  // client that must authenticate itself.
  std::string ca_file;  // trust anchors; required when verify_peer is set
  std::string certificate_file;
  std::string private_key_file;
  std::string private_key_password;
  // CRLs checked for the peer's leaf certificate, which is rejected when no CRL of its issuer is
  // in the file. Unset checks no revocation.
  std::string crl_file;

  bool verify_peer = true;
  // Client: the server certificate must match peer_name, or the host being connected to when
  // peer_name is empty (an IP literal is matched against the IP subject alternative names).
  // Server: only checked when peer_name is set. Needs verify_peer.
  bool verify_peer_name = true;
  std::string peer_name;

  tls_version min_version = tls_version::tls1_2;
  std::optional<tls_version> max_version;
  // OpenSSL cipher strings for TLS 1.2 and TLS 1.3; empty keeps OpenSSL's defaults.
  std::string cipher_list;
  std::string cipher_suites;
};

// What the TLS handshake established. Immutable once the channel is handed out.
struct tls_session_info {
  std::string version;  // e.g. "TLSv1.3"
  std::string cipher;
  // The peer's leaf certificate, empty when it sent none.
  std::string peer_subject;  // RFC 2253 form
  std::string peer_issuer;
  std::string peer_serial;  // upper-case hex
  std::string peer_fingerprint_sha256;  // lower-case hex
};

// A loaded tls_config, shared by every connection that uses it. Immutable and safe to share
// between threads; connections keep it alive.
class tls_context {
 public:
  // Loads and checks the files. Errors: errc::unsupported when the library was built without
  // OPENIEC61850_ENABLE_TLS, std::errc::invalid_argument for an inconsistent configuration, the
  // OpenSSL error (asio::error::get_ssl_category()) for a file that cannot be loaded.
  // A server needs server = true: certificate_file and private_key_file become mandatory.
  [[nodiscard]] static result<std::shared_ptr<tls_context>> create(const tls_config& config,
                                                                   bool server);

  // False when the library was built without TLS.
  [[nodiscard]] static bool available() noexcept;

  [[nodiscard]] const tls_config& config() const noexcept;

  struct impl;
  [[nodiscard]] impl& native() const noexcept { return *impl_; }

  explicit tls_context(std::shared_ptr<impl> i) noexcept : impl_(std::move(i)) {}

 private:
  std::shared_ptr<impl> impl_;
};

}  // namespace openiec61850::transport
