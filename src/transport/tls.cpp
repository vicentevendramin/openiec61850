#include "openiec61850/transport/tls.hpp"

#include <system_error>

#ifdef OPENIEC61850_WITH_TLS

#include <array>
#include <cstddef>
#include <cstring>
#include <memory>
#include <string_view>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <asio/ip/address.hpp>

#include "tls_impl.hpp"

namespace openiec61850::transport {

namespace {

std::error_code last_ssl_error() {
  const auto e = ERR_get_error();
  ERR_clear_error();
  if (e == 0) return make_error_code(errc::malformed_encoding);
  return {static_cast<int>(e), asio::error::get_ssl_category()};
}

std::string name_to_string(const X509_NAME* name) {
  const std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
  if (!bio || X509_NAME_print_ex(bio.get(), name, 0, XN_FLAG_RFC2253) < 0) return {};
  char* data = nullptr;
  const auto size = BIO_get_mem_data(bio.get(), &data);
  return size > 0 ? std::string(data, static_cast<std::size_t>(size)) : std::string{};
}

std::string serial_to_string(const ASN1_INTEGER* serial) {
  const std::unique_ptr<BIGNUM, decltype(&BN_free)> bn(ASN1_INTEGER_to_BN(serial, nullptr), BN_free);
  if (!bn) return {};
  const std::unique_ptr<char, void (*)(char*)> hex(BN_bn2hex(bn.get()),
                                                   [](char* p) { OPENSSL_free(p); });
  return hex ? std::string(hex.get()) : std::string{};
}

std::string fingerprint_sha256(const X509* cert) {
  std::array<unsigned char, EVP_MAX_MD_SIZE> md{};
  unsigned int size = 0;
  if (X509_digest(cert, EVP_sha256(), md.data(), &size) != 1) return {};
  static constexpr std::string_view digits = "0123456789abcdef";
  std::string text;
  text.reserve(size * 2);
  for (unsigned int i = 0; i < size; ++i) {
    text.push_back(digits[md[i] >> 4]);
    text.push_back(digits[md[i] & 0x0F]);
  }
  return text;
}

bool is_ip_literal(const std::string& host) {
  std::error_code ec;
  (void)asio::ip::make_address(host, ec);
  return !ec;
}

std::error_code load_crls(SSL_CTX* ctx, const std::string& path) {
  X509_STORE* store = SSL_CTX_get_cert_store(ctx);
  X509_LOOKUP* lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
  if (lookup == nullptr || X509_load_crl_file(lookup, path.c_str(), X509_FILETYPE_PEM) <= 0) {
    return last_ssl_error();
  }
  X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
  return {};
}

std::error_code configure(SSL_CTX* ctx, const tls_config& c) {
  // Both ends authenticate on every connection, so nothing is gained from resumption, and a
  // resumed session would skip the certificate checks of the handshake being made.
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_num_tickets(ctx, 0);
  SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION);
  const auto wire = [](tls_version v) { return v == tls_version::tls1_3 ? TLS1_3_VERSION : TLS1_2_VERSION; };
  if (SSL_CTX_set_min_proto_version(ctx, wire(c.min_version)) != 1) return last_ssl_error();
  if (c.max_version && SSL_CTX_set_max_proto_version(ctx, wire(*c.max_version)) != 1) {
    return last_ssl_error();
  }
  if (!c.cipher_list.empty() && SSL_CTX_set_cipher_list(ctx, c.cipher_list.c_str()) != 1) {
    return last_ssl_error();
  }
  if (!c.cipher_suites.empty() && SSL_CTX_set_ciphersuites(ctx, c.cipher_suites.c_str()) != 1) {
    return last_ssl_error();
  }
  return {};
}

}  // namespace

result<std::shared_ptr<tls_context>> tls_context::create(const tls_config& config, bool server) {
  const bool has_cert = !config.certificate_file.empty();
  const bool has_key = !config.private_key_file.empty();
  if (has_cert != has_key || (server && !has_cert) || (config.verify_peer && config.ca_file.empty())) {
    return std::make_error_code(std::errc::invalid_argument);
  }
  auto i = std::make_shared<impl>();
  i->config = config;
  SSL_CTX* ctx = i->ssl.native_handle();
  ERR_clear_error();
  if (auto ec = configure(ctx, config)) return ec;

  std::error_code ec;
  if (has_cert) {
    if (i->ssl.set_password_callback(
            [pw = config.private_key_password](std::size_t, asio::ssl::context::password_purpose) {
              return pw;
            },
            ec);
        ec) {
      return ec;
    }
    if (i->ssl.use_certificate_chain_file(config.certificate_file, ec); ec) return ec;
    if (i->ssl.use_private_key_file(config.private_key_file, asio::ssl::context::pem, ec); ec) {
      return ec;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) return last_ssl_error();
  }
  if (!config.ca_file.empty()) {
    if (i->ssl.load_verify_file(config.ca_file, ec); ec) return ec;
  }
  if (!config.crl_file.empty()) {
    if (auto e = load_crls(ctx, config.crl_file)) return e;
  }
  asio::ssl::verify_mode mode = asio::ssl::verify_none;
  if (config.verify_peer) mode = asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert;
  if (i->ssl.set_verify_mode(mode, ec); ec) return ec;
  return std::make_shared<tls_context>(std::move(i));
}

bool tls_context::available() noexcept { return true; }

const tls_config& tls_context::config() const noexcept { return impl_->config; }

std::error_code set_expected_peer_name(tls_stream& stream, const std::string& name) {
  SSL* ssl = stream.native_handle();
  if (is_ip_literal(name)) {
    if (X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), name.c_str()) != 1) return last_ssl_error();
  } else if (SSL_set1_host(ssl, name.c_str()) != 1) {
    return last_ssl_error();
  }
  return {};
}

void set_server_name_indication(tls_stream& stream, const std::string& host) {
  if (!host.empty() && !is_ip_literal(host)) {
    // SSL_set_tlsext_host_name() is a macro with an old-style cast.
    SSL_ctrl(stream.native_handle(), SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name,
             const_cast<char*>(host.c_str()));
  }
}

tls_session_info describe_session(tls_stream& stream) {
  SSL* ssl = stream.native_handle();
  tls_session_info info;
  info.version = SSL_get_version(ssl);
  info.cipher = SSL_get_cipher_name(ssl);
  const std::unique_ptr<X509, decltype(&X509_free)> cert(SSL_get1_peer_certificate(ssl), X509_free);
  if (cert) {
    info.peer_subject = name_to_string(X509_get_subject_name(cert.get()));
    info.peer_issuer = name_to_string(X509_get_issuer_name(cert.get()));
    info.peer_serial = serial_to_string(X509_get0_serialNumber(cert.get()));
    info.peer_fingerprint_sha256 = fingerprint_sha256(cert.get());
  }
  return info;
}

}  // namespace openiec61850::transport

#else

namespace openiec61850::transport {

struct tls_context::impl {
  tls_config config;
};

result<std::shared_ptr<tls_context>> tls_context::create(const tls_config&, bool) {
  return errc::unsupported;
}

bool tls_context::available() noexcept { return false; }

const tls_config& tls_context::config() const noexcept { return impl_->config; }

}  // namespace openiec61850::transport

#endif
