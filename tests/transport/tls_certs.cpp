#include "tls_certs.hpp"

#ifdef OPENIEC61850_WITH_TLS

#include <atomic>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <utility>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <unistd.h>

namespace tls_test {

namespace fs = std::filesystem;

namespace {

using pkey_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using x509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using bio_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;

void check(bool ok, const char* what) {
  if (!ok) throw std::runtime_error(std::string("OpenSSL failure: ") + what);
}

EVP_PKEY* new_key() {
  EVP_PKEY* key = EVP_EC_gen("P-256");
  check(key != nullptr, "EVP_EC_gen");
  return key;
}

bio_ptr open_file(const std::string& path) {
  bio_ptr bio(BIO_new_file(path.c_str(), "w"), BIO_free);
  check(bio != nullptr, "BIO_new_file");
  return bio;
}

void add_ext(X509* cert, X509* issuer, int nid, const std::string& value) {
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
  X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value.c_str());
  check(ext != nullptr, "X509V3_EXT_conf_nid");
  check(X509_add_ext(cert, ext, -1) == 1, "X509_add_ext");
  X509_EXTENSION_free(ext);
}

X509* make_cert(const std::string& name, long serial, EVP_PKEY* subject_key, X509* issuer,
                int valid_seconds) {
  X509* cert = X509_new();
  check(cert != nullptr, "X509_new");
  X509_set_version(cert, X509_VERSION_3);
  ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
  X509_gmtime_adj(X509_getm_notBefore(cert), -60);
  X509_gmtime_adj(X509_getm_notAfter(cert), valid_seconds);
  X509_set_pubkey(cert, subject_key);
  X509_NAME* subject = X509_get_subject_name(cert);
  X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                             reinterpret_cast<const unsigned char*>(name.c_str()), -1, -1, 0);
  X509_set_issuer_name(cert, issuer != nullptr ? X509_get_subject_name(issuer) : subject);
  return cert;
}

void write_cert(const std::string& path, X509* cert) {
  auto bio = open_file(path);
  check(PEM_write_bio_X509(bio.get(), cert) == 1, "PEM_write_bio_X509");
}

}  // namespace

certificate_authority::certificate_authority(fs::path dir, const std::string& name)
    : dir_(std::move(dir)), name_(name) {
  EVP_PKEY* key = new_key();
  X509* cert = make_cert(name, 1, key, nullptr, 3600);
  add_ext(cert, cert, NID_basic_constraints, "critical,CA:TRUE");
  add_ext(cert, cert, NID_key_usage, "critical,keyCertSign,cRLSign");
  check(X509_sign(cert, key, EVP_sha256()) > 0, "X509_sign");
  cert_path_ = (dir_ / (name + "-ca.pem")).string();
  write_cert(cert_path_, cert);
  key_ = key;
  cert_ = cert;
}

certificate_authority::~certificate_authority() {
  X509_free(static_cast<X509*>(cert_));
  EVP_PKEY_free(static_cast<EVP_PKEY*>(key_));
}

key_pair certificate_authority::issue(const std::string& name,
                                      const std::vector<std::string>& subject_alt_names,
                                      int valid_seconds) {
  auto* ca_key = static_cast<EVP_PKEY*>(key_);
  auto* ca_cert = static_cast<X509*>(cert_);
  pkey_ptr key(new_key(), EVP_PKEY_free);
  x509_ptr cert(make_cert(name, next_serial_++, key.get(), ca_cert, valid_seconds),
                X509_free);
  add_ext(cert.get(), ca_cert, NID_basic_constraints, "critical,CA:FALSE");
  add_ext(cert.get(), ca_cert, NID_ext_key_usage, "serverAuth,clientAuth");
  if (!subject_alt_names.empty()) {
    std::string san;
    for (const auto& s : subject_alt_names) san += (san.empty() ? "" : ",") + s;
    add_ext(cert.get(), ca_cert, NID_subject_alt_name, san);
  }
  check(X509_sign(cert.get(), ca_key, EVP_sha256()) > 0, "X509_sign");

  key_pair out;
  out.certificate = (dir_ / (name + ".pem")).string();
  out.private_key = (dir_ / (name + ".key")).string();
  write_cert(out.certificate, cert.get());
  auto bio = open_file(out.private_key);
  check(PEM_write_bio_PrivateKey(bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1,
        "PEM_write_bio_PrivateKey");
  return out;
}

std::string certificate_authority::revoke(const key_pair& revoked) {
  bio_ptr in(BIO_new_file(revoked.certificate.c_str(), "r"), BIO_free);
  check(in != nullptr, "BIO_new_file");
  x509_ptr cert(PEM_read_bio_X509(in.get(), nullptr, nullptr, nullptr), X509_free);
  check(cert != nullptr, "PEM_read_bio_X509");

  std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> crl(X509_CRL_new(), X509_CRL_free);
  check(crl != nullptr, "X509_CRL_new");
  X509_CRL_set_version(crl.get(), X509_CRL_VERSION_2);
  X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(static_cast<X509*>(cert_)));
  std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> now(ASN1_TIME_new(), ASN1_TIME_free);
  X509_gmtime_adj(now.get(), -60);
  X509_CRL_set1_lastUpdate(crl.get(), now.get());
  X509_gmtime_adj(now.get(), 3600);
  X509_CRL_set1_nextUpdate(crl.get(), now.get());

  X509_REVOKED* entry = X509_REVOKED_new();
  X509_REVOKED_set_serialNumber(entry, X509_get_serialNumber(cert.get()));
  X509_gmtime_adj(now.get(), -60);
  X509_REVOKED_set_revocationDate(entry, now.get());
  check(X509_CRL_add0_revoked(crl.get(), entry) == 1, "X509_CRL_add0_revoked");
  X509_CRL_sort(crl.get());
  check(X509_CRL_sign(crl.get(), static_cast<EVP_PKEY*>(key_), EVP_sha256()) > 0, "X509_CRL_sign");

  const auto path = (dir_ / (name_ + ".crl")).string();
  auto bio = open_file(path);
  check(PEM_write_bio_X509_CRL(bio.get(), crl.get()) == 1, "PEM_write_bio_X509_CRL");
  return path;
}

temp_dir::temp_dir() {
  static std::atomic<int> counter{0};
  path = fs::temp_directory_path() /
         ("openiec61850-tls-" + std::to_string(::getpid()) + "-" + std::to_string(++counter));
  fs::create_directories(path);
}

temp_dir::~temp_dir() {
  std::error_code ignored;
  fs::remove_all(path, ignored);
}

}  // namespace tls_test

#endif
