#pragma once

#include <filesystem>
#include <string>
#include <vector>

// Short-lived X.509 material generated at test time (EC P-256), so that no key or expiring
// certificate lives in the repository.
namespace tls_test {

struct key_pair {
  std::string certificate;  // PEM file
  std::string private_key;  // PEM file
};

class certificate_authority {
 public:
  // Creates a self-signed CA below dir.
  certificate_authority(std::filesystem::path dir, const std::string& name);
  ~certificate_authority();
  certificate_authority(const certificate_authority&) = delete;
  certificate_authority& operator=(const certificate_authority&) = delete;

  // subject_alt_names as in OpenSSL's config syntax: "DNS:ied1", "IP:127.0.0.1".
  [[nodiscard]] key_pair issue(const std::string& name,
                               const std::vector<std::string>& subject_alt_names = {},
                               int valid_seconds = 3600);
  // Writes a CRL revoking the certificates issued from `revoked` and returns its path.
  [[nodiscard]] std::string revoke(const key_pair& revoked);

  [[nodiscard]] const std::string& certificate() const noexcept { return cert_path_; }

 private:
  std::filesystem::path dir_;
  std::string name_;
  std::string cert_path_;
  void* key_ = nullptr;   // EVP_PKEY*
  void* cert_ = nullptr;  // X509*
  long next_serial_ = 2;
};

// A new empty directory, removed by the destructor.
struct temp_dir {
  temp_dir();
  ~temp_dir();
  temp_dir(const temp_dir&) = delete;
  temp_dir& operator=(const temp_dir&) = delete;
  std::filesystem::path path;
};

}  // namespace tls_test
