#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>

#include "openiec61850/ber/oid.hpp"
#include "openiec61850/ber/tag.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"

// BER encoder producing DER-style minimal definite lengths, minimal INTEGERs and minimal tags.
//
// Design: forward encoding with reserve-and-patch. Opening a constructed element writes the
// identifier and reserves one length octet; closing it writes the real length, shifting the
// contents right only when the long form is needed (contents >= 128 octets). Compared with
// backwards encoding this keeps the natural field order of the ASN.1 definition at the call
// site, and the cost of the shift (one memmove of the contents per long constructed element)
// is small for MMS-sized PDUs. Open elements are tracked by markers held by the caller, so the
// writer itself never allocates; only the output buffer grows.

namespace openiec61850::ber {

class writer {
 public:
  // Opaque handle returned by begin(); must be passed to end() in LIFO order.
  struct marker {
    std::size_t length_offset;
    std::size_t depth;
  };

  // Appends to `out`; existing contents are kept (e.g. reserved space for lower-layer headers).
  explicit writer(byte_buffer& out) noexcept : out_(&out) {}

  [[nodiscard]] byte_buffer& buffer() const noexcept { return *out_; }
  // Number of constructed elements opened and not yet closed.
  [[nodiscard]] std::size_t depth() const noexcept { return depth_; }

  // Constructed elements; `t` is taken as constructed.
  [[nodiscard]] marker begin(tag t);
  void end(marker m);
  template <typename F>
  void constructed(tag t, F&& body) {
    const marker m = begin(t);
    std::forward<F>(body)();
    end(m);
  }

  // Identifier, length and contents written as given.
  void write_tlv(tag t, byte_view contents);
  // Pre-encoded TLVs copied verbatim.
  void write_raw(byte_view encoded);

  void write_boolean(bool v, tag t = tags::boolean);
  void write_integer(std::int64_t v, tag t = tags::integer);
  void write_unsigned(std::uint64_t v, tag t = tags::integer);
  void write_enumerated(std::int64_t v, tag t = tags::enumerated);
  void write_null(tag t = tags::null);
  // `bytes` must hold exactly ceil(bit_count / 8) octets (errc::malformed_encoding otherwise).
  // Padding bits are written as zero (X.690 §11.2.1).
  result<void> write_bit_string(byte_view bytes, std::size_t bit_count, tag t = tags::bit_string);
  void write_octet_string(byte_view v, tag t = tags::octet_string);
  // Fails with errc::malformed_encoding unless v.valid().
  result<void> write_oid(const oid& v, tag t = tags::object_identifier);
  void write_visible_string(std::string_view v, tag t = tags::visible_string);
  void write_utf8_string(std::string_view v, tag t = tags::utf8_string);
  void write_generalized_time(std::string_view v, tag t = tags::generalized_time);

 private:
  byte_buffer* out_;
  std::size_t depth_ = 0;
};

// Low-level helpers, appending to `out`.
void encode_tag(byte_buffer& out, tag t);
void encode_length(byte_buffer& out, std::size_t length);
[[nodiscard]] std::size_t encoded_length_size(std::size_t length) noexcept;

}  // namespace openiec61850::ber
