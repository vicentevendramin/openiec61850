#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "openiec61850/ber/decode.hpp"
#include "openiec61850/ber/oid.hpp"
#include "openiec61850/ber/tag.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"

namespace openiec61850::ber {

// Non-allocating cursor over a sequence of TLVs. Copying a reader is cheap (it is a view).
// Every operation that fails leaves the reader unchanged.
//
//   ber::reader rd{pdu};
//   auto seq = rd.enter(ber::tags::sequence);           // descend into a SEQUENCE
//   auto id = seq->read_unsigned(ber::context(0));      // [0] IMPLICIT INTEGER
//   if (seq->next_is(ber::context(1, true))) { ... }    // OPTIONAL field
class reader {
 public:
  reader() noexcept = default;
  explicit reader(byte_view data, decode_options opts = {}) noexcept : data_(data), opts_(opts) {}

  [[nodiscard]] bool empty() const noexcept { return data_.empty(); }
  [[nodiscard]] std::size_t remaining() const noexcept { return data_.size(); }
  [[nodiscard]] byte_view rest() const noexcept { return data_; }
  [[nodiscard]] std::size_t depth() const noexcept { return depth_; }
  [[nodiscard]] const decode_options& options() const noexcept { return opts_; }

  // Decodes the next element without consuming it.
  [[nodiscard]] result<tlv> peek() const noexcept;
  // Decodes only the next identifier; cheaper than peek().
  [[nodiscard]] result<ber::tag> peek_tag() const noexcept;
  // True when the next identifier is exactly `t` (class, form and number).
  [[nodiscard]] bool next_is(ber::tag t) const noexcept;

  [[nodiscard]] result<tlv> next() noexcept;
  // Like next(), but fails with errc::malformed_encoding unless the tag is exactly `t`.
  [[nodiscard]] result<tlv> expect(ber::tag t) noexcept;
  [[nodiscard]] result<void> skip() noexcept;
  // Fails with errc::malformed_encoding when unread data remains.
  [[nodiscard]] result<void> expect_end() const noexcept;

  // Reader over the contents of a constructed element (errc::malformed_encoding if primitive,
  // errc::nesting_too_deep beyond max_depth).
  [[nodiscard]] result<reader> enter(const tlv& e) const noexcept;
  // expect(t) followed by enter(); `t` is taken as constructed.
  [[nodiscard]] result<reader> enter(ber::tag t) noexcept;

  // Reads the next element with the class and number of `t` through the matching decoder.
  // The form is checked by the decoder (see decode.hpp), so a segmented string is reported
  // as errc::unsupported rather than as a tag mismatch.
  [[nodiscard]] result<bool> read_boolean(ber::tag t = tags::boolean) noexcept;
  [[nodiscard]] result<std::int64_t> read_integer(ber::tag t = tags::integer) noexcept;
  [[nodiscard]] result<std::uint64_t> read_unsigned(ber::tag t = tags::integer) noexcept;
  [[nodiscard]] result<std::int64_t> read_enumerated(ber::tag t = tags::enumerated) noexcept;
  [[nodiscard]] result<void> read_null(ber::tag t = tags::null) noexcept;
  [[nodiscard]] result<bit_string_view> read_bit_string(ber::tag t = tags::bit_string) noexcept;
  [[nodiscard]] result<byte_view> read_octet_string(ber::tag t = tags::octet_string) noexcept;
  [[nodiscard]] result<oid> read_oid(ber::tag t = tags::object_identifier) noexcept;
  [[nodiscard]] result<std::string_view> read_visible_string(
      ber::tag t = tags::visible_string) noexcept;
  [[nodiscard]] result<std::string_view> read_utf8_string(ber::tag t = tags::utf8_string) noexcept;
  [[nodiscard]] result<std::string_view> read_generalized_time(
      ber::tag t = tags::generalized_time) noexcept;

 private:
  reader(byte_view data, decode_options opts, std::size_t depth) noexcept
      : data_(data), opts_(opts), depth_(depth) {}

  template <typename T, typename Decoder>
  result<T> read_as(ber::tag t, Decoder decode) noexcept;

  void advance(const tlv& e) noexcept { data_ = data_.subspan(e.encoding.size()); }

  byte_view data_;
  decode_options opts_;
  std::size_t depth_ = 0;
};

}  // namespace openiec61850::ber
