#include "openiec61850/ber/reader.hpp"

namespace openiec61850::ber {

result<tlv> reader::peek() const noexcept {
  if (data_.empty()) return errc::truncated_input;
  return decode_tlv(data_, opts_, depth_);
}

result<tag> reader::peek_tag() const noexcept { return decode_tag(data_); }

bool reader::next_is(ber::tag t) const noexcept {
  const auto actual = peek_tag();
  return actual && *actual == t;
}

result<tlv> reader::next() noexcept {
  auto e = peek();
  if (e) advance(*e);
  return e;
}

result<tlv> reader::expect(ber::tag t) noexcept {
  // Check the identifier first so a mismatch does not pay for scanning an indefinite length.
  const auto actual = peek_tag();
  if (!actual) return actual.error();
  if (*actual != t) return errc::malformed_encoding;
  return next();
}

result<void> reader::skip() noexcept {
  const auto e = next();
  if (!e) return e.error();
  return {};
}

result<void> reader::expect_end() const noexcept {
  if (!data_.empty()) return errc::malformed_encoding;
  return {};
}

result<reader> reader::enter(const tlv& e) const noexcept {
  if (!e.tag.constructed) return errc::malformed_encoding;
  if (depth_ + 1 > opts_.max_depth) return errc::nesting_too_deep;
  return reader{e.value, opts_, depth_ + 1};
}

result<reader> reader::enter(ber::tag t) noexcept {
  const auto actual = peek_tag();
  if (!actual) return actual.error();
  if (*actual != t.as_constructed()) return errc::malformed_encoding;
  const auto e = peek();
  if (!e) return e.error();
  auto child = enter(*e);
  if (child) advance(*e);
  return child;
}

template <typename T, typename Decoder>
result<T> reader::read_as(ber::tag t, Decoder decode) noexcept {
  const auto actual = peek_tag();
  if (!actual) return actual.error();
  if (!actual->same_id(t)) return errc::malformed_encoding;
  const auto e = peek();
  if (!e) return e.error();
  // Form errors (e.g. a constructed BOOLEAN, or a segmented string) come from the decoder.
  auto v = decode(*e);
  if (v) advance(*e);
  return v;
}

result<bool> reader::read_boolean(ber::tag t) noexcept {
  return read_as<bool>(t, [](const tlv& e) { return decode_boolean(e); });
}
result<std::int64_t> reader::read_integer(ber::tag t) noexcept {
  return read_as<std::int64_t>(t, [](const tlv& e) { return decode_integer(e); });
}
result<std::uint64_t> reader::read_unsigned(ber::tag t) noexcept {
  return read_as<std::uint64_t>(t, [](const tlv& e) { return decode_unsigned(e); });
}
result<std::int64_t> reader::read_enumerated(ber::tag t) noexcept {
  return read_as<std::int64_t>(t, [](const tlv& e) { return decode_enumerated(e); });
}
result<void> reader::read_null(ber::tag t) noexcept {
  return read_as<void>(t, [](const tlv& e) { return decode_null(e); });
}
result<bit_string_view> reader::read_bit_string(ber::tag t) noexcept {
  return read_as<bit_string_view>(t, [](const tlv& e) { return decode_bit_string(e); });
}
result<byte_view> reader::read_octet_string(ber::tag t) noexcept {
  return read_as<byte_view>(t, [](const tlv& e) { return decode_octet_string(e); });
}
result<oid> reader::read_oid(ber::tag t) noexcept {
  return read_as<oid>(t, [](const tlv& e) { return decode_oid(e); });
}
result<std::string_view> reader::read_visible_string(ber::tag t) noexcept {
  return read_as<std::string_view>(t, [](const tlv& e) { return decode_visible_string(e); });
}
result<std::string_view> reader::read_utf8_string(ber::tag t) noexcept {
  return read_as<std::string_view>(t, [](const tlv& e) { return decode_utf8_string(e); });
}
result<std::string_view> reader::read_generalized_time(ber::tag t) noexcept {
  return read_as<std::string_view>(t, [](const tlv& e) { return decode_generalized_time(e); });
}

}  // namespace openiec61850::ber
