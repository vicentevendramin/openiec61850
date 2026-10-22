#include "openiec61850/ber/writer.hpp"

#include <cassert>

namespace openiec61850::ber {
namespace {

std::size_t unsigned_octets(std::uint64_t v) noexcept {
  std::size_t n = 1;
  while (n < 8 && (v >> (8 * n)) != 0) ++n;
  return n;
}

// Smallest two's-complement width in octets (X.690 §8.3.2).
std::size_t signed_octets(std::int64_t v) noexcept {
  std::size_t n = 1;
  while (n < 8) {
    const std::int64_t bound = std::int64_t{1} << (8 * n - 1);
    if (v >= -bound && v < bound) break;
    ++n;
  }
  return n;
}

void put_big_endian(byte_buffer& out, std::uint64_t v, std::size_t n) {
  for (std::size_t i = n; i-- > 0;) out.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
}

void put_base128(byte_buffer& out, std::uint64_t v) {
  std::size_t groups = 1;
  while (groups < 10 && (v >> (7 * groups)) != 0) ++groups;
  for (std::size_t i = groups; i-- > 0;) {
    const auto group = static_cast<std::uint8_t>((v >> (7 * i)) & 0x7FU);
    out.push_back(i == 0 ? group : static_cast<std::uint8_t>(group | 0x80U));
  }
}

// Writes the identifier and a one-octet length placeholder; returns the placeholder offset.
std::size_t open_element(byte_buffer& out, tag t) {
  encode_tag(out, t);
  out.push_back(0);
  return out.size() - 1;
}

// Replaces the placeholder at `offset` with the minimal length of everything after it.
void close_element(byte_buffer& out, std::size_t offset) {
  const std::size_t length = out.size() - offset - 1;
  if (length < 0x80) {
    out[offset] = static_cast<std::uint8_t>(length);
    return;
  }
  const std::size_t n = encoded_length_size(length) - 1;
  const auto pos = out.begin() + static_cast<std::ptrdiff_t>(offset) + 1;
  out.insert(pos, n, std::uint8_t{0});
  out[offset] = static_cast<std::uint8_t>(0x80U | n);
  for (std::size_t i = 0; i < n; ++i) {
    out[offset + 1 + i] = static_cast<std::uint8_t>(length >> (8 * (n - 1 - i)));
  }
}

}  // namespace

// X.690 §8.1.2
void encode_tag(byte_buffer& out, tag t) {
  auto first = static_cast<std::uint8_t>(static_cast<unsigned>(t.cls) << 6);
  if (t.constructed) first = static_cast<std::uint8_t>(first | 0x20U);
  if (t.number < 31) {
    out.push_back(static_cast<std::uint8_t>(first | t.number));
    return;
  }
  out.push_back(static_cast<std::uint8_t>(first | 0x1FU));
  put_base128(out, t.number);
}

std::size_t encoded_length_size(std::size_t length) noexcept {
  if (length < 0x80) return 1;
  return 1 + unsigned_octets(length);
}

// X.690 §8.1.3, definite form; §10.1: shortest possible.
void encode_length(byte_buffer& out, std::size_t length) {
  if (length < 0x80) {
    out.push_back(static_cast<std::uint8_t>(length));
    return;
  }
  const std::size_t n = unsigned_octets(length);
  out.push_back(static_cast<std::uint8_t>(0x80U | n));
  put_big_endian(out, length, n);
}

writer::marker writer::begin(tag t) {
  const std::size_t offset = open_element(*out_, t.as_constructed());
  return {offset, depth_++};
}

void writer::end(marker m) {
  assert(depth_ > 0 && m.depth == depth_ - 1 && "writer::end called out of order");
  --depth_;
  close_element(*out_, m.length_offset);
}

void writer::write_tlv(tag t, byte_view contents) {
  encode_tag(*out_, t);
  encode_length(*out_, contents.size());
  out_->insert(out_->end(), contents.begin(), contents.end());
}

void writer::write_raw(byte_view encoded) {
  out_->insert(out_->end(), encoded.begin(), encoded.end());
}

// §11.1: DER encodes TRUE as FF.
void writer::write_boolean(bool v, tag t) {
  encode_tag(*out_, t);
  out_->push_back(1);
  out_->push_back(v ? 0xFF : 0x00);
}

void writer::write_integer(std::int64_t v, tag t) {
  const std::size_t n = signed_octets(v);
  encode_tag(*out_, t);
  out_->push_back(static_cast<std::uint8_t>(n));
  put_big_endian(*out_, static_cast<std::uint64_t>(v), n);
}

void writer::write_unsigned(std::uint64_t v, tag t) {
  const std::size_t n = unsigned_octets(v);
  const bool pad = ((v >> (8 * n - 1)) & 1U) != 0;  // keep the value non-negative
  encode_tag(*out_, t);
  out_->push_back(static_cast<std::uint8_t>(n + (pad ? 1 : 0)));
  if (pad) out_->push_back(0);
  put_big_endian(*out_, v, n);
}

void writer::write_enumerated(std::int64_t v, tag t) { write_integer(v, t); }

void writer::write_null(tag t) {
  encode_tag(*out_, t);
  out_->push_back(0);
}

// §8.6.2
result<void> writer::write_bit_string(byte_view bytes, std::size_t bit_count, tag t) {
  if (bytes.size() != (bit_count + 7) / 8) return errc::malformed_encoding;
  const auto unused = static_cast<std::uint8_t>(bytes.size() * 8 - bit_count);
  encode_tag(*out_, t);
  encode_length(*out_, bytes.size() + 1);
  out_->push_back(unused);
  if (bytes.empty()) return {};
  out_->insert(out_->end(), bytes.begin(), bytes.end());
  out_->back() = static_cast<std::uint8_t>(out_->back() & (0xFFU << unused));
  return {};
}

void writer::write_octet_string(byte_view v, tag t) { write_tlv(t, v); }

// §8.19
result<void> writer::write_oid(const oid& v, tag t) {
  if (!v.valid()) return errc::malformed_encoding;
  const std::size_t offset = open_element(*out_, t);
  put_base128(*out_, std::uint64_t{v[0]} * 40 + v[1]);
  for (std::size_t i = 2; i < v.size(); ++i) put_base128(*out_, v[i]);
  close_element(*out_, offset);
  return {};
}

namespace {
byte_view as_bytes(std::string_view s) noexcept {
  return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}
}  // namespace

void writer::write_visible_string(std::string_view v, tag t) { write_tlv(t, as_bytes(v)); }
void writer::write_utf8_string(std::string_view v, tag t) { write_tlv(t, as_bytes(v)); }
void writer::write_generalized_time(std::string_view v, tag t) { write_tlv(t, as_bytes(v)); }

}  // namespace openiec61850::ber
