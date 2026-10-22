#include "openiec61850/iso/cotp/tpkt.hpp"

#include <algorithm>

namespace openiec61850::iso::cotp {

namespace {

std::size_t clamp_max(std::size_t max_length) noexcept {
  return std::clamp(max_length, tpkt_min_length, tpkt_max_length);
}

}  // namespace

result<std::size_t> decode_tpkt_header(byte_view header, std::size_t max_length) {
  if (header.size() < tpkt_header_size) return errc::truncated_input;
  // RFC 1006 §6: only version 3 is defined; the reserved octet is not checked.
  if (header[0] != tpkt_version) return errc::malformed_encoding;
  const std::size_t length = (std::size_t{header[2]} << 8) | header[3];
  if (length < tpkt_min_length) return errc::malformed_encoding;
  if (length > clamp_max(max_length)) return errc::length_overflow;
  return length;
}

result<void> encode_tpkt_header(std::size_t payload_size, byte_buffer& out) {
  if (payload_size > tpkt_max_length - tpkt_header_size) return errc::length_overflow;
  const std::size_t length = payload_size + tpkt_header_size;
  out.push_back(tpkt_version);
  out.push_back(0);
  out.push_back(static_cast<std::uint8_t>(length >> 8));
  out.push_back(static_cast<std::uint8_t>(length & 0xFF));
  return {};
}

tpkt_framer::tpkt_framer(std::size_t max_length) noexcept : max_length_(clamp_max(max_length)) {}

void tpkt_framer::set_max_length(std::size_t max_length) noexcept {
  max_length_ = clamp_max(max_length);
}

void tpkt_framer::consume_pending() noexcept {
  head_ += pending_;
  pending_ = 0;
}

void tpkt_framer::feed(byte_view data) {
  consume_pending();
  if (error_) return;
  if (head_ == buffer_.size()) {
    buffer_.clear();
    head_ = 0;
  } else if (head_ > 0) {
    buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(head_));
    head_ = 0;
  }
  buffer_.insert(buffer_.end(), data.begin(), data.end());
}

result<std::optional<byte_view>> tpkt_framer::next() {
  consume_pending();
  if (error_) return error_;
  const byte_view available = byte_view{buffer_}.subspan(head_);
  if (available.size() < tpkt_header_size) return std::optional<byte_view>{};
  auto length = decode_tpkt_header(available, max_length_);
  if (!length) {
    error_ = length.error();
    buffer_.clear();
    head_ = 0;
    return error_;
  }
  if (available.size() < *length) return std::optional<byte_view>{};
  pending_ = *length;
  return std::optional<byte_view>{available.subspan(tpkt_header_size, *length - tpkt_header_size)};
}

}  // namespace openiec61850::iso::cotp
