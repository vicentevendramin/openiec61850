#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"

namespace openiec61850::iso::cotp {

// RFC 1006 §6: version (3), reserved (0), 16-bit big-endian length including the header.
inline constexpr std::size_t tpkt_header_size = 4;
inline constexpr std::uint8_t tpkt_version = 3;
inline constexpr std::size_t tpkt_max_length = 65535;
// Header plus the smallest TPDU (a class 0 DT header: LI, code, EOT/NR).
inline constexpr std::size_t tpkt_min_length = tpkt_header_size + 3;

// Validates a TPKT header and returns the total packet length (header included).
[[nodiscard]] result<std::size_t> decode_tpkt_header(byte_view header,
                                                     std::size_t max_length = tpkt_max_length);

// Appends a TPKT header for a payload of payload_size octets.
[[nodiscard]] result<void> encode_tpkt_header(std::size_t payload_size, byte_buffer& out);

// Reassembles TPKT packets from a byte stream split at arbitrary boundaries.
// A framing error is fatal: the stream cannot be resynchronised, so every later
// call to next() returns the same error.
class tpkt_framer {
 public:
  explicit tpkt_framer(std::size_t max_length = tpkt_max_length) noexcept;

  // Upper bound for the TPKT length field, clamped to [tpkt_min_length, tpkt_max_length].
  void set_max_length(std::size_t max_length) noexcept;
  [[nodiscard]] std::size_t max_length() const noexcept { return max_length_; }

  // Appends received bytes. Invalidates the view returned by the previous next().
  void feed(byte_view data);

  // Returns the payload (TPDU) of the next complete packet, std::nullopt if more
  // bytes are needed, or the framing error. The view stays valid until the next
  // call to next() or feed().
  [[nodiscard]] result<std::optional<byte_view>> next();

  [[nodiscard]] std::size_t buffered() const noexcept { return buffer_.size() - head_; }
  [[nodiscard]] std::error_code error() const noexcept { return error_; }

 private:
  void consume_pending() noexcept;

  byte_buffer buffer_;
  std::size_t head_ = 0;     // start of unread data in buffer_
  std::size_t pending_ = 0;  // length of the packet handed out by the last next()
  std::size_t max_length_;
  std::error_code error_;
};

}  // namespace openiec61850::iso::cotp
