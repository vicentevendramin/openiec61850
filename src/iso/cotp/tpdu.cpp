#include "openiec61850/iso/cotp/tpdu.hpp"

#include "openiec61850/iso/cotp/tpkt.hpp"

namespace openiec61850::iso::cotp {

namespace {

constexpr std::size_t max_li = 254;  // X.224 §13.2.1: 255 is reserved
constexpr std::size_t max_parameter_length = 255;

std::uint16_t read_u16(byte_view in, std::size_t offset) noexcept {
  return static_cast<std::uint16_t>((in[offset] << 8) | in[offset + 1]);
}

void write_u16(std::uint16_t value, byte_buffer& out) {
  out.push_back(static_cast<std::uint8_t>(value >> 8));
  out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

// Walks the variable part (X.224 §13.2.3): code, length, value triplets.
template <typename Fn>
result<void> for_each_parameter(byte_view vp, Fn&& fn) {
  while (!vp.empty()) {
    if (vp.size() < 2) return errc::length_overflow;
    const std::uint8_t code = vp[0];
    const std::size_t length = vp[1];
    if (vp.size() - 2 < length) return errc::length_overflow;
    if (auto r = fn(code, vp.subspan(2, length)); !r) return r;
    vp = vp.subspan(2 + length);
  }
  return {};
}

byte_buffer to_buffer(byte_view v) { return {v.begin(), v.end()}; }

// Accumulates the variable part so its length can be validated before writing.
class parameter_writer {
 public:
  void add(std::uint8_t code, byte_view value) {
    if (value.size() > max_parameter_length) {
      error_ = true;
      return;
    }
    bytes_.push_back(code);
    bytes_.push_back(static_cast<std::uint8_t>(value.size()));
    bytes_.insert(bytes_.end(), value.begin(), value.end());
  }
  void add(const std::vector<tpdu_parameter>& params) {
    for (const auto& p : params) add(p.code, p.value);
  }
  [[nodiscard]] bool failed() const noexcept { return error_; }
  [[nodiscard]] const byte_buffer& bytes() const noexcept { return bytes_; }

 private:
  byte_buffer bytes_;
  bool error_ = false;
};

result<std::uint8_t> header_li(std::size_t fixed, const parameter_writer& vp) {
  if (vp.failed()) return errc::length_overflow;
  const std::size_t li = fixed + vp.bytes().size();
  if (li > max_li) return errc::length_overflow;
  return static_cast<std::uint8_t>(li);
}

result<void> decode_connect(byte_view header, byte_view data, connect_tpdu& t) {
  // X.224 §13.3.1: LI, CR/CC+CDT, DST-REF, SRC-REF, class and options.
  if (header.size() < 7) return errc::malformed_encoding;
  t.credit = static_cast<std::uint8_t>(header[1] & 0x0F);
  t.dst_ref = read_u16(header, 2);
  t.src_ref = read_u16(header, 4);
  t.class_options = header[6];
  auto r = for_each_parameter(header.subspan(7), [&](std::uint8_t code, byte_view value) -> result<void> {
    switch (code) {
      case parameter_code::tpdu_size:
        if (value.size() != 1 || !tpdu_size_from_code(value[0])) return errc::malformed_encoding;
        t.tpdu_size = value[0];
        break;
      case parameter_code::calling_tsap:
        t.calling_tsap = to_buffer(value);
        break;
      case parameter_code::called_tsap:
        t.called_tsap = to_buffer(value);
        break;
      default:
        t.other_parameters.push_back({code, to_buffer(value)});
        break;
    }
    return {};
  });
  if (!r) return r;
  t.user_data = to_buffer(data);
  return {};
}

result<void> encode_connect(std::uint8_t code, const connect_tpdu& t, byte_buffer& out) {
  parameter_writer vp;
  if (t.calling_tsap) vp.add(parameter_code::calling_tsap, *t.calling_tsap);
  if (t.called_tsap) vp.add(parameter_code::called_tsap, *t.called_tsap);
  if (t.tpdu_size) {
    const std::uint8_t size = *t.tpdu_size;
    vp.add(parameter_code::tpdu_size, byte_view{&size, 1});
  }
  vp.add(t.other_parameters);
  auto li = header_li(6, vp);
  if (!li) return li.error();
  out.push_back(*li);
  out.push_back(static_cast<std::uint8_t>(code | (t.credit & 0x0F)));
  write_u16(t.dst_ref, out);
  write_u16(t.src_ref, out);
  out.push_back(t.class_options);
  out.insert(out.end(), vp.bytes().begin(), vp.bytes().end());
  out.insert(out.end(), t.user_data.begin(), t.user_data.end());
  return {};
}

}  // namespace

std::optional<tpdu_kind> tpdu_kind_of(std::uint8_t code) noexcept {
  const auto high = static_cast<std::uint8_t>(code & 0xF0);
  const bool low_zero = (code & 0x0F) == 0;
  switch (high) {
    // The low nibble carries CDT (CR, CC, AK, RJ), or ROA/flags (DT, ED).
    case 0xE0: return tpdu_kind::cr;
    case 0xD0: return tpdu_kind::cc;
    case 0xF0: return tpdu_kind::dt;
    case 0x10: return tpdu_kind::ed;
    case 0x60: return tpdu_kind::ak;
    case 0x50: return tpdu_kind::rj;
    case 0x80: return low_zero ? std::optional{tpdu_kind::dr} : std::nullopt;
    case 0xC0: return low_zero ? std::optional{tpdu_kind::dc} : std::nullopt;
    case 0x20: return low_zero ? std::optional{tpdu_kind::ea} : std::nullopt;
    case 0x70: return low_zero ? std::optional{tpdu_kind::er} : std::nullopt;
    default: return std::nullopt;
  }
}

std::optional<std::size_t> tpdu_size_from_code(std::uint8_t code) noexcept {
  if (code < 7 || code > 13) return std::nullopt;
  return std::size_t{1} << code;
}

std::optional<std::uint8_t> tpdu_size_code(std::size_t size) noexcept {
  for (std::uint8_t code = 7; code <= 13; ++code) {
    if ((std::size_t{1} << code) == size) return code;
  }
  return std::nullopt;
}

result<tpdu> decode_tpdu(byte_view in) {
  if (in.size() < 2) return errc::truncated_input;
  // X.224 §13.2.1: LI counts the header octets after itself.
  const std::size_t li = in[0];
  if (li == 0 || li > max_li) return errc::malformed_encoding;
  if (li >= in.size()) return errc::length_overflow;
  const byte_view header = in.first(li + 1);
  const byte_view data = in.subspan(li + 1);

  const auto kind = tpdu_kind_of(in[1]);
  if (!kind) return errc::malformed_encoding;
  switch (*kind) {
    case tpdu_kind::cr: {
      connection_request t;
      if (auto r = decode_connect(header, data, t); !r) return r.error();
      return tpdu{std::move(t)};
    }
    case tpdu_kind::cc: {
      connection_confirm t;
      if (auto r = decode_connect(header, data, t); !r) return r.error();
      return tpdu{std::move(t)};
    }
    case tpdu_kind::dr: {
      // X.224 §13.5.1: LI, DR, DST-REF, SRC-REF, reason.
      if (header.size() < 7) return errc::malformed_encoding;
      disconnect_request t;
      t.dst_ref = read_u16(header, 2);
      t.src_ref = read_u16(header, 4);
      t.reason = header[6];
      auto r = for_each_parameter(header.subspan(7), [&](std::uint8_t code, byte_view value) -> result<void> {
        t.parameters.push_back({code, to_buffer(value)});
        return {};
      });
      if (!r) return r.error();
      t.user_data = to_buffer(data);
      return tpdu{std::move(t)};
    }
    case tpdu_kind::dt: {
      // X.224 §13.7.1, normal format for classes 0 and 1: LI = 2, no variable part.
      if (li != 2 || (in[1] & 0x0F) != 0) return errc::malformed_encoding;
      data_tpdu t;
      t.eot = (header[2] & 0x80) != 0;
      t.nr = static_cast<std::uint8_t>(header[2] & 0x7F);
      t.user_data = data;
      return tpdu{t};
    }
    case tpdu_kind::er: {
      // X.224 §13.12.1: LI, ER, DST-REF, reject cause; no user data.
      if (header.size() < 5 || !data.empty()) return errc::malformed_encoding;
      error_tpdu t;
      t.dst_ref = read_u16(header, 2);
      t.cause = header[4];
      auto r = for_each_parameter(header.subspan(5), [&](std::uint8_t code, byte_view value) -> result<void> {
        if (code == parameter_code::invalid_tpdu) {
          t.invalid_tpdu = to_buffer(value);
        } else {
          t.other_parameters.push_back({code, to_buffer(value)});
        }
        return {};
      });
      if (!r) return r.error();
      return tpdu{std::move(t)};
    }
    case tpdu_kind::dc:
    case tpdu_kind::ed:
    case tpdu_kind::ak:
    case tpdu_kind::ea:
    case tpdu_kind::rj:
      return errc::unsupported;
  }
  return errc::malformed_encoding;
}

result<void> encode(const connection_request& t, byte_buffer& out) {
  return encode_connect(static_cast<std::uint8_t>(tpdu_kind::cr), t, out);
}

result<void> encode(const connection_confirm& t, byte_buffer& out) {
  return encode_connect(static_cast<std::uint8_t>(tpdu_kind::cc), t, out);
}

result<void> encode(const disconnect_request& t, byte_buffer& out) {
  parameter_writer vp;
  vp.add(t.parameters);
  auto li = header_li(6, vp);
  if (!li) return li.error();
  out.push_back(*li);
  out.push_back(static_cast<std::uint8_t>(tpdu_kind::dr));
  write_u16(t.dst_ref, out);
  write_u16(t.src_ref, out);
  out.push_back(t.reason);
  out.insert(out.end(), vp.bytes().begin(), vp.bytes().end());
  out.insert(out.end(), t.user_data.begin(), t.user_data.end());
  return {};
}

result<void> encode(const data_tpdu& t, byte_buffer& out) {
  out.push_back(2);
  out.push_back(static_cast<std::uint8_t>(tpdu_kind::dt));
  out.push_back(static_cast<std::uint8_t>((t.eot ? 0x80 : 0x00) | (t.nr & 0x7F)));
  out.insert(out.end(), t.user_data.begin(), t.user_data.end());
  return {};
}

result<void> encode(const error_tpdu& t, byte_buffer& out) {
  parameter_writer vp;
  if (t.invalid_tpdu) vp.add(parameter_code::invalid_tpdu, *t.invalid_tpdu);
  vp.add(t.other_parameters);
  auto li = header_li(4, vp);
  if (!li) return li.error();
  out.push_back(*li);
  out.push_back(static_cast<std::uint8_t>(tpdu_kind::er));
  write_u16(t.dst_ref, out);
  out.push_back(t.cause);
  out.insert(out.end(), vp.bytes().begin(), vp.bytes().end());
  return {};
}

result<void> encode(const tpdu& t, byte_buffer& out) {
  return std::visit([&](const auto& v) { return encode(v, out); }, t);
}

result<void> encode_tpkt(const tpdu& t, byte_buffer& out) {
  const std::size_t start = out.size();
  out.resize(start + tpkt_header_size);
  if (auto r = encode(t, out); !r) {
    out.resize(start);
    return r;
  }
  const std::size_t length = out.size() - start;
  if (length > tpkt_max_length) {
    out.resize(start);
    return errc::length_overflow;
  }
  out[start] = tpkt_version;
  out[start + 1] = 0;
  out[start + 2] = static_cast<std::uint8_t>(length >> 8);
  out[start + 3] = static_cast<std::uint8_t>(length & 0xFF);
  return {};
}

}  // namespace openiec61850::iso::cotp
