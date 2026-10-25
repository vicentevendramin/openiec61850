#include "openiec61850/goose/sv.hpp"

#include <bit>
#include <cmath>
#include <limits>

#include "detail.hpp"
#include "openiec61850/ber/reader.hpp"
#include "openiec61850/ber/writer.hpp"

namespace openiec61850::sv {

namespace {

using ber::context;

std::uint32_t load_be(byte_view b) noexcept {
  std::uint32_t v = 0;
  for (auto c : b) v = (v << 8) | c;
  return v;
}

// A fixed-size OCTET STRING holding a big-endian unsigned integer.
template <typename T>
result<T> read_fixed(ber::reader& rd, ber::tag t, std::size_t size) noexcept {
  auto v = rd.read_octet_string(t);
  if (!v) return v.error();
  if (v->size() != size) return errc::malformed_encoding;
  return static_cast<T>(load_be(*v));
}

result<asdu_view> decode_asdu_checked(const ber::tlv& element) noexcept {
  if (element.tag != ber::tags::sequence) return errc::malformed_encoding;
  ber::reader rd{element.value};
  asdu_view a;
  auto id = rd.read_visible_string(context(0));
  if (!id) return id.error();
  a.sv_id = *id;
  if (rd.next_is(context(1))) {
    auto ds = rd.read_visible_string(context(1));
    if (!ds) return ds.error();
    a.dat_set = *ds;
  }
  auto cnt = read_fixed<std::uint16_t>(rd, context(2), 2);
  if (!cnt) return cnt.error();
  a.smp_cnt = *cnt;
  auto cr = read_fixed<std::uint32_t>(rd, context(3), 4);
  if (!cr) return cr.error();
  a.conf_rev = *cr;
  if (rd.next_is(context(4))) {
    auto t = goose::detail::read_utc_time(rd, context(4));
    if (!t) return t.error();
    a.refr_tm = *t;
  }
  auto synch = read_fixed<std::uint8_t>(rd, context(5), 1);
  if (!synch) return synch.error();
  a.smp_synch = *synch;
  if (rd.next_is(context(6))) {
    auto rate = read_fixed<std::uint16_t>(rd, context(6), 2);
    if (!rate) return rate.error();
    a.smp_rate = *rate;
  }
  auto data = rd.read_octet_string(context(7));
  if (!data) return data.error();
  a.seq_data = *data;
  if (rd.next_is(context(8))) {
    auto mod = read_fixed<std::uint16_t>(rd, context(8), 2);
    if (!mod) return mod.error();
    a.smp_mod = *mod;
  }
  if (rd.next_is(context(9))) {
    auto gm = rd.read_octet_string(context(9));
    if (!gm) return gm.error();
    if (gm->size() != 8) return errc::malformed_encoding;
    std::array<std::uint8_t, 8> id8{};
    for (std::size_t i = 0; i < 8; ++i) id8[i] = (*gm)[i];
    a.gm_identity = id8;
  }
  if (auto end = rd.expect_end(); !end) return end.error();
  return a;
}

void store_be(byte_buffer& out, std::uint32_t v, std::size_t size) {
  for (std::size_t i = size; i-- > 0;) {
    out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFU));
  }
}

void write_fixed(ber::writer& w, ber::tag t, std::uint32_t v, std::size_t size) {
  std::array<std::uint8_t, 4> b{};
  for (std::size_t i = 0; i < size; ++i) {
    b[i] = static_cast<std::uint8_t>((v >> (8 * (size - 1 - i))) & 0xFFU);
  }
  w.write_octet_string(byte_view{b.data(), size}, t);
}

std::int32_t saturate(double v) noexcept {
  if (std::isnan(v)) return 0;
  const double r = std::nearbyint(v);
  if (r >= static_cast<double>(std::numeric_limits<std::int32_t>::max())) {
    return std::numeric_limits<std::int32_t>::max();
  }
  if (r <= static_cast<double>(std::numeric_limits<std::int32_t>::min())) {
    return std::numeric_limits<std::int32_t>::min();
  }
  return static_cast<std::int32_t>(r);
}

}  // namespace

result<asdu_view> decode_asdu(const ber::tlv& element) noexcept {
  return decode_asdu_checked(element);
}

result<pdu_view> decode_pdu(byte_view apdu) noexcept {
  ber::reader top{apdu};
  auto rd = top.enter(ber::application(0, true));
  if (!rd) return rd.error();
  if (auto end = top.expect_end(); !end) return end.error();

  pdu_view p;
  auto n = rd->read_unsigned(context(0));
  if (!n) return n.error();
  if (*n == 0 || *n > 0xFFFF) return errc::malformed_encoding;
  p.no_asdu = static_cast<std::uint16_t>(*n);
  auto sec = goose::detail::read_security(*rd, 1);
  if (!sec) return sec.error();
  p.security = *sec;
  auto seq = rd->enter(context(2, true));
  if (!seq) return seq.error();
  const byte_view contents = seq->rest();
  std::size_t count = 0;
  while (!seq->empty()) {
    auto e = seq->next();
    if (!e) return e.error();
    auto a = decode_asdu_checked(*e);
    if (!a) return a.error();
    ++count;
  }
  if (count != p.no_asdu) return errc::malformed_encoding;
  p.asdus = mms::list_view<asdu_view>::encoded(contents, &decode_asdu);
  if (auto end = rd->expect_end(); !end) return end.error();
  return p;
}

result<message_view> decode(byte_view frame) noexcept {
  auto f = goose::decode_frame(frame);
  if (!f) return f.error();
  if (f->ether_type != goose::ethertype_sv) return errc::unsupported;
  auto p = decode_pdu(f->apdu);
  if (!p) return p.error();
  return message_view{*f, *p};
}

result<void> encode_pdu(std::span<const asdu> asdus, byte_buffer& out) {
  if (asdus.empty() || asdus.size() > 0xFFFF) return errc::invalid_state;
  ber::writer w{out};
  const auto pdu = w.begin(ber::application(0, true));
  w.write_unsigned(asdus.size(), context(0));
  const auto seq = w.begin(context(2, true));
  for (const auto& a : asdus) {
    const auto s = w.begin(ber::tags::sequence);
    w.write_visible_string(a.sv_id, context(0));
    if (a.dat_set) w.write_visible_string(*a.dat_set, context(1));
    write_fixed(w, context(2), a.smp_cnt, 2);
    write_fixed(w, context(3), a.conf_rev, 4);
    if (a.refr_tm) {
      const auto t = a.refr_tm->to_bytes();
      w.write_octet_string(t, context(4));
    }
    write_fixed(w, context(5), a.smp_synch, 1);
    if (a.smp_rate) write_fixed(w, context(6), *a.smp_rate, 2);
    w.write_octet_string(a.seq_data, context(7));
    if (a.smp_mod) write_fixed(w, context(8), *a.smp_mod, 2);
    if (a.gm_identity) w.write_octet_string(*a.gm_identity, context(9));
    w.end(s);
  }
  w.end(seq);
  w.end(pdu);
  return {};
}

result<void> encode(const frame_header& header, std::span<const asdu> asdus, byte_buffer& out) {
  frame_header h = header;
  h.ether_type = goose::ethertype_sv;
  const auto start = goose::begin_frame(out, h);
  if (auto r = encode_pdu(asdus, out); !r) {
    out.resize(start);
    return r;
  }
  return goose::finish_frame(out, start);
}

// ------------------------------------------------------------------ fixed-length values

std::int32_t load_int32(byte_view data, std::size_t offset) noexcept {
  return static_cast<std::int32_t>(load_uint32(data, offset));
}

std::uint32_t load_uint32(byte_view data, std::size_t offset) noexcept {
  return load_be(data.subspan(offset, 4));
}

float load_float32(byte_view data, std::size_t offset) noexcept {
  return std::bit_cast<float>(load_uint32(data, offset));
}

void store_int32(byte_buffer& out, std::int32_t v) {
  store_be(out, static_cast<std::uint32_t>(v), 4);
}

void store_uint32(byte_buffer& out, std::uint32_t v) { store_be(out, v, 4); }

void store_float32(byte_buffer& out, float v) { store_be(out, std::bit_cast<std::uint32_t>(v), 4); }

result<std::size_t> decode_analog_samples(byte_view seq_data,
                                          std::span<analog_sample> out) noexcept {
  if (seq_data.size() % 8 != 0) return errc::malformed_encoding;
  const std::size_t n = seq_data.size() / 8;
  if (n > out.size()) return errc::buffer_too_small;
  for (std::size_t i = 0; i < n; ++i) {
    out[i].value = load_int32(seq_data, i * 8);
    out[i].q.raw = load_uint32(seq_data, i * 8 + 4);
  }
  return n;
}

void encode_analog_samples(std::span<const analog_sample> samples, byte_buffer& out) {
  out.reserve(out.size() + samples.size() * 8);
  for (const auto& s : samples) {
    store_int32(out, s.value);
    store_uint32(out, s.q.raw);
  }
}

namespace le {

void samples::set_current(std::size_t i, double amperes, quality32 q) noexcept {
  channels[i] = {saturate(amperes / amperes_per_lsb), q};
}

void samples::set_voltage(std::size_t i, double volts, quality32 q) noexcept {
  channels[4 + i] = {saturate(volts / volts_per_lsb), q};
}

std::array<std::uint8_t, seq_data_size> encode(const samples& s) noexcept {
  std::array<std::uint8_t, seq_data_size> out{};
  std::size_t o = 0;
  auto put = [&](std::uint32_t v) {
    for (int sh = 24; sh >= 0; sh -= 8) out[o++] = static_cast<std::uint8_t>((v >> sh) & 0xFFU);
  };
  for (const auto& c : s.channels) {
    put(static_cast<std::uint32_t>(c.value));
    put(c.q.raw);
  }
  return out;
}

result<samples> decode(byte_view seq_data) noexcept {
  if (seq_data.size() != seq_data_size) return errc::malformed_encoding;
  samples s;
  auto n = decode_analog_samples(seq_data, s.channels);
  if (!n) return n.error();
  return s;
}

}  // namespace le

}  // namespace openiec61850::sv
