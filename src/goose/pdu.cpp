#include "openiec61850/goose/pdu.hpp"

#include <limits>

#include "detail.hpp"
#include "openiec61850/ber/reader.hpp"
#include "openiec61850/ber/writer.hpp"

namespace openiec61850::goose {

namespace {

result<mms::data_view> validated_data(const ber::tlv& e) noexcept {
  return mms::data_view::unchecked(e);
}

}  // namespace

namespace detail {

result<std::uint32_t> read_u32(ber::reader& rd, ber::tag t) noexcept {
  auto v = rd.read_unsigned(t);
  if (!v) return v.error();
  if (*v > std::numeric_limits<std::uint32_t>::max()) return errc::value_out_of_range;
  return static_cast<std::uint32_t>(*v);
}

result<mms::utc_time> read_utc_time(ber::reader& rd, ber::tag t) noexcept {
  auto v = rd.read_octet_string(t);
  if (!v) return v.error();
  if (v->size() != 8) return errc::malformed_encoding;
  return mms::utc_time::from_bytes(std::span<const std::uint8_t, 8>(v->data(), 8));
}

result<std::optional<byte_view>> read_security(ber::reader& rd, std::uint32_t number) noexcept {
  auto t = rd.peek_tag();
  if (!t || !t->same_id(ber::context(number))) return std::optional<byte_view>{};
  auto e = rd.next();
  if (!e) return e.error();
  return std::optional<byte_view>{e->value};
}

}  // namespace detail

result<pdu_view> decode_pdu(byte_view apdu, const mms::decode_options& opts) noexcept {
  using ber::context;
  ber::reader top{apdu};
  auto rd = top.enter(ber::application(1, true));
  if (!rd) return rd.error();
  if (auto end = top.expect_end(); !end) return end.error();

  pdu_view p;
  auto gocb = rd->read_visible_string(context(0));
  if (!gocb) return gocb.error();
  p.gocb_ref = *gocb;
  auto tal = detail::read_u32(*rd, context(1));
  if (!tal) return tal.error();
  p.time_allowed_to_live = *tal;
  auto ds = rd->read_visible_string(context(2));
  if (!ds) return ds.error();
  p.dat_set = *ds;
  if (rd->next_is(context(3))) {
    auto id = rd->read_visible_string(context(3));
    if (!id) return id.error();
    p.go_id = *id;
  }
  auto t = detail::read_utc_time(*rd, context(4));
  if (!t) return t.error();
  p.t = *t;
  auto st = detail::read_u32(*rd, context(5));
  if (!st) return st.error();
  p.st_num = *st;
  auto sq = detail::read_u32(*rd, context(6));
  if (!sq) return sq.error();
  p.sq_num = *sq;
  if (rd->next_is(context(7))) {
    auto sim = rd->read_boolean(context(7));
    if (!sim) return sim.error();
    p.simulation = *sim;
  }
  auto cr = detail::read_u32(*rd, context(8));
  if (!cr) return cr.error();
  p.conf_rev = *cr;
  if (rd->next_is(context(9))) {
    auto nds = rd->read_boolean(context(9));
    if (!nds) return nds.error();
    p.nds_com = *nds;
  }
  auto n = detail::read_u32(*rd, context(10));
  if (!n) return n.error();
  p.num_dat_set_entries = *n;

  auto all = rd->enter(context(11, true));
  if (!all) return all.error();
  const byte_view contents = all->rest();
  while (!all->empty()) {
    auto e = all->next();
    if (!e) return e.error();
    auto v = mms::data_view::parse(*e, opts);
    if (!v) return v.error();
  }
  p.all_data = mms::list_view<mms::data_view>::encoded(contents, &validated_data);

  auto sec = detail::read_security(*rd, 12);
  if (!sec) return sec.error();
  p.security = *sec;
  if (auto end = rd->expect_end(); !end) return end.error();
  return p;
}

result<message_view> decode(byte_view frame, const mms::decode_options& opts) noexcept {
  auto f = decode_frame(frame);
  if (!f) return f.error();
  if (f->ether_type != ethertype_goose) return errc::unsupported;
  auto p = decode_pdu(f->apdu, opts);
  if (!p) return p.error();
  return message_view{*f, *p};
}

namespace {

template <typename Body>
result<void> encode_with(const pdu_fields& f, std::uint32_t count, byte_buffer& out, Body body) {
  using ber::context;
  ber::writer w{out};
  const auto pdu = w.begin(ber::application(1, true));
  w.write_visible_string(f.gocb_ref, context(0));
  w.write_unsigned(f.time_allowed_to_live, context(1));
  w.write_visible_string(f.dat_set, context(2));
  if (!f.go_id.empty()) w.write_visible_string(f.go_id, context(3));
  const auto t = f.t.to_bytes();
  w.write_octet_string(t, context(4));
  w.write_unsigned(f.st_num, context(5));
  w.write_unsigned(f.sq_num, context(6));
  w.write_boolean(f.simulation, context(7));
  w.write_unsigned(f.conf_rev, context(8));
  w.write_boolean(f.nds_com, context(9));
  w.write_unsigned(f.num_dat_set_entries.value_or(count), context(10));
  const auto all = w.begin(context(11, true));
  if (auto r = body(w); !r) return r;
  w.end(all);
  w.end(pdu);
  return {};
}

}  // namespace

result<void> encode_pdu(const pdu_fields& f, mms::list_view<mms::data_ref> values,
                        byte_buffer& out) {
  if (values.is_encoded()) {
    return encode_pdu_raw(f, values.encoded_contents(),
                          static_cast<std::uint32_t>(values.size()), out);
  }
  return encode_with(f, static_cast<std::uint32_t>(values.size()), out,
                     [&](ber::writer& w) -> result<void> {
                       for (const auto& v : values) {
                         if (auto r = v.encode(w); !r) return r;
                       }
                       return {};
                     });
}

result<void> encode_pdu_raw(const pdu_fields& f, byte_view all_data_contents, std::uint32_t count,
                            byte_buffer& out) {
  return encode_with(f, count, out, [&](ber::writer& w) -> result<void> {
    w.write_raw(all_data_contents);
    return {};
  });
}

result<void> encode(const frame_header& header, const pdu_fields& f,
                    mms::list_view<mms::data_ref> values, byte_buffer& out) {
  frame_header h = header;
  h.ether_type = ethertype_goose;
  const auto start = begin_frame(out, h);
  if (auto r = encode_pdu(f, values, out); !r) {
    out.resize(start);
    return r;
  }
  return finish_frame(out, start);
}

}  // namespace openiec61850::goose
