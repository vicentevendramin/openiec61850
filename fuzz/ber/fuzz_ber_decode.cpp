// Walks arbitrary input with ber::reader, runs every primitive decoder on every element and
// checks that canonical values re-encode to the same bytes.
// Seed corpus: fuzz/corpus/ber_decode/

#include <cstddef>
#include <cstdint>
#include <string>

#include "openiec61850/ber/ber.hpp"

namespace ber = openiec61850::ber;
using openiec61850::byte_buffer;
using openiec61850::byte_view;

namespace {

void check(bool condition) {
  if (!condition) __builtin_trap();
}

bool same(byte_view a, byte_view b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

// Contents of the single element that the writer just produced.
byte_view contents_of(const byte_buffer& encoded) {
  const auto r = ber::decode_tlv(encoded);
  check(r.has_value() && r->encoding.size() == encoded.size());
  return r->value;
}

void decode_primitives(const ber::tlv& e) {
  (void)ber::decode_boolean(e);
  (void)ber::decode_enumerated(e);
  (void)ber::decode_null(e);
  (void)ber::decode_octet_string(e);
  (void)ber::decode_visible_string(e);
  (void)ber::decode_utf8_string(e);
  (void)ber::decode_generalized_time(e);
  (void)ber::decode_integer_as<std::int16_t>(e.value);
  (void)ber::decode_integer_as<std::uint32_t>(e.value);

  // INTEGER and OID decoding is strict, so a decoded value must re-encode to the same contents.
  if (auto v = ber::decode_integer(e)) {
    byte_buffer out;
    ber::writer{out}.write_integer(*v, e.tag);
    check(same(contents_of(out), e.value));
  }
  if (auto v = ber::decode_unsigned(e)) {
    byte_buffer out;
    ber::writer{out}.write_unsigned(*v, e.tag);
    check(same(contents_of(out), e.value));
  }
  if (auto v = ber::decode_oid(e)) {
    byte_buffer out;
    ber::writer w{out};
    check(static_cast<bool>(w.write_oid(*v, e.tag)));
    check(same(contents_of(out), e.value));
    const auto text = v->to_string();
    const auto parsed = ber::oid::from_string(text);
    check(parsed.has_value() && *parsed == *v);
  }
  if (auto bits = ber::decode_bit_string(e)) {
    check(bits->bit_count <= bits->bytes.size() * 8);
    if (bits->bit_count > 0) (void)bits->test(bits->bit_count - 1);
    byte_buffer out;
    check(static_cast<bool>(ber::writer{out}.write_bit_string(bits->bytes, bits->bit_count)));
  }
}

void walk(ber::reader rd) {
  while (!rd.empty()) {
    const auto t = rd.peek_tag();
    auto e = rd.next();
    if (!e) return;
    check(t.has_value() && *t == e->tag);
    check(e->encoding.size() == e->header_size() + e->value.size() + (e->indefinite ? 2 : 0));
    decode_primitives(*e);
    if (e->constructed()) {
      if (auto child = rd.enter(*e)) walk(*child);
    }
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const byte_view input{data, size};
  walk(ber::reader{input});
  walk(ber::reader{input, {.max_depth = 4}});
  return 0;
}
