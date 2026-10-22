#include "openiec61850/mms/type_description.hpp"

#include "openiec61850/ber/reader.hpp"

namespace openiec61850::mms {
namespace {

constexpr ber::tag ctx(data_type t, bool constructed = false) noexcept {
  return ber::context(static_cast<std::uint32_t>(t), constructed);
}

result<type_description> decode_description(const ber::tlv& e, const decode_options& opts,
                                            std::size_t depth);

// The single element inside an explicit [n] TypeSpecification tag.
result<type_description> decode_specification(const ber::tlv& wrapper, const decode_options& opts,
                                              std::size_t depth) {
  ber::reader rd{wrapper.value};
  auto inner = rd.next();
  if (!inner) return inner.error();
  if (auto r = rd.expect_end(); !r) return r.error();
  if (inner->tag == ber::context(0, true)) return errc::unsupported;  // typeName
  return decode_description(*inner, opts, depth);
}

result<bool> read_packed(ber::reader& rd) {
  if (!rd.next_is(ber::context(0))) return false;
  return rd.read_boolean(ber::context(0));
}

template <typename T>
result<T> primitive_integer(const ber::tlv& e) {
  if (e.tag.constructed) return errc::malformed_encoding;
  return ber::decode_integer_as<T>(e.value);
}

result<type_description> decode_description(const ber::tlv& e, const decode_options& opts,
                                            std::size_t depth) {
  if (e.tag.cls != ber::tag_class::context || e.tag.number > 17) return errc::malformed_encoding;
  type_description d;
  d.type = static_cast<data_type>(e.tag.number);
  switch (d.type) {
    case data_type::array: {
      if (!e.tag.constructed) return errc::malformed_encoding;
      if (depth >= opts.max_nesting) return errc::nesting_too_deep;
      ber::reader rd{e.value};
      auto packed = read_packed(rd);
      if (!packed) return packed.error();
      d.packed = *packed;
      auto n = rd.read_unsigned(ber::context(1));
      if (!n) return n.error();
      if (*n > std::numeric_limits<std::uint32_t>::max()) return errc::value_out_of_range;
      d.number_of_elements = static_cast<std::uint32_t>(*n);
      auto elem = rd.expect(ber::context(2, true));
      if (!elem) return elem.error();
      auto t = decode_specification(*elem, opts, depth + 1);
      if (!t) return t.error();
      d.components.push_back({{}, std::move(*t)});
      if (auto r = rd.expect_end(); !r) return r.error();
      return d;
    }
    case data_type::structure: {
      if (!e.tag.constructed) return errc::malformed_encoding;
      if (depth >= opts.max_nesting) return errc::nesting_too_deep;
      ber::reader rd{e.value};
      auto packed = read_packed(rd);
      if (!packed) return packed.error();
      d.packed = *packed;
      auto list = rd.enter(ber::context(1, true));
      if (!list) return list.error();
      while (!list->empty()) {
        auto seq = list->enter(ber::tags::sequence);
        if (!seq) return seq.error();
        type_component c;
        if (seq->next_is(ber::context(0))) {
          auto name = seq->read_visible_string(ber::context(0));
          if (!name) return name.error();
          c.name = std::string(*name);
        }
        auto type = seq->expect(ber::context(1, true));
        if (!type) return type.error();
        auto t = decode_specification(*type, opts, depth + 1);
        if (!t) return t.error();
        c.type = std::move(*t);
        if (auto r = seq->expect_end(); !r) return r.error();
        d.components.push_back(std::move(c));
      }
      if (auto r = rd.expect_end(); !r) return r.error();
      return d;
    }
    case data_type::boolean:
    case data_type::generalized_time:
    case data_type::obj_id:
    case data_type::utc_time:
      if (auto r = ber::decode_null(e); !r) return r.error();
      return d;
    case data_type::bit_string:
    case data_type::octet_string:
    case data_type::visible_string:
    case data_type::mms_string: {
      auto v = primitive_integer<std::int32_t>(e);
      if (!v) return v.error();
      d.size = *v;
      return d;
    }
    case data_type::integer:
    case data_type::unsigned_:
    case data_type::bcd: {
      auto v = primitive_integer<std::uint8_t>(e);
      if (!v) return v.error();
      d.size = *v;
      return d;
    }
    case data_type::floating_point: {
      if (!e.tag.constructed) return errc::malformed_encoding;
      ber::reader rd{e.value};
      auto fw = rd.read_unsigned();
      if (!fw) return fw.error();
      auto ew = rd.read_unsigned();
      if (!ew) return ew.error();
      if (*fw > 0xFF || *ew > 0xFF) return errc::value_out_of_range;
      if (auto r = rd.expect_end(); !r) return r.error();
      d.format_width = static_cast<std::uint8_t>(*fw);
      d.exponent_width = static_cast<std::uint8_t>(*ew);
      return d;
    }
    case data_type::binary_time: {
      auto v = ber::decode_boolean(e);
      if (!v) return v.error();
      d.with_date = *v;
      return d;
    }
    case data_type::boolean_array:
    case data_type::invalid:
      return errc::malformed_encoding;
  }
  return e.tag.number == 8 ? errc::unsupported : errc::malformed_encoding;
}

bool same(const type_description& a, const type_description& b) noexcept {
  if (a.type != b.type || a.packed != b.packed || a.size != b.size ||
      a.format_width != b.format_width || a.exponent_width != b.exponent_width ||
      a.with_date != b.with_date || a.number_of_elements != b.number_of_elements ||
      a.components.size() != b.components.size()) {
    return false;
  }
  for (std::size_t i = 0; i < a.components.size(); ++i) {
    if (!(a.components[i] == b.components[i])) return false;
  }
  return true;
}

type_description simple(data_type t, std::int32_t size = 0) {
  type_description d;
  d.type = t;
  d.size = size;
  return d;
}

}  // namespace

type_description type_description::boolean() { return simple(data_type::boolean); }
type_description type_description::bit_string(std::int32_t size) {
  return simple(data_type::bit_string, size);
}
type_description type_description::integer(std::uint8_t width) {
  return simple(data_type::integer, width);
}
type_description type_description::unsigned_integer(std::uint8_t width) {
  return simple(data_type::unsigned_, width);
}
type_description type_description::float32() {
  auto d = simple(data_type::floating_point);
  d.format_width = 32;
  d.exponent_width = 8;
  return d;
}
type_description type_description::float64() {
  auto d = simple(data_type::floating_point);
  d.format_width = 64;
  d.exponent_width = 11;
  return d;
}
type_description type_description::octet_string(std::int32_t size) {
  return simple(data_type::octet_string, size);
}
type_description type_description::visible_string(std::int32_t size) {
  return simple(data_type::visible_string, size);
}
type_description type_description::generalized_time() {
  return simple(data_type::generalized_time);
}
type_description type_description::binary_time(bool with_date) {
  auto d = simple(data_type::binary_time);
  d.with_date = with_date;
  return d;
}
type_description type_description::bcd(std::uint8_t width) {
  return simple(data_type::bcd, width);
}
type_description type_description::obj_id() { return simple(data_type::obj_id); }
type_description type_description::mms_string(std::int32_t size) {
  return simple(data_type::mms_string, size);
}
type_description type_description::utc_time() { return simple(data_type::utc_time); }
type_description type_description::array(std::uint32_t number_of_elements,
                                         type_description element) {
  auto d = simple(data_type::array);
  d.number_of_elements = number_of_elements;
  d.components.push_back({{}, std::move(element)});
  return d;
}
type_description type_description::structure(std::vector<type_component> components) {
  auto d = simple(data_type::structure);
  d.components = std::move(components);
  return d;
}

result<type_description> type_description::decode(const ber::tlv& element,
                                                  const decode_options& opts) {
  if (element.tag == ber::context(0, true)) return errc::unsupported;  // typeName
  return decode_description(element, opts, 0);
}

result<type_description> type_description::decode(byte_view encoding,
                                                  const decode_options& opts) {
  auto e = ber::decode_tlv(encoding);
  if (!e) return e.error();
  if (e->encoding.size() != encoding.size()) return errc::malformed_encoding;
  return decode(*e, opts);
}

result<void> type_description::encode(ber::writer& w) const {
  switch (type) {
    case data_type::array: {
      if (components.size() != 1) return errc::invalid_state;
      const auto m = w.begin(ctx(type, true));
      if (packed) w.write_boolean(true, ber::context(0));
      w.write_unsigned(number_of_elements, ber::context(1));
      const auto t = w.begin(ber::context(2, true));
      if (auto r = components.front().type.encode(w); !r) return r;
      w.end(t);
      w.end(m);
      return {};
    }
    case data_type::structure: {
      const auto m = w.begin(ctx(type, true));
      if (packed) w.write_boolean(true, ber::context(0));
      const auto list = w.begin(ber::context(1, true));
      for (const auto& c : components) {
        const auto seq = w.begin(ber::tags::sequence);
        if (!c.name.empty()) w.write_visible_string(c.name, ber::context(0));
        const auto t = w.begin(ber::context(1, true));
        if (auto r = c.type.encode(w); !r) return r;
        w.end(t);
        w.end(seq);
      }
      w.end(list);
      w.end(m);
      return {};
    }
    case data_type::boolean:
    case data_type::generalized_time:
    case data_type::obj_id:
    case data_type::utc_time:
      w.write_null(ctx(type));
      return {};
    case data_type::bit_string:
    case data_type::octet_string:
    case data_type::visible_string:
    case data_type::mms_string:
      w.write_integer(size, ctx(type));
      return {};
    case data_type::integer:
    case data_type::unsigned_:
    case data_type::bcd:
      if (size < 0 || size > 0xFF) return errc::invalid_state;
      w.write_integer(size, ctx(type));
      return {};
    case data_type::floating_point: {
      const auto m = w.begin(ctx(type, true));
      w.write_unsigned(format_width);
      w.write_unsigned(exponent_width);
      w.end(m);
      return {};
    }
    case data_type::binary_time:
      w.write_boolean(with_date, ctx(type));
      return {};
    case data_type::boolean_array:
    case data_type::invalid:
      break;
  }
  return errc::invalid_state;
}

bool operator==(const type_description& a, const type_description& b) noexcept {
  return same(a, b);
}

bool operator==(const type_component& a, const type_component& b) noexcept {
  return a.name == b.name && a.type == b.type;
}

}  // namespace openiec61850::mms
