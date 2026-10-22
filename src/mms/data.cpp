#include "openiec61850/mms/data.hpp"

#include <algorithm>
#include <bit>

#include "detail.hpp"

namespace openiec61850::mms {
namespace {

constexpr ber::tag ctx(data_type t, bool constructed = false) noexcept {
  return ber::context(static_cast<std::uint32_t>(t), constructed);
}

std::uint64_t get_be(byte_view b) noexcept {
  std::uint64_t v = 0;
  for (auto x : b) v = (v << 8) | x;
  return v;
}

template <std::size_t N>
void put_be(std::array<std::uint8_t, N>& out, std::size_t offset, std::uint64_t v,
            std::size_t n) noexcept {
  for (std::size_t i = 0; i < n; ++i) {
    out[offset + i] = static_cast<std::uint8_t>(v >> (8 * (n - 1 - i)));
  }
}

constexpr std::uint8_t exponent_width_single = 8;
constexpr std::uint8_t exponent_width_double = 11;

bool is_single(byte_view c) noexcept { return c.size() == 5 && c[0] == exponent_width_single; }
bool is_double_fp(byte_view c) noexcept { return c.size() == 9 && c[0] == exponent_width_double; }

binary_time decode_binary_time(byte_view c) noexcept {
  binary_time t;
  t.ms_of_day = static_cast<std::uint32_t>(get_be(c.first(4)));
  if (c.size() == 6) t.days = static_cast<std::uint16_t>(get_be(c.subspan(4)));
  return t;
}

void write_binary_time(ber::writer& w, const binary_time& t) {
  std::array<std::uint8_t, 6> b{};
  put_be(b, 0, t.ms_of_day, 4);
  std::size_t n = 4;
  if (t.days) {
    put_be(b, 4, *t.days, 2);
    n = 6;
  }
  w.write_tlv(ctx(data_type::binary_time), byte_view{b.data(), n});
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// Time helpers

std::array<std::uint8_t, 8> utc_time::to_bytes() const noexcept {
  std::array<std::uint8_t, 8> b{};
  put_be(b, 0, seconds, 4);
  put_be(b, 4, fraction & 0xFFFFFFU, 3);
  b[7] = quality;
  return b;
}

utc_time utc_time::from_bytes(std::span<const std::uint8_t, 8> b) noexcept {
  const byte_view v{b};
  return {static_cast<std::uint32_t>(get_be(v.first(4))),
          static_cast<std::uint32_t>(get_be(v.subspan(4, 3))), b[7]};
}

std::array<std::uint8_t, 5> encode_float(float v) noexcept {
  std::array<std::uint8_t, 5> b{};
  b[0] = exponent_width_single;
  put_be(b, 1, std::bit_cast<std::uint32_t>(v), 4);
  return b;
}

std::array<std::uint8_t, 9> encode_double(double v) noexcept {
  std::array<std::uint8_t, 9> b{};
  b[0] = exponent_width_double;
  put_be(b, 1, std::bit_cast<std::uint64_t>(v), 8);
  return b;
}

// ---------------------------------------------------------------------------------------------
// Validation

namespace detail {

result<void> validate_data(const ber::tlv& e, const decode_options& opts,
                           std::size_t depth) noexcept {
  if (e.tag.cls != ber::tag_class::context) return errc::malformed_encoding;
  const auto t = static_cast<data_type>(e.tag.number);
  if (e.tag.number > 17) return errc::malformed_encoding;
  if (t != data_type::array && t != data_type::structure && e.tag.constructed) {
    // Constructed (segmented) strings are valid BER but not supported, like in ber::decode_*.
    switch (t) {
      case data_type::bit_string:
      case data_type::octet_string:
      case data_type::visible_string:
      case data_type::generalized_time:
      case data_type::boolean_array:
      case data_type::mms_string:
        return errc::unsupported;
      default:
        return errc::malformed_encoding;
    }
  }
  const byte_view c = e.value;
  switch (t) {
    case data_type::array:
    case data_type::structure: {
      if (!e.tag.constructed) return errc::malformed_encoding;
      if (depth >= opts.max_nesting) return errc::nesting_too_deep;
      byte_view rest = c;
      while (!rest.empty()) {
        auto child = ber::decode_tlv(rest);
        if (!child) return child.error();
        if (auto r = validate_data(*child, opts, depth + 1); !r) return r;
        rest = rest.subspan(child->encoding.size());
      }
      return {};
    }
    case data_type::boolean:
      if (auto r = ber::decode_boolean(c); !r) return r.error();
      return {};
    case data_type::bit_string:
    case data_type::boolean_array:
      if (auto r = ber::decode_bit_string(c); !r) return r.error();
      return {};
    case data_type::integer:
      if (auto r = ber::decode_integer(c); !r) return r.error();
      return {};
    case data_type::unsigned_:
    case data_type::bcd:
      if (auto r = ber::decode_unsigned(c); !r) return r.error();
      return {};
    case data_type::floating_point:
      // Exponent-width octet plus at least one octet; formats other than IEEE single and
      // double are kept and reported as unsupported by the accessors.
      if (c.size() < 2) return errc::malformed_encoding;
      return {};
    case data_type::octet_string:
    case data_type::visible_string:
    case data_type::generalized_time:
    case data_type::mms_string:
      return {};
    case data_type::binary_time:
      if (c.size() != 4 && c.size() != 6) return errc::malformed_encoding;
      return {};
    case data_type::obj_id:
      if (auto r = ber::decode_oid(c); !r) return r.error();
      return {};
    case data_type::utc_time:
      if (c.size() != 8) return errc::malformed_encoding;
      return {};
    case data_type::invalid:
      return errc::malformed_encoding;
  }
  // [8] (real) and any other number not in the CHOICE.
  return e.tag.number == 8 ? errc::unsupported : errc::malformed_encoding;
}

result<data_view> make_data_view(const ber::tlv& e) noexcept { return data_view::unchecked(e); }

}  // namespace detail

// ---------------------------------------------------------------------------------------------
// data_view

result<data_view> data_view::parse(byte_view encoding, const decode_options& opts) noexcept {
  auto e = ber::decode_tlv(encoding);
  if (!e) return e.error();
  if (e->encoding.size() != encoding.size()) return errc::malformed_encoding;
  return parse(*e, opts);
}

result<data_view> data_view::parse(const ber::tlv& element, const decode_options& opts) noexcept {
  if (auto r = detail::validate_data(element, opts, 0); !r) return r.error();
  return unchecked(element);
}

data_view data_view::unchecked(const ber::tlv& element) noexcept {
  data_view v;
  v.type_ = static_cast<data_type>(element.tag.number);
  v.encoding_ = element.encoding;
  v.contents_ = element.value;
  return v;
}

list_view<data_view> data_view::elements() const noexcept {
  if (!is_constructed()) return {};
  return list_view<data_view>::encoded(contents_, &detail::make_data_view);
}

result<data_view> data_view::at(std::size_t i) const noexcept {
  for (const auto& e : elements()) {
    if (i-- == 0) return e;
  }
  return errc::value_out_of_range;
}

result<bool> data_view::as_boolean() const noexcept {
  if (type_ != data_type::boolean) return errc::invalid_state;
  return ber::decode_boolean(contents_);
}

result<ber::bit_string_view> data_view::as_bit_string() const noexcept {
  if (type_ != data_type::bit_string) return errc::invalid_state;
  return ber::decode_bit_string(contents_);
}

result<ber::bit_string_view> data_view::as_boolean_array() const noexcept {
  if (type_ != data_type::boolean_array) return errc::invalid_state;
  return ber::decode_bit_string(contents_);
}

result<float> data_view::as_float() const noexcept {
  if (type_ != data_type::floating_point) return errc::invalid_state;
  if (is_single(contents_)) {
    return std::bit_cast<float>(static_cast<std::uint32_t>(get_be(contents_.subspan(1))));
  }
  if (is_double_fp(contents_)) return errc::value_out_of_range;
  return errc::unsupported;
}

result<double> data_view::as_double() const noexcept {
  if (type_ != data_type::floating_point) return errc::invalid_state;
  if (is_double_fp(contents_)) return std::bit_cast<double>(get_be(contents_.subspan(1)));
  if (is_single(contents_)) {
    return static_cast<double>(
        std::bit_cast<float>(static_cast<std::uint32_t>(get_be(contents_.subspan(1)))));
  }
  return errc::unsupported;
}

bool data_view::is_double() const noexcept {
  return type_ == data_type::floating_point && is_double_fp(contents_);
}

result<byte_view> data_view::as_octet_string() const noexcept {
  if (type_ != data_type::octet_string) return errc::invalid_state;
  return contents_;
}

result<std::string_view> data_view::as_visible_string() const noexcept {
  if (type_ != data_type::visible_string) return errc::invalid_state;
  return ber::decode_visible_string(contents_);
}

result<std::string_view> data_view::as_generalized_time() const noexcept {
  if (type_ != data_type::generalized_time) return errc::invalid_state;
  return ber::decode_generalized_time(contents_);
}

result<std::string_view> data_view::as_mms_string() const noexcept {
  if (type_ != data_type::mms_string) return errc::invalid_state;
  return ber::decode_utf8_string(contents_);
}

result<binary_time> data_view::as_binary_time() const noexcept {
  if (type_ != data_type::binary_time) return errc::invalid_state;
  if (contents_.size() != 4 && contents_.size() != 6) return errc::malformed_encoding;
  return decode_binary_time(contents_);
}

result<std::uint64_t> data_view::as_bcd() const noexcept {
  if (type_ != data_type::bcd) return errc::invalid_state;
  return ber::decode_unsigned(contents_);
}

result<ber::oid> data_view::as_obj_id() const noexcept {
  if (type_ != data_type::obj_id) return errc::invalid_state;
  return ber::decode_oid(contents_);
}

result<utc_time> data_view::as_utc_time() const noexcept {
  if (type_ != data_type::utc_time) return errc::invalid_state;
  if (contents_.size() != 8) return errc::malformed_encoding;
  return utc_time::from_bytes(contents_.first<8>());
}

// ---------------------------------------------------------------------------------------------
// data

namespace {

byte_buffer bit_bytes(byte_view bytes, std::size_t bit_count) {
  const std::size_t n = (bit_count + 7) / 8;
  byte_buffer b(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(std::min(n, bytes.size())));
  b.resize(n, 0);
  if (bit_count % 8 != 0) {
    b.back() = static_cast<std::uint8_t>(b.back() & (0xFFU << (8 - bit_count % 8)));
  }
  return b;
}

}  // namespace

data data::array(std::vector<data> elements) {
  return {data_type::array, std::move(elements)};
}
data data::structure(std::vector<data> components) {
  return {data_type::structure, std::move(components)};
}
data data::boolean(bool v) { return {data_type::boolean, v}; }
data data::bit_string(byte_view bytes, std::size_t bit_count) {
  return {data_type::bit_string, bit_bytes(bytes, bit_count), bit_count};
}
data data::integer(std::int64_t v) { return {data_type::integer, v}; }
data data::unsigned_integer(std::uint64_t v) { return {data_type::unsigned_, v}; }
data data::floating_point(float v) { return {data_type::floating_point, v}; }
data data::floating_point(double v) { return {data_type::floating_point, v}; }
data data::octet_string(byte_view v) {
  return {data_type::octet_string, byte_buffer(v.begin(), v.end())};
}
data data::visible_string(std::string_view v) {
  return {data_type::visible_string, std::string(v)};
}
data data::generalized_time(std::string_view v) {
  return {data_type::generalized_time, std::string(v)};
}
data data::binary_time(const mms::binary_time& v) { return {data_type::binary_time, v}; }
data data::bcd(std::uint64_t v) { return {data_type::bcd, v}; }
data data::boolean_array(byte_view bytes, std::size_t bit_count) {
  return {data_type::boolean_array, bit_bytes(bytes, bit_count), bit_count};
}
data data::obj_id(const ber::oid& v) { return {data_type::obj_id, v}; }
data data::mms_string(std::string_view v) { return {data_type::mms_string, std::string(v)}; }
data data::utc_time(const mms::utc_time& v) { return {data_type::utc_time, v}; }

result<data> data::from_view(const data_view& v) {
  switch (v.type()) {
    case data_type::array:
    case data_type::structure: {
      std::vector<data> children;
      for (const auto& e : v.elements()) {
        auto c = from_view(e);
        if (!c) return c.error();
        children.push_back(std::move(*c));
      }
      return data{v.type(), std::move(children)};
    }
    case data_type::boolean: {
      auto x = v.as_boolean();
      if (!x) return x.error();
      return boolean(*x);
    }
    case data_type::bit_string:
    case data_type::boolean_array: {
      auto x = ber::decode_bit_string(v.contents());
      if (!x) return x.error();
      return data{v.type(), bit_bytes(x->bytes, x->bit_count), x->bit_count};
    }
    case data_type::integer: {
      auto x = v.as_int64();
      if (!x) return x.error();
      return integer(*x);
    }
    case data_type::unsigned_: {
      auto x = v.as_uint64();
      if (!x) return x.error();
      return unsigned_integer(*x);
    }
    case data_type::floating_point: {
      if (v.is_double()) return floating_point(*v.as_double());
      auto x = v.as_float();
      if (!x) return x.error();
      return floating_point(*x);
    }
    case data_type::octet_string:
      return octet_string(v.contents());
    case data_type::visible_string:
    case data_type::generalized_time:
    case data_type::mms_string: {
      const auto c = v.contents();
      return data{v.type(), std::string(c.begin(), c.end())};
    }
    case data_type::binary_time: {
      auto x = v.as_binary_time();
      if (!x) return x.error();
      return binary_time(*x);
    }
    case data_type::bcd: {
      auto x = v.as_bcd();
      if (!x) return x.error();
      return bcd(*x);
    }
    case data_type::obj_id: {
      auto x = v.as_obj_id();
      if (!x) return x.error();
      return obj_id(*x);
    }
    case data_type::utc_time: {
      auto x = v.as_utc_time();
      if (!x) return x.error();
      return utc_time(*x);
    }
    case data_type::invalid:
      break;
  }
  return errc::invalid_state;
}

std::span<const data> data::elements() const noexcept {
  if (const auto* v = std::get_if<std::vector<data>>(&value_)) return *v;
  return {};
}

result<std::vector<data>*> data::mutable_elements() noexcept {
  if (auto* v = std::get_if<std::vector<data>>(&value_)) return v;
  return errc::invalid_state;
}

namespace {

template <typename T, typename V>
result<T> get_as(const V& value, data_type actual, data_type expected) noexcept {
  if (actual != expected) return errc::invalid_state;
  if (const auto* p = std::get_if<T>(&value)) return *p;
  return errc::invalid_state;
}

}  // namespace

result<bool> data::as_boolean() const noexcept {
  return get_as<bool>(value_, type_, data_type::boolean);
}

result<ber::bit_string_view> data::as_bit_string() const noexcept {
  if (type_ != data_type::bit_string) return errc::invalid_state;
  return ber::bit_string_view{std::get<byte_buffer>(value_), bits_};
}

result<ber::bit_string_view> data::as_boolean_array() const noexcept {
  if (type_ != data_type::boolean_array) return errc::invalid_state;
  return ber::bit_string_view{std::get<byte_buffer>(value_), bits_};
}

result<std::int64_t> data::as_int64() const noexcept {
  if (type_ == data_type::integer) return std::get<std::int64_t>(value_);
  if (type_ == data_type::unsigned_) {
    const auto v = std::get<std::uint64_t>(value_);
    if (v > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
      return errc::value_out_of_range;
    }
    return static_cast<std::int64_t>(v);
  }
  return errc::invalid_state;
}

result<std::uint64_t> data::as_uint64() const noexcept {
  if (type_ == data_type::unsigned_) return std::get<std::uint64_t>(value_);
  if (type_ == data_type::integer) {
    const auto v = std::get<std::int64_t>(value_);
    if (v < 0) return errc::value_out_of_range;
    return static_cast<std::uint64_t>(v);
  }
  return errc::invalid_state;
}

result<float> data::as_float() const noexcept {
  if (type_ != data_type::floating_point) return errc::invalid_state;
  if (const auto* f = std::get_if<float>(&value_)) return *f;
  return errc::value_out_of_range;
}

result<double> data::as_double() const noexcept {
  if (type_ != data_type::floating_point) return errc::invalid_state;
  if (const auto* f = std::get_if<float>(&value_)) return static_cast<double>(*f);
  return std::get<double>(value_);
}

bool data::is_double() const noexcept { return std::holds_alternative<double>(value_); }

result<byte_view> data::as_octet_string() const noexcept {
  if (type_ != data_type::octet_string) return errc::invalid_state;
  return byte_view{std::get<byte_buffer>(value_)};
}

result<std::string_view> data::as_visible_string() const noexcept {
  if (type_ != data_type::visible_string) return errc::invalid_state;
  return std::string_view{std::get<std::string>(value_)};
}

result<std::string_view> data::as_generalized_time() const noexcept {
  if (type_ != data_type::generalized_time) return errc::invalid_state;
  return std::string_view{std::get<std::string>(value_)};
}

result<std::string_view> data::as_mms_string() const noexcept {
  if (type_ != data_type::mms_string) return errc::invalid_state;
  return std::string_view{std::get<std::string>(value_)};
}

result<mms::binary_time> data::as_binary_time() const noexcept {
  return get_as<mms::binary_time>(value_, type_, data_type::binary_time);
}

result<std::uint64_t> data::as_bcd() const noexcept {
  return get_as<std::uint64_t>(value_, type_, data_type::bcd);
}

result<ber::oid> data::as_obj_id() const noexcept {
  return get_as<ber::oid>(value_, type_, data_type::obj_id);
}

result<mms::utc_time> data::as_utc_time() const noexcept {
  return get_as<mms::utc_time>(value_, type_, data_type::utc_time);
}

result<void> data::encode(ber::writer& w) const {
  switch (type_) {
    case data_type::array:
    case data_type::structure: {
      const auto m = w.begin(ctx(type_, true));
      for (const auto& c : std::get<std::vector<data>>(value_)) {
        if (auto r = c.encode(w); !r) return r;
      }
      w.end(m);
      return {};
    }
    case data_type::boolean:
      w.write_boolean(std::get<bool>(value_), ctx(type_));
      return {};
    case data_type::bit_string:
    case data_type::boolean_array:
      return w.write_bit_string(std::get<byte_buffer>(value_), bits_, ctx(type_));
    case data_type::integer:
      w.write_integer(std::get<std::int64_t>(value_), ctx(type_));
      return {};
    case data_type::unsigned_:
    case data_type::bcd:
      w.write_unsigned(std::get<std::uint64_t>(value_), ctx(type_));
      return {};
    case data_type::floating_point:
      if (const auto* f = std::get_if<float>(&value_)) {
        w.write_tlv(ctx(type_), encode_float(*f));
      } else {
        w.write_tlv(ctx(type_), encode_double(std::get<double>(value_)));
      }
      return {};
    case data_type::octet_string:
      w.write_octet_string(std::get<byte_buffer>(value_), ctx(type_));
      return {};
    case data_type::visible_string:
    case data_type::generalized_time:
    case data_type::mms_string:
      w.write_tlv(ctx(type_), detail::as_bytes(std::get<std::string>(value_)));
      return {};
    case data_type::binary_time:
      write_binary_time(w, std::get<mms::binary_time>(value_));
      return {};
    case data_type::obj_id:
      if (!w.write_oid(std::get<ber::oid>(value_), ctx(type_))) return errc::invalid_state;
      return {};
    case data_type::utc_time:
      w.write_tlv(ctx(type_), std::get<mms::utc_time>(value_).to_bytes());
      return {};
    case data_type::invalid:
      break;
  }
  return errc::invalid_state;
}

bool operator==(const data& a, const data& b) noexcept {
  return a.type_ == b.type_ && a.bits_ == b.bits_ && a.value_ == b.value_;
}

result<void> data_ref::encode(ber::writer& w) const {
  if (owned_ != nullptr) return owned_->encode(w);
  if (!view_.valid()) return errc::invalid_state;
  w.write_raw(view_.encoding());
  return {};
}

result<void> encode_data(const data& v, byte_buffer& out) {
  const std::size_t original = out.size();
  ber::writer w{out};
  auto r = v.encode(w);
  if (!r) out.resize(original);
  return r;
}

}  // namespace openiec61850::mms
