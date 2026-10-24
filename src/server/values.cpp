#include "values.hpp"

#include <cmath>
#include <cstdint>
#include <limits>
#include <utility>
#include <vector>

namespace openiec61850::server::detail {

namespace {

using dae = mms::data_access_error;

bool length_ok(std::size_t len, std::int32_t size) noexcept {
  if (size == 0) return true;
  const auto limit = size < 0 ? -static_cast<std::int64_t>(size) : static_cast<std::int64_t>(size);
  return static_cast<std::int64_t>(len) <= limit;
}

std::optional<std::int64_t> as_signed(const mms::data& v) {
  if (v.type() == mms::data_type::integer) {
    auto x = v.as_int64();
    if (x) return *x;
    return std::nullopt;
  }
  auto x = v.as_uint64();
  if (!x || *x > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
    return std::nullopt;
  }
  return static_cast<std::int64_t>(*x);
}

}  // namespace

mms::data resize_bits(const ber::bit_string_view& bits, std::size_t count) {
  byte_buffer bytes((count + 7) / 8, 0);
  const std::size_t n = bits.bit_count < count ? bits.bit_count : count;
  for (std::size_t i = 0; i < n; ++i) {
    if (bits.test(i)) bytes[i / 8] = static_cast<std::uint8_t>(bytes[i / 8] | (0x80U >> (i % 8)));
  }
  return mms::data::bit_string(bytes, count);
}

mms::data make_bits(const std::vector<bool>& bits) {
  byte_buffer bytes((bits.size() + 7) / 8, 0);
  for (std::size_t i = 0; i < bits.size(); ++i) {
    if (bits[i]) bytes[i / 8] = static_cast<std::uint8_t>(bytes[i / 8] | (0x80U >> (i % 8)));
  }
  return mms::data::bit_string(bytes, bits.size());
}

std::size_t encoded_size(const mms::data& v) {
  byte_buffer out;
  if (!mms::encode_data(v, out)) return 0;
  return out.size();
}

conformed conform(const mms::data& v, const mms::type_description& t) {
  switch (t.type) {
    case mms::data_type::structure: {
      if (v.type() != mms::data_type::structure) return dae::type_inconsistent;
      const auto elems = v.elements();
      if (elems.size() != t.components.size()) return dae::type_inconsistent;
      std::vector<mms::data> out;
      out.reserve(elems.size());
      for (std::size_t i = 0; i < elems.size(); ++i) {
        auto c = conform(elems[i], t.components[i].type);
        if (auto* e = std::get_if<dae>(&c)) return *e;
        out.push_back(std::move(std::get<mms::data>(c)));
      }
      return mms::data::structure(std::move(out));
    }
    case mms::data_type::array: {
      if (v.type() != mms::data_type::array || t.components.empty()) return dae::type_inconsistent;
      const auto elems = v.elements();
      if (elems.size() != t.number_of_elements) return dae::type_inconsistent;
      std::vector<mms::data> out;
      out.reserve(elems.size());
      for (const auto& el : elems) {
        auto c = conform(el, t.components.front().type);
        if (auto* e = std::get_if<dae>(&c)) return *e;
        out.push_back(std::move(std::get<mms::data>(c)));
      }
      return mms::data::array(std::move(out));
    }
    case mms::data_type::boolean:
      if (v.type() != mms::data_type::boolean) return dae::type_inconsistent;
      return v;
    case mms::data_type::bit_string: {
      auto bits = v.as_bit_string();
      if (!bits) return dae::type_inconsistent;
      if (t.size <= 0) return v;
      return resize_bits(*bits, static_cast<std::size_t>(t.size));
    }
    case mms::data_type::integer: {
      if (v.type() != mms::data_type::integer && v.type() != mms::data_type::unsigned_) {
        return dae::type_inconsistent;
      }
      const auto x = as_signed(v);
      if (!x) return dae::object_value_invalid;
      if (t.size > 0 && t.size < 64) {
        const std::int64_t hi = (std::int64_t{1} << (t.size - 1)) - 1;
        if (*x > hi || *x < -hi - 1) return dae::object_value_invalid;
      }
      return mms::data::integer(*x);
    }
    case mms::data_type::unsigned_: {
      std::uint64_t x = 0;
      if (v.type() == mms::data_type::unsigned_) {
        auto u = v.as_uint64();
        if (!u) return dae::object_value_invalid;
        x = *u;
      } else if (v.type() == mms::data_type::integer) {
        auto s = v.as_int64();
        if (!s || *s < 0) return dae::object_value_invalid;
        x = static_cast<std::uint64_t>(*s);
      } else {
        return dae::type_inconsistent;
      }
      if (t.size > 0 && t.size < 64 && x > ((std::uint64_t{1} << t.size) - 1)) {
        return dae::object_value_invalid;
      }
      return mms::data::unsigned_integer(x);
    }
    case mms::data_type::floating_point: {
      auto d = v.as_double();
      if (!d) return dae::type_inconsistent;
      if (t.exponent_width == 8) {
        if (std::isfinite(*d) &&
            std::fabs(*d) > static_cast<double>(std::numeric_limits<float>::max())) {
          return dae::object_value_invalid;
        }
        return mms::data::floating_point(static_cast<float>(*d));
      }
      return mms::data::floating_point(*d);
    }
    case mms::data_type::octet_string: {
      auto o = v.as_octet_string();
      if (!o) return dae::type_inconsistent;
      if (t.size > 0 ? o->size() != static_cast<std::size_t>(t.size) : !length_ok(o->size(), t.size)) {
        return dae::object_value_invalid;
      }
      return v;
    }
    case mms::data_type::visible_string: {
      auto s = v.as_visible_string();
      if (!s) return dae::type_inconsistent;
      if (!length_ok(s->size(), t.size)) return dae::object_value_invalid;
      return v;
    }
    case mms::data_type::mms_string: {
      auto s = v.type() == mms::data_type::visible_string ? v.as_visible_string() : v.as_mms_string();
      if (!s) return dae::type_inconsistent;
      if (!length_ok(s->size(), t.size)) return dae::object_value_invalid;
      return mms::data::mms_string(*s);
    }
    case mms::data_type::binary_time: {
      auto b = v.as_binary_time();
      if (!b) return dae::type_inconsistent;
      if (t.with_date != b->days.has_value()) return dae::type_inconsistent;
      return v;
    }
    default:
      if (v.type() != t.type) return dae::type_inconsistent;
      return v;
  }
}

}  // namespace openiec61850::server::detail
