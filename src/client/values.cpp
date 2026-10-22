#include "openiec61850/client/values.hpp"

#include <cmath>
#include <limits>

#include "openiec61850/client/error.hpp"

namespace openiec61850::client {

namespace {

template <typename T>
result<T> typed(result<T> r) {
  if (!r && r.error() == openiec61850::errc::invalid_state) return make_error_code(errc::type_mismatch);
  return r;
}

}  // namespace

result<bool> to_bool(const mms::data& d) { return typed(d.as_boolean()); }

result<std::int64_t> to_int64(const mms::data& d) { return typed(d.as_int64()); }

result<std::uint64_t> to_uint64(const mms::data& d) { return typed(d.as_uint64()); }

result<float> to_float(const mms::data& d) {
  if (d.type() != mms::data_type::floating_point) return make_error_code(errc::type_mismatch);
  if (!d.is_double()) return d.as_float();
  auto v = d.as_double();
  if (!v) return v.error();
  if (std::isfinite(*v) && std::fabs(*v) > static_cast<double>(std::numeric_limits<float>::max())) {
    return openiec61850::errc::value_out_of_range;
  }
  return static_cast<float>(*v);
}

result<double> to_double(const mms::data& d) { return typed(d.as_double()); }

result<std::string> to_string(const mms::data& d) {
  if (d.type() == mms::data_type::visible_string) return std::string(*d.as_visible_string());
  if (d.type() == mms::data_type::mms_string) return std::string(*d.as_mms_string());
  return make_error_code(errc::type_mismatch);
}

result<byte_buffer> to_bytes(const mms::data& d) {
  auto v = typed(d.as_octet_string());
  if (!v) return v.error();
  return byte_buffer(v->begin(), v->end());
}

result<model::quality> to_quality(const mms::data& d) {
  return typed(model::quality::from_mms(d));
}

result<model::timestamp> to_timestamp(const mms::data& d) {
  return typed(model::timestamp::from_mms(d));
}

result<model::entry_time> to_entry_time(const mms::data& d) {
  return typed(model::entry_time_from_mms(d));
}

result<model::entry_id> to_entry_id(const mms::data& d) {
  return typed(model::entry_id::from_mms(d));
}

result<model::dbpos> to_dbpos(const mms::data& d) { return typed(model::dbpos_from_mms(d)); }

result<mms::data> component(const mms::data& d, std::size_t i) {
  if (d.type() != mms::data_type::structure && d.type() != mms::data_type::array) {
    return make_error_code(errc::type_mismatch);
  }
  const auto e = d.elements();
  if (i >= e.size()) return openiec61850::errc::value_out_of_range;
  return e[i];
}

}  // namespace openiec61850::client
