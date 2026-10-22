#include "openiec61850/model/basic_type.hpp"

#include <array>

namespace openiec61850::model {
namespace {

constexpr std::array<std::string_view, 29> names{
    "BOOLEAN",   "INT8",       "INT16",     "INT24",     "INT32",      "INT64",
    "INT128",    "INT8U",      "INT16U",    "INT24U",    "INT32U",     "FLOAT32",
    "FLOAT64",   "Enum",       "CodedEnum", "PackedList", "Octet",     "VisString",
    "Unicode",   "Timestamp",  "EntryTime", "Quality",   "ObjRef",     "EntryID",
    "Dbpos",     "Tcmd",       "Check",     "TrgOps",    "OptFlds"};

}  // namespace

std::string_view to_string(basic_type t) noexcept {
  const auto i = static_cast<std::size_t>(t);
  return i < names.size() ? names[i] : std::string_view{};
}

result<mms::type_description> to_mms_type(basic_type t, std::int32_t size, edition e) {
  using td = mms::type_description;
  switch (t) {
    case basic_type::boolean: return td::boolean();
    case basic_type::int8: return td::integer(8);
    case basic_type::int16: return td::integer(16);
    case basic_type::int24: return td::integer(24);
    case basic_type::int32: return td::integer(32);
    case basic_type::int64: return td::integer(64);
    case basic_type::int128: return td::integer(128);
    case basic_type::int8u: return td::unsigned_integer(8);
    case basic_type::int16u: return td::unsigned_integer(16);
    case basic_type::int24u: return td::unsigned_integer(24);
    case basic_type::int32u: return td::unsigned_integer(32);
    case basic_type::float32: return td::float32();
    case basic_type::float64: return td::float64();
    case basic_type::enumerated: return td::integer(8);
    case basic_type::coded_enum:
    case basic_type::packed_list:
      if (size <= 0) return errc::invalid_state;
      return td::bit_string(size);
    case basic_type::octet_string:
      if (size <= 0) return errc::invalid_state;
      return td::octet_string(-size);
    case basic_type::visible_string:
      if (size <= 0) return errc::invalid_state;
      return td::visible_string(-size);
    case basic_type::unicode_string:
      if (size <= 0) return errc::invalid_state;
      return td::mms_string(-size);
    case basic_type::timestamp: return td::utc_time();
    case basic_type::entry_time: return td::binary_time(true);
    case basic_type::quality: return td::bit_string(13);
    case basic_type::object_reference:
      return td::visible_string(e == edition::ed1 ? -65 : -129);
    case basic_type::entry_id: return td::octet_string(8);
    case basic_type::dbpos:
    case basic_type::tcmd:
    case basic_type::check: return td::bit_string(2);
    case basic_type::trigger_conditions: return td::bit_string(6);
    case basic_type::optional_fields: return td::bit_string(10);
  }
  return errc::invalid_state;
}

std::optional<basic_type> deduce_basic_type(const mms::type_description& t) noexcept {
  switch (t.type) {
    case mms::data_type::boolean: return basic_type::boolean;
    case mms::data_type::integer:
      switch (t.size) {
        case 16: return basic_type::int16;
        case 24: return basic_type::int24;
        case 32: return basic_type::int32;
        case 64: return basic_type::int64;
        case 128: return basic_type::int128;
        default: return std::nullopt;
      }
    case mms::data_type::unsigned_:
      switch (t.size) {
        case 8: return basic_type::int8u;
        case 16: return basic_type::int16u;
        case 24: return basic_type::int24u;
        case 32: return basic_type::int32u;
        default: return std::nullopt;
      }
    case mms::data_type::floating_point:
      if (t.format_width == 32 && t.exponent_width == 8) return basic_type::float32;
      if (t.format_width == 64 && t.exponent_width == 11) return basic_type::float64;
      return std::nullopt;
    case mms::data_type::bit_string:
      if (t.size == 13) return basic_type::quality;
      return std::nullopt;
    case mms::data_type::octet_string: return basic_type::octet_string;
    case mms::data_type::visible_string: return basic_type::visible_string;
    case mms::data_type::mms_string: return basic_type::unicode_string;
    case mms::data_type::utc_time: return basic_type::timestamp;
    case mms::data_type::binary_time:
      if (t.with_date) return basic_type::entry_time;
      return std::nullopt;
    default: return std::nullopt;
  }
}

}  // namespace openiec61850::model
