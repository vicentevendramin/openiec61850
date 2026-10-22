#include "openiec61850/iso/session/spdu.hpp"

#include <bitset>
#include <iterator>
#include <utility>

namespace openiec61850::iso::session {
namespace {

inline constexpr std::size_t max_selector = 16;
inline constexpr std::size_t max_reference = 64;
inline constexpr std::size_t max_additional_reference = 4;
inline constexpr std::size_t max_initial_serial_number = 6;
inline constexpr std::size_t max_reflect_parameter = 9;

// ---------------------------------------------------------------------------------------------
// Decoding

// LI field, X.225 §8.2.5: one octet 0..254, or 0xFF followed by a two-octet length. The extended
// form is accepted on input even for lengths below 255.
result<std::size_t> read_li(byte_view& in) {
  if (in.empty()) return errc::truncated_input;
  std::size_t length = in[0];
  std::size_t header = 1;
  if (length == 0xFF) {
    if (in.size() < 3) return errc::truncated_input;
    length = (std::size_t{in[1]} << 8) | std::size_t{in[2]};
    header = 3;
  }
  in = in.subspan(header);
  if (length > in.size()) return errc::length_overflow;
  return length;
}

struct unit {
  std::uint8_t code;
  byte_view value;
};

// Walks a parameter field made of PI/PGI units (X.225 §8.2). The callback handles known codes and
// returns success for unknown ones, which are thereby skipped. A code may appear only once.
template <typename F>
result<void> for_each_unit(byte_view field, F&& handle) {
  std::bitset<256> seen;
  while (!field.empty()) {
    const std::uint8_t code = field[0];
    field = field.subspan(1);
    auto length = read_li(field);
    if (!length) return length.error();
    const unit u{code, field.first(*length)};
    field = field.subspan(*length);
    if (seen.test(code)) return errc::malformed_encoding;
    seen.set(code);
    if (auto r = handle(u); !r) return r;
  }
  return {};
}

result<void> get_u8(byte_view v, std::uint8_t& dst) {
  if (v.size() != 1) return errc::malformed_encoding;
  dst = v[0];
  return {};
}

result<void> get_u8(byte_view v, std::optional<std::uint8_t>& dst) {
  std::uint8_t value = 0;
  if (auto r = get_u8(v, value); !r) return r;
  dst = value;
  return {};
}

result<void> get_u16(byte_view v, std::uint16_t& dst) {
  if (v.size() != 2) return errc::malformed_encoding;
  dst = static_cast<std::uint16_t>((v[0] << 8) | v[1]);
  return {};
}

result<void> get_u16(byte_view v, std::optional<std::uint16_t>& dst) {
  std::uint16_t value = 0;
  if (auto r = get_u16(v, value); !r) return r;
  dst = value;
  return {};
}

result<void> get_bounded(byte_view v, std::size_t max, byte_view& dst) {
  if (v.size() > max) return errc::malformed_encoding;
  dst = v;
  return {};
}

result<void> parse_connection_id(byte_view v, std::optional<connection_identifier>& dst) {
  connection_identifier id;
  auto r = for_each_unit(v, [&](const unit& u) -> result<void> {
    switch (u.code) {
      case pi::called_ss_user_reference:
      case pi::calling_ss_user_reference:
        return get_bounded(u.value, max_reference, id.ss_user_reference);
      case pi::common_reference: return get_bounded(u.value, max_reference, id.common_reference);
      case pi::additional_reference:
        return get_bounded(u.value, max_additional_reference, id.additional_reference);
      default: return {};
    }
  });
  if (!r) return r;
  dst = id;
  return {};
}

// Connect/Accept Item PGI, shared by CN and AC.
template <typename S>
result<void> parse_connect_accept_item(byte_view v, S& s) {
  return for_each_unit(v, [&](const unit& u) -> result<void> {
    switch (u.code) {
      case pi::protocol_options: return get_u8(u.value, s.protocol_options);
      case pi::tsdu_maximum_size: {
        if (u.value.size() != 4) return errc::malformed_encoding;
        tsdu_maximum_size size;
        size.initiator_to_responder = static_cast<std::uint16_t>((u.value[0] << 8) | u.value[1]);
        size.responder_to_initiator = static_cast<std::uint16_t>((u.value[2] << 8) | u.value[3]);
        s.tsdu_max_size = size;
        return {};
      }
      case pi::version_number: return get_u8(u.value, s.version_number);
      case pi::initial_serial_number:
        return get_bounded(u.value, max_initial_serial_number, s.initial_serial_number);
      case pi::token_setting_item: return get_u8(u.value, s.token_setting);
      default: return {};
    }
  });
}

result<connect_spdu> parse_connect(byte_view params) {
  connect_spdu s;
  s.version_number = version_1;  // implied when the Connect/Accept Item is absent
  s.session_requirements = fu::default_requirements;
  bool has_user_data = false;
  auto r = for_each_unit(params, [&](const unit& u) -> result<void> {
    switch (u.code) {
      case pi::connection_identifier: return parse_connection_id(u.value, s.connection_id);
      case pi::connect_accept_item: return parse_connect_accept_item(u.value, s);
      case pi::session_user_requirements: return get_u16(u.value, s.session_requirements);
      case pi::calling_session_selector:
        return get_bounded(u.value, max_selector, s.calling_selector);
      case pi::called_session_selector: return get_bounded(u.value, max_selector, s.called_selector);
      case pi::data_overflow: return get_u8(u.value, s.data_overflow);
      case pi::user_data:
      case pi::extended_user_data:
        if (has_user_data) return errc::malformed_encoding;  // both PGI 193 and 194
        has_user_data = true;
        s.user_data = u.value;
        return {};
      default: return {};
    }
  });
  if (!r) return r.error();
  return s;
}

result<accept_spdu> parse_accept(byte_view params) {
  accept_spdu s;
  s.version_number = version_1;
  s.session_requirements = fu::default_requirements;
  auto r = for_each_unit(params, [&](const unit& u) -> result<void> {
    switch (u.code) {
      case pi::connection_identifier: return parse_connection_id(u.value, s.connection_id);
      case pi::connect_accept_item: return parse_connect_accept_item(u.value, s);
      case pi::token_item: return get_u8(u.value, s.token_item);
      case pi::session_user_requirements: return get_u16(u.value, s.session_requirements);
      case pi::enclosure_item: return get_u8(u.value, s.enclosure);
      case pi::calling_session_selector:
        return get_bounded(u.value, max_selector, s.calling_selector);
      case pi::responding_session_selector:
        return get_bounded(u.value, max_selector, s.responding_selector);
      case pi::user_data: s.user_data = u.value; return {};
      default: return {};
    }
  });
  if (!r) return r.error();
  return s;
}

result<refuse_spdu> parse_refuse(byte_view params) {
  refuse_spdu s;
  bool has_reason = false;
  auto r = for_each_unit(params, [&](const unit& u) -> result<void> {
    switch (u.code) {
      case pi::connection_identifier: return parse_connection_id(u.value, s.connection_id);
      case pi::transport_disconnect: return get_u8(u.value, s.transport_disconnect);
      case pi::session_user_requirements: return get_u16(u.value, s.session_requirements);
      case pi::version_number: return get_u8(u.value, s.version_number);
      case pi::enclosure_item: return get_u8(u.value, s.enclosure);
      case pi::reason_code:
        if (u.value.empty()) return errc::malformed_encoding;
        has_reason = true;
        s.reason = u.value[0];
        s.user_data = u.value.subspan(1);
        return {};
      default: return {};
    }
  });
  if (!r) return r.error();
  if (!has_reason) return errc::malformed_encoding;  // Reason Code is mandatory in RF
  return s;
}

result<finish_spdu> parse_finish(byte_view params) {
  finish_spdu s;
  auto r = for_each_unit(params, [&](const unit& u) -> result<void> {
    switch (u.code) {
      case pi::transport_disconnect: return get_u8(u.value, s.transport_disconnect);
      case pi::enclosure_item: return get_u8(u.value, s.enclosure);
      case pi::user_data: s.user_data = u.value; return {};
      default: return {};
    }
  });
  if (!r) return r.error();
  return s;
}

// DN and NF have the same parameters.
template <typename S>
result<S> parse_enclosure_and_user_data(byte_view params) {
  S s;
  auto r = for_each_unit(params, [&](const unit& u) -> result<void> {
    switch (u.code) {
      case pi::enclosure_item: return get_u8(u.value, s.enclosure);
      case pi::user_data: s.user_data = u.value; return {};
      default: return {};
    }
  });
  if (!r) return r.error();
  return s;
}

result<abort_spdu> parse_abort(byte_view params) {
  abort_spdu s;
  auto r = for_each_unit(params, [&](const unit& u) -> result<void> {
    switch (u.code) {
      case pi::transport_disconnect: return get_u8(u.value, s.transport_disconnect);
      case pi::enclosure_item: return get_u8(u.value, s.enclosure);
      case pi::reflect_parameter_values:
        return get_bounded(u.value, max_reflect_parameter, s.reflect_parameter);
      case pi::user_data: s.user_data = u.value; return {};
      default: return {};
    }
  });
  if (!r) return r.error();
  return s;
}

result<give_tokens_spdu> parse_give_tokens(byte_view params) {
  give_tokens_spdu s;
  auto r = for_each_unit(params, [&](const unit& u) -> result<void> {
    if (u.code == pi::token_item) return get_u8(u.value, s.token_item);
    return {};
  });
  if (!r) return r.error();
  return s;
}

result<data_transfer_spdu> parse_data_transfer(byte_view params) {
  data_transfer_spdu s;
  auto r = for_each_unit(params, [&](const unit& u) -> result<void> {
    if (u.code == pi::enclosure_item) return get_u8(u.value, s.enclosure);
    return {};
  });
  if (!r) return r.error();
  return s;
}

template <typename T>
result<spdu> widen(result<T>&& r) {
  if (!r) return r.error();
  return spdu{std::move(*r)};
}

// SPDUs that exist in X.225 but are outside the kernel + duplex profile.
bool is_unsupported_si(std::uint8_t code) {
  switch (code) {
    case si::please_tokens:
    case 5:   // EX
    case 15:  // CDO
    case 16:  // OA
    case 33:  // TD
    case 61:  // CD
    case 62:  // CDA
      return true;
    default: return false;
  }
}

// ---------------------------------------------------------------------------------------------
// Encoding

void put_li(byte_buffer& out, std::size_t length) {
  if (length < 0xFF) {
    out.push_back(static_cast<std::uint8_t>(length));
  } else {
    out.push_back(0xFF);
    out.push_back(static_cast<std::uint8_t>((length >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(length & 0xFF));
  }
}

void put_unit(byte_buffer& out, std::uint8_t code, byte_view value) {
  out.push_back(code);
  put_li(out, value.size());
  out.insert(out.end(), value.begin(), value.end());
}

void put_u8(byte_buffer& out, std::uint8_t code, std::uint8_t value) {
  const std::uint8_t v[1] = {value};
  put_unit(out, code, v);
}

void put_u8(byte_buffer& out, std::uint8_t code, const std::optional<std::uint8_t>& value) {
  if (value) put_u8(out, code, *value);
}

void put_u16(byte_buffer& out, std::uint8_t code, std::uint16_t value) {
  const std::uint8_t v[2] = {static_cast<std::uint8_t>(value >> 8),
                             static_cast<std::uint8_t>(value & 0xFF)};
  put_unit(out, code, v);
}

void put_view(byte_buffer& out, std::uint8_t code, byte_view value) {
  if (!value.empty()) put_unit(out, code, value);
}

// Appends SI + LI + parameter field after checking that the field fits an LI.
result<void> put_spdu(byte_buffer& out, std::uint8_t code, const byte_buffer& params) {
  if (params.size() > max_li) return errc::length_overflow;
  out.push_back(code);
  put_li(out, params.size());
  out.insert(out.end(), params.begin(), params.end());
  return {};
}

result<void> check_selector(byte_view v) {
  return v.size() <= max_selector ? result<void>{} : result<void>{errc::length_overflow};
}

result<void> put_connection_id(byte_buffer& out, const std::optional<connection_identifier>& id,
                               std::uint8_t reference_code) {
  if (!id) return {};
  if (id->ss_user_reference.size() > max_reference || id->common_reference.size() > max_reference ||
      id->additional_reference.size() > max_additional_reference) {
    return errc::length_overflow;
  }
  byte_buffer group;
  put_view(group, reference_code, id->ss_user_reference);
  put_view(group, pi::common_reference, id->common_reference);
  put_view(group, pi::additional_reference, id->additional_reference);
  put_unit(out, pi::connection_identifier, group);
  return {};
}

template <typename S>
void put_connect_accept_item(byte_buffer& out, const S& s) {
  byte_buffer group;
  put_u8(group, pi::protocol_options, s.protocol_options);
  if (s.tsdu_max_size) {
    const auto& m = *s.tsdu_max_size;
    const std::uint8_t v[4] = {static_cast<std::uint8_t>(m.initiator_to_responder >> 8),
                               static_cast<std::uint8_t>(m.initiator_to_responder & 0xFF),
                               static_cast<std::uint8_t>(m.responder_to_initiator >> 8),
                               static_cast<std::uint8_t>(m.responder_to_initiator & 0xFF)};
    put_unit(group, pi::tsdu_maximum_size, v);
  }
  put_u8(group, pi::version_number, s.version_number);
  put_view(group, pi::initial_serial_number, s.initial_serial_number);
  put_u8(group, pi::token_setting_item, s.token_setting);
  put_unit(out, pi::connect_accept_item, group);
}

}  // namespace

result<spdu> decode_tsdu(byte_view tsdu) {
  byte_view in = tsdu;
  if (in.empty()) return errc::truncated_input;
  const std::uint8_t code = in[0];
  in = in.subspan(1);
  auto length = read_li(in);
  if (!length) return length.error();
  const byte_view params = in.first(*length);
  const byte_view rest = in.subspan(*length);

  if (code == si::give_tokens) {
    auto gt = parse_give_tokens(params);
    if (!gt) return gt.error();
    if (rest.empty()) return spdu{*gt};
    // Basic concatenation: a category 2 SPDU follows the category 0 GT.
    if (gt->token_item && *gt->token_item != 0) return errc::unsupported;
    byte_view in2 = rest;
    const std::uint8_t code2 = in2[0];
    in2 = in2.subspan(1);
    auto length2 = read_li(in2);
    if (!length2) return length2.error();
    if (code2 != si::data_transfer) return errc::unsupported;
    auto dt = parse_data_transfer(in2.first(*length2));
    if (!dt) return dt.error();
    dt->user_information = in2.subspan(*length2);
    return spdu{*dt};
  }

  // Category 1 SPDUs are mapped one-to-one onto a TSDU.
  if (!rest.empty()) {
    return is_unsupported_si(code) ? errc::unsupported : errc::malformed_encoding;
  }
  switch (code) {
    case si::connect: return widen(parse_connect(params));
    case si::accept: return widen(parse_accept(params));
    case si::refuse: return widen(parse_refuse(params));
    case si::finish: return widen(parse_finish(params));
    case si::disconnect: return widen(parse_enclosure_and_user_data<disconnect_spdu>(params));
    case si::not_finished: return widen(parse_enclosure_and_user_data<not_finished_spdu>(params));
    case si::abort: return widen(parse_abort(params));
    case si::abort_accept: {
      auto r = for_each_unit(params, [](const unit&) -> result<void> { return {}; });
      if (!r) return r.error();
      return spdu{abort_accept_spdu{}};
    }
    default: return is_unsupported_si(code) ? errc::unsupported : errc::malformed_encoding;
  }
}

result<void> encode(const connect_spdu& s, byte_buffer& out) {
  if (auto r = check_selector(s.calling_selector); !r) return r;
  if (auto r = check_selector(s.called_selector); !r) return r;
  const bool extended = s.user_data.size() > max_connect_user_data;
  if (extended) {
    if ((s.version_number & version_2) == 0) return errc::length_overflow;
    if (s.user_data.size() > max_connect_extended_user_data) return errc::unsupported;
  }
  byte_buffer params;
  if (auto r = put_connection_id(params, s.connection_id, pi::calling_ss_user_reference); !r) {
    return r;
  }
  put_connect_accept_item(params, s);
  put_u16(params, pi::session_user_requirements, s.session_requirements);
  put_view(params, pi::calling_session_selector, s.calling_selector);
  put_view(params, pi::called_session_selector, s.called_selector);
  put_u8(params, pi::data_overflow, s.data_overflow);
  put_view(params, extended ? pi::extended_user_data : pi::user_data, s.user_data);
  return put_spdu(out, si::connect, params);
}

result<void> encode(const accept_spdu& s, byte_buffer& out) {
  if (auto r = check_selector(s.calling_selector); !r) return r;
  if (auto r = check_selector(s.responding_selector); !r) return r;
  byte_buffer params;
  if (auto r = put_connection_id(params, s.connection_id, pi::called_ss_user_reference); !r) {
    return r;
  }
  put_connect_accept_item(params, s);
  put_u8(params, pi::token_item, s.token_item);
  put_u16(params, pi::session_user_requirements, s.session_requirements);
  put_u8(params, pi::enclosure_item, s.enclosure);
  put_view(params, pi::calling_session_selector, s.calling_selector);
  put_view(params, pi::responding_session_selector, s.responding_selector);
  put_view(params, pi::user_data, s.user_data);
  return put_spdu(out, si::accept, params);
}

result<void> encode(const refuse_spdu& s, byte_buffer& out) {
  byte_buffer params;
  if (auto r = put_connection_id(params, s.connection_id, pi::called_ss_user_reference); !r) {
    return r;
  }
  put_u8(params, pi::transport_disconnect, s.transport_disconnect);
  if (s.session_requirements) put_u16(params, pi::session_user_requirements, *s.session_requirements);
  put_u8(params, pi::version_number, s.version_number);
  put_u8(params, pi::enclosure_item, s.enclosure);
  byte_buffer reason;
  reason.reserve(1 + s.user_data.size());
  reason.push_back(s.reason);
  reason.insert(reason.end(), s.user_data.begin(), s.user_data.end());
  put_unit(params, pi::reason_code, reason);
  return put_spdu(out, si::refuse, params);
}

result<void> encode(const finish_spdu& s, byte_buffer& out) {
  byte_buffer params;
  put_u8(params, pi::transport_disconnect, s.transport_disconnect);
  put_u8(params, pi::enclosure_item, s.enclosure);
  put_view(params, pi::user_data, s.user_data);
  return put_spdu(out, si::finish, params);
}

result<void> encode(const disconnect_spdu& s, byte_buffer& out) {
  byte_buffer params;
  put_u8(params, pi::enclosure_item, s.enclosure);
  put_view(params, pi::user_data, s.user_data);
  return put_spdu(out, si::disconnect, params);
}

result<void> encode(const not_finished_spdu& s, byte_buffer& out) {
  byte_buffer params;
  put_u8(params, pi::enclosure_item, s.enclosure);
  put_view(params, pi::user_data, s.user_data);
  return put_spdu(out, si::not_finished, params);
}

result<void> encode(const abort_spdu& s, byte_buffer& out) {
  if (s.reflect_parameter.size() > max_reflect_parameter) return errc::length_overflow;
  byte_buffer params;
  put_u8(params, pi::transport_disconnect, s.transport_disconnect);
  put_u8(params, pi::enclosure_item, s.enclosure);
  put_view(params, pi::reflect_parameter_values, s.reflect_parameter);
  put_view(params, pi::user_data, s.user_data);
  return put_spdu(out, si::abort, params);
}

result<void> encode(const abort_accept_spdu&, byte_buffer& out) {
  return put_spdu(out, si::abort_accept, {});
}

result<void> encode(const give_tokens_spdu& s, byte_buffer& out) {
  byte_buffer params;
  put_u8(params, pi::token_item, s.token_item);
  return put_spdu(out, si::give_tokens, params);
}

result<void> encode(const data_transfer_spdu& s, byte_buffer& out) {
  out.push_back(si::give_tokens);
  out.push_back(0);
  out.push_back(si::data_transfer);
  if (s.enclosure) {
    out.push_back(3);
    put_u8(out, pi::enclosure_item, *s.enclosure);
  } else {
    out.push_back(0);
  }
  out.insert(out.end(), s.user_information.begin(), s.user_information.end());
  return {};
}

result<void> encode(const spdu& s, byte_buffer& out) {
  return std::visit([&out](const auto& v) { return encode(v, out); }, s);
}

void encode_data_tsdu(byte_view user_information, byte_buffer& out) {
  out.reserve(out.size() + 4 + user_information.size());
  const std::uint8_t header[4] = {si::give_tokens, 0, si::data_transfer, 0};
  out.insert(out.end(), std::begin(header), std::end(header));
  out.insert(out.end(), user_information.begin(), user_information.end());
}

}  // namespace openiec61850::iso::session
