#include <limits>
#include <optional>
#include <type_traits>

#include "detail.hpp"
#include "openiec61850/ber/reader.hpp"
#include "openiec61850/mms/pdu.hpp"

namespace openiec61850::mms {
namespace {

using ber::context;

template <std::integral T>
result<T> read_int(ber::reader& rd, ber::tag t) {
  const auto e = rd.peek();
  if (!e) return e.error();
  if (!e->tag.same_id(t)) return errc::malformed_encoding;
  if (e->tag.constructed) return errc::malformed_encoding;
  auto v = ber::decode_integer_as<T>(e->value);
  if (v) (void)rd.next();
  return v;
}

// Consumes the next element when its identifier is `t`.
result<std::optional<ber::tlv>> next_if(ber::reader& rd, ber::tag t) {
  if (!rd.next_is(t)) return std::optional<ber::tlv>{};
  auto e = rd.next();
  if (!e) return e.error();
  return std::optional<ber::tlv>{*e};
}

// The single element inside an explicit tag.
result<ber::tlv> single(const ber::tlv& wrapper) {
  if (!wrapper.tag.constructed) return errc::malformed_encoding;
  ber::reader rd{wrapper.value};
  auto inner = rd.next();
  if (!inner) return inner.error();
  if (auto r = rd.expect_end(); !r) return r.error();
  return inner;
}

// Validates every element of a SEQUENCE OF with `check`.
template <typename F>
result<void> for_each_element(byte_view contents, F&& check) {
  while (!contents.empty()) {
    auto e = ber::decode_tlv(contents);
    if (!e) return e.error();
    if (auto r = check(*e); !r) return r.error();
    contents = contents.subspan(e->encoding.size());
  }
  return {};
}

// A list whose element decoder is also its validator.
template <typename T>
result<list_view<T>> decode_list(byte_view contents, typename list_view<T>::element_decoder dec) {
  if (auto r = for_each_element(contents, dec); !r) return r.error();
  return list_view<T>::encoded(contents, dec);
}

// ----- element decoders (also used lazily by list_view) -----

result<std::string_view> decode_identifier(const ber::tlv& e) noexcept {
  if (!e.tag.same_id(ber::tags::visible_string)) return errc::malformed_encoding;
  return ber::decode_visible_string(e);
}

result<ber::oid> decode_oid_element(const ber::tlv& e) noexcept {
  if (!e.tag.same_id(ber::tags::object_identifier)) return errc::malformed_encoding;
  return ber::decode_oid(e);
}

result<object_name> decode_object_name(const ber::tlv& e) noexcept {
  if (e.tag.cls != ber::tag_class::context) return errc::malformed_encoding;
  switch (e.tag.number) {
    case 0:
    case 2: {
      auto id = ber::decode_visible_string(e);
      if (!id) return id.error();
      return object_name{e.tag.number == 0 ? object_scope::vmd_specific : object_scope::aa_specific,
                         {}, *id};
    }
    case 1: {
      if (!e.tag.constructed) return errc::malformed_encoding;
      ber::reader rd{e.value};
      auto domain = rd.read_visible_string();
      if (!domain) return domain.error();
      auto item = rd.read_visible_string();
      if (!item) return item.error();
      if (auto r = rd.expect_end(); !r) return r.error();
      return object_name::domain(*domain, *item);
    }
    default:
      return errc::malformed_encoding;
  }
}

result<variable_spec> decode_variable_spec(const ber::tlv& e) noexcept {
  if (e.tag != ber::tags::sequence) return errc::malformed_encoding;
  ber::reader rd{e.value};
  auto vs = rd.next();
  if (!vs) return vs.error();
  if (vs->tag.cls != ber::tag_class::context) return errc::malformed_encoding;
  if (vs->tag.number != 0) return vs->tag.number <= 4 ? errc::unsupported : errc::malformed_encoding;
  auto inner = single(*vs);
  if (!inner) return inner.error();
  auto name = decode_object_name(*inner);
  if (!name) return name.error();
  variable_spec spec{*name};
  auto alt = next_if(rd, context(5, true));
  if (!alt) return alt.error();
  if (*alt) spec.alternate_access = (*alt)->value;
  if (auto r = rd.expect_end(); !r) return r.error();
  return spec;
}

result<data_access_error> decode_data_access_error(const ber::tlv& e) noexcept {
  if (e.tag.constructed) return errc::malformed_encoding;
  auto v = ber::decode_integer_as<std::uint8_t>(e.value);
  if (!v) return v.error();
  return static_cast<data_access_error>(*v);
}

// Unchecked: the PDU decoder validates with validate_access_result first.
result<access_result> make_access_result(const ber::tlv& e) noexcept {
  if (e.tag == context(0)) {
    auto f = decode_data_access_error(e);
    if (!f) return f.error();
    return access_result{*f};
  }
  return access_result{data_ref{data_view::unchecked(e)}};
}

result<data_ref> make_data_ref(const ber::tlv& e) noexcept {
  return data_ref{data_view::unchecked(e)};
}

result<write_result> decode_write_result(const ber::tlv& e) noexcept {
  if (e.tag == context(0)) {
    auto f = decode_data_access_error(e);
    if (!f) return f.error();
    return write_result{*f};
  }
  if (e.tag.same_id(context(1))) {
    if (auto r = ber::decode_null(e); !r) return r.error();
    return write_result{};
  }
  return errc::malformed_encoding;
}

result<list_view<access_result>> decode_access_results(byte_view contents,
                                                       const decode_options& opts) {
  auto ok = for_each_element(contents, [&](const ber::tlv& e) -> result<void> {
    if (e.tag.same_id(context(0))) {
      auto f = decode_data_access_error(e);
      if (!f) return f.error();
      return {};
    }
    return detail::validate_data(e, opts, 0);
  });
  if (!ok) return ok.error();
  return list_view<access_result>::encoded(contents, &make_access_result);
}

result<list_view<data_ref>> decode_data_list(byte_view contents, const decode_options& opts) {
  auto ok = for_each_element(
      contents, [&](const ber::tlv& e) { return detail::validate_data(e, opts, 0); });
  if (!ok) return ok.error();
  return list_view<data_ref>::encoded(contents, &make_data_ref);
}

result<variable_access_specification> decode_vas(const ber::tlv& e) {
  if (e.tag == context(0, true)) {
    auto l = decode_list<variable_spec>(e.value, &decode_variable_spec);
    if (!l) return l.error();
    return variable_access_specification::list(*l);
  }
  if (e.tag == context(1, true)) {
    auto inner = single(e);
    if (!inner) return inner.error();
    auto name = decode_object_name(*inner);
    if (!name) return name.error();
    return variable_access_specification::named(*name);
  }
  return errc::malformed_encoding;
}

result<object_name> decode_wrapped_name(const ber::tlv& e) {
  auto inner = single(e);
  if (!inner) return inner.error();
  return decode_object_name(*inner);
}

result<service_error> decode_service_error(byte_view contents) {
  ber::reader rd{contents};
  auto cls = rd.expect(context(0, true));
  if (!cls) return cls.error();
  auto code = single(*cls);
  if (!code) return code.error();
  if (code->tag.cls != ber::tag_class::context || code->tag.number > 12 || code->tag.constructed) {
    return errc::malformed_encoding;
  }
  service_error se;
  se.cls = static_cast<error_class>(code->tag.number);
  auto c = ber::decode_integer(code->value);
  if (!c) return c.error();
  se.code = *c;
  if (rd.next_is(context(1))) {
    auto v = rd.read_integer(context(1));
    if (!v) return v.error();
    se.additional_code = *v;
  }
  if (rd.next_is(context(2))) {
    auto v = rd.read_visible_string(context(2));
    if (!v) return v.error();
    se.additional_description = *v;
  }
  auto info = next_if(rd, context(3, true));
  if (!info) return info.error();
  if (*info) se.service_specific_info = (*info)->value;
  if (auto r = rd.expect_end(); !r) return r.error();
  return se;
}

// ----- confirmed service requests -----

result<get_name_list_request> decode_get_name_list_request(ber::reader rd) {
  get_name_list_request req;
  auto oc = rd.expect(context(0, true));
  if (!oc) return oc.error();
  auto basic = single(*oc);
  if (!basic) return basic.error();
  if (basic->tag != context(0)) {
    return basic->tag.same_id(context(1)) ? errc::unsupported : errc::malformed_encoding;
  }
  auto cls = ber::decode_integer_as<std::uint8_t>(basic->value);
  if (!cls) return cls.error();
  req.cls = static_cast<object_class>(*cls);

  auto scope = rd.expect(context(1, true));
  if (!scope) return scope.error();
  auto s = single(*scope);
  if (!s) return s.error();
  if (s->tag == context(0) || s->tag == context(2)) {
    if (auto r = ber::decode_null(*s); !r) return r.error();
    req.scope = s->tag.number == 0 ? object_scope::vmd_specific : object_scope::aa_specific;
  } else if (s->tag.same_id(context(1))) {
    auto d = ber::decode_visible_string(*s);
    if (!d) return d.error();
    req.scope = object_scope::domain_specific;
    req.domain_id = *d;
  } else {
    return errc::malformed_encoding;
  }
  if (rd.next_is(context(2))) {
    auto ca = rd.read_visible_string(context(2));
    if (!ca) return ca.error();
    req.continue_after = *ca;
  }
  if (auto r = rd.expect_end(); !r) return r.error();
  return req;
}

result<read_request> decode_read_request(ber::reader rd) {
  read_request req;
  if (rd.next_is(context(0))) {
    auto v = rd.read_boolean(context(0));
    if (!v) return v.error();
    req.specification_with_result = *v;
  }
  auto spec = rd.expect(context(1, true));
  if (!spec) return spec.error();
  auto inner = single(*spec);
  if (!inner) return inner.error();
  auto vas = decode_vas(*inner);
  if (!vas) return vas.error();
  req.spec = *vas;
  if (auto r = rd.expect_end(); !r) return r.error();
  return req;
}

result<write_request> decode_write_request(ber::reader rd, const decode_options& opts) {
  write_request req;
  auto spec = rd.next();
  if (!spec) return spec.error();
  auto vas = decode_vas(*spec);
  if (!vas) return vas.error();
  req.spec = *vas;
  auto list = rd.expect(context(0, true));
  if (!list) return list.error();
  auto values = decode_data_list(list->value, opts);
  if (!values) return values.error();
  req.values = *values;
  if (auto r = rd.expect_end(); !r) return r.error();
  return req;
}

result<define_named_variable_list_request> decode_define_nvl_request(ber::reader rd) {
  define_named_variable_list_request req;
  auto name = rd.next();
  if (!name) return name.error();
  auto n = decode_object_name(*name);
  if (!n) return n.error();
  req.name = *n;
  auto list = rd.expect(context(0, true));
  if (!list) return list.error();
  auto vars = decode_list<variable_spec>(list->value, &decode_variable_spec);
  if (!vars) return vars.error();
  req.variables = *vars;
  if (auto r = rd.expect_end(); !r) return r.error();
  return req;
}

result<delete_named_variable_list_request> decode_delete_nvl_request(ber::reader rd) {
  delete_named_variable_list_request req;
  if (rd.next_is(context(0))) {
    auto s = read_int<std::uint8_t>(rd, context(0));
    if (!s) return s.error();
    if (*s > 3) return errc::value_out_of_range;
    req.scope = static_cast<delete_scope>(*s);
  }
  auto list = next_if(rd, context(1, true));
  if (!list) return list.error();
  if (*list) {
    auto names = decode_list<object_name>((*list)->value, &decode_object_name);
    if (!names) return names.error();
    req.names = *names;
  }
  if (rd.next_is(context(2))) {
    auto d = rd.read_visible_string(context(2));
    if (!d) return d.error();
    req.domain_name = *d;
  }
  if (auto r = rd.expect_end(); !r) return r.error();
  return req;
}

// ----- journal and file services -----

result<binary_time> decode_time_of_day(const ber::tlv& e) noexcept {
  if (e.tag.constructed) return errc::malformed_encoding;
  const auto c = e.value;
  if (c.size() != 4 && c.size() != 6) return errc::malformed_encoding;
  binary_time t;
  t.ms_of_day = (std::uint32_t{c[0]} << 24) | (std::uint32_t{c[1]} << 16) |
                (std::uint32_t{c[2]} << 8) | std::uint32_t{c[3]};
  if (c.size() == 6) t.days = static_cast<std::uint16_t>((c[4] << 8) | c[5]);
  return t;
}

result<binary_time> read_time_of_day(ber::reader& rd, ber::tag t) {
  auto e = rd.expect(t);
  if (!e) return e.error();
  return decode_time_of_day(*e);
}

result<std::string_view> decode_graphic_string(const ber::tlv& e) noexcept {
  if (!e.tag.same_id(ber::tags::graphic_string) && !e.tag.same_id(ber::tags::visible_string)) {
    return errc::malformed_encoding;
  }
  return ber::decode_visible_string(e);
}

result<std::string_view> decode_mms_string_element(const ber::tlv& e) noexcept {
  if (!e.tag.same_id(ber::tags::utf8_string)) return errc::malformed_encoding;
  return ber::decode_utf8_string(e);
}

result<list_view<std::string_view>> decode_file_name(const ber::tlv& e) noexcept {
  if (!e.tag.constructed) return errc::malformed_encoding;
  return decode_list<std::string_view>(e.value, &decode_graphic_string);
}

result<file_attributes> decode_file_attributes(const ber::tlv& e) noexcept {
  if (!e.tag.constructed) return errc::malformed_encoding;
  ber::reader rd{e.value};
  file_attributes a;
  auto size = read_int<std::uint32_t>(rd, context(0));
  if (!size) return size.error();
  a.size = *size;
  if (rd.next_is(context(1))) {
    auto t = rd.read_generalized_time(context(1));
    if (!t) return t.error();
    a.last_modified = *t;
  }
  if (auto r = rd.expect_end(); !r) return r.error();
  return a;
}

result<directory_entry> decode_directory_entry(const ber::tlv& e) noexcept {
  if (e.tag != ber::tags::sequence) return errc::malformed_encoding;
  ber::reader rd{e.value};
  auto name = rd.expect(context(0, true));
  if (!name) return name.error();
  auto n = decode_file_name(*name);
  if (!n) return n.error();
  auto attrs = rd.expect(context(1, true));
  if (!attrs) return attrs.error();
  auto a = decode_file_attributes(*attrs);
  if (!a) return a.error();
  if (auto r = rd.expect_end(); !r) return r.error();
  return directory_entry{*n, *a};
}

// Unchecked part of a Journal-Variable (the Data value is validated by validate_journal_entry).
result<journal_variable> decode_journal_variable(const ber::tlv& e) noexcept {
  if (e.tag != ber::tags::sequence) return errc::malformed_encoding;
  ber::reader rd{e.value};
  auto tag = rd.expect(context(0));
  if (!tag) return tag.error();
  auto value = rd.expect(context(1, true));
  if (!value) return value.error();
  auto inner = single(*value);
  if (!inner) return inner.error();
  if (auto r = rd.expect_end(); !r) return r.error();
  auto text = ber::decode_utf8_string(tag->value);
  if (!text) return text.error();
  return journal_variable{*text, data_ref{data_view::unchecked(*inner)}};
}

result<journal_entry> decode_journal_entry(const ber::tlv& e) noexcept {
  if (e.tag != ber::tags::sequence) return errc::malformed_encoding;
  ber::reader rd{e.value};
  journal_entry j;
  auto id = rd.read_octet_string(context(0));
  if (!id) return id.error();
  j.entry_id = *id;
  auto app = rd.expect(context(1, true));
  if (!app) return app.error();
  j.originating_application = app->value;
  auto content = rd.expect(context(2, true));
  if (!content) return content.error();
  if (auto r = rd.expect_end(); !r) return r.error();

  ber::reader c{content->value};
  auto t = read_time_of_day(c, context(0));
  if (!t) return t.error();
  j.occurrence_time = *t;
  if (c.next_is(context(1, true)) || c.next_is(context(1))) {  // additionalDetail
    if (auto r = c.skip(); !r) return r.error();
  }
  auto form = c.next();
  if (!form) return form.error();
  if (form->tag == context(2, true)) {
    ber::reader d{form->value};
    auto ev = next_if(d, context(0, true));
    if (!ev) return ev.error();
    if (*ev) j.event = (*ev)->value;
    auto vars = next_if(d, context(1, true));
    if (!vars) return vars.error();
    if (*vars) {
      auto l = decode_list<journal_variable>((*vars)->value, &decode_journal_variable);
      if (!l) return l.error();
      j.variables = *l;
    }
    if (auto r = d.expect_end(); !r) return r.error();
  } else if (form->tag.same_id(context(3))) {
    // annotation [3] MMSString: explicit tag (also accepted implicit).
    if (form->tag.constructed) {
      auto inner = single(*form);
      if (!inner) return inner.error();
      auto s = decode_mms_string_element(*inner);
      if (!s) return s.error();
      j.annotation = *s;
    } else {
      auto s = ber::decode_utf8_string(form->value);
      if (!s) return s.error();
      j.annotation = *s;
    }
  } else {
    return errc::malformed_encoding;
  }
  if (auto r = c.expect_end(); !r) return r.error();
  return j;
}

// Validates the Data values of a JournalEntry (decode_journal_entry checks everything else).
result<void> validate_journal_entry(const ber::tlv& e, const decode_options& opts) {
  auto j = decode_journal_entry(e);
  if (!j) return j.error();
  for (const auto v : j->variables) {
    const auto& view = v.value.view();
    auto tlv = ber::decode_tlv(view.encoding());
    if (!tlv) return tlv.error();
    if (auto r = detail::validate_data(*tlv, opts, 0); !r) return r.error();
  }
  return {};
}

result<read_journal_request> decode_read_journal_request(ber::reader rd) {
  read_journal_request req;
  auto name = rd.expect(context(0, true));
  if (!name) return name.error();
  auto n = decode_wrapped_name(*name);
  if (!n) return n.error();
  req.journal_name = *n;
  auto start = next_if(rd, context(1, true));
  if (!start) return start.error();
  if (*start) {
    auto inner = single(**start);
    if (!inner) return inner.error();
    if (inner->tag.same_id(context(0))) {
      auto t = decode_time_of_day(*inner);
      if (!t) return t.error();
      req.starting_time = *t;
    } else if (inner->tag.same_id(context(1))) {
      auto o = ber::decode_octet_string(*inner);
      if (!o) return o.error();
      req.starting_entry = *o;
    } else {
      return errc::malformed_encoding;
    }
  }
  auto stop = next_if(rd, context(2, true));
  if (!stop) return stop.error();
  if (*stop) {
    auto inner = single(**stop);
    if (!inner) return inner.error();
    if (inner->tag.same_id(context(0))) {
      auto t = decode_time_of_day(*inner);
      if (!t) return t.error();
      req.ending_time = *t;
    } else if (inner->tag == context(1)) {
      auto v = ber::decode_integer_as<std::int32_t>(inner->value);
      if (!v) return v.error();
      req.number_of_entries = *v;
    } else {
      return errc::malformed_encoding;
    }
  }
  auto vars = next_if(rd, context(4, true));
  if (!vars) return vars.error();
  if (*vars) {
    auto l = decode_list<std::string_view>((*vars)->value, &decode_identifier);
    if (!l) return l.error();
    req.variables = *l;
  }
  auto after = next_if(rd, context(5, true));
  if (!after) return after.error();
  if (*after) {
    ber::reader a{(*after)->value};
    auto t = read_time_of_day(a, context(0));
    if (!t) return t.error();
    auto entry = a.read_octet_string(context(1));
    if (!entry) return entry.error();
    if (auto r = a.expect_end(); !r) return r.error();
    req.start_after = journal_start_after{*t, *entry};
  }
  if (auto r = rd.expect_end(); !r) return r.error();
  return req;
}

result<initialize_journal_request> decode_initialize_journal_request(ber::reader rd) {
  initialize_journal_request req;
  auto name = rd.expect(context(0, true));
  if (!name) return name.error();
  auto n = decode_wrapped_name(*name);
  if (!n) return n.error();
  req.journal_name = *n;
  auto limit = next_if(rd, context(1, true));
  if (!limit) return limit.error();
  if (*limit) {
    ber::reader l{(*limit)->value};
    auto t = read_time_of_day(l, context(0));
    if (!t) return t.error();
    req.limiting_time = *t;
    if (l.next_is(context(1))) {
      auto entry = l.read_octet_string(context(1));
      if (!entry) return entry.error();
      req.limiting_entry = *entry;
    }
    if (auto r = l.expect_end(); !r) return r.error();
  }
  if (auto r = rd.expect_end(); !r) return r.error();
  return req;
}

result<file_open_request> decode_file_open_request(ber::reader rd) {
  file_open_request req;
  auto name = rd.expect(context(0, true));
  if (!name) return name.error();
  auto n = decode_file_name(*name);
  if (!n) return n.error();
  req.file_name = *n;
  auto pos = read_int<std::uint32_t>(rd, context(1));
  if (!pos) return pos.error();
  req.initial_position = *pos;
  if (auto r = rd.expect_end(); !r) return r.error();
  return req;
}

result<file_rename_request> decode_file_rename_request(ber::reader rd) {
  file_rename_request req;
  auto cur = rd.expect(context(0, true));
  if (!cur) return cur.error();
  auto c = decode_file_name(*cur);
  if (!c) return c.error();
  auto next = rd.expect(context(1, true));
  if (!next) return next.error();
  auto n = decode_file_name(*next);
  if (!n) return n.error();
  if (auto r = rd.expect_end(); !r) return r.error();
  req.current_name = *c;
  req.new_name = *n;
  return req;
}

result<file_directory_request> decode_file_directory_request(ber::reader rd) {
  file_directory_request req;
  auto spec = next_if(rd, context(0, true));
  if (!spec) return spec.error();
  if (*spec) {
    auto n = decode_file_name(**spec);
    if (!n) return n.error();
    req.file_specification = *n;
  }
  auto after = next_if(rd, context(1, true));
  if (!after) return after.error();
  if (*after) {
    auto n = decode_file_name(**after);
    if (!n) return n.error();
    req.continue_after = *n;
  }
  if (auto r = rd.expect_end(); !r) return r.error();
  return req;
}

result<read_journal_response> decode_read_journal_response(ber::reader rd,
                                                           const decode_options& opts) {
  read_journal_response resp;
  auto list = rd.expect(context(0, true));
  if (!list) return list.error();
  auto ok = for_each_element(list->value,
                             [&](const ber::tlv& e) { return validate_journal_entry(e, opts); });
  if (!ok) return ok.error();
  resp.entries = list_view<journal_entry>::encoded(list->value, &decode_journal_entry);
  if (rd.next_is(context(1))) {
    auto more = rd.read_boolean(context(1));
    if (!more) return more.error();
    resp.more_follows = *more;
  }
  if (auto r = rd.expect_end(); !r) return r.error();
  return resp;
}

result<report_journal_status_response> decode_report_journal_status_response(ber::reader rd) {
  report_journal_status_response resp;
  auto n = read_int<std::uint32_t>(rd, context(0));
  if (!n) return n.error();
  auto del = rd.read_boolean(context(1));
  if (!del) return del.error();
  resp.current_entries = *n;
  resp.mms_deletable = *del;
  if (rd.next_is(context(2))) {  // accessControlList
    if (auto r = rd.skip(); !r) return r.error();
  }
  if (auto r = rd.expect_end(); !r) return r.error();
  return resp;
}

result<file_open_response> decode_file_open_response(ber::reader rd) {
  file_open_response resp;
  auto id = read_int<std::int32_t>(rd, context(0));
  if (!id) return id.error();
  resp.frsm_id = *id;
  auto attrs = rd.expect(context(1, true));
  if (!attrs) return attrs.error();
  auto a = decode_file_attributes(*attrs);
  if (!a) return a.error();
  resp.attributes = *a;
  if (auto r = rd.expect_end(); !r) return r.error();
  return resp;
}

result<file_read_response> decode_file_read_response(ber::reader rd) {
  file_read_response resp;
  auto data = rd.read_octet_string(context(0));
  if (!data) return data.error();
  resp.data = *data;
  if (rd.next_is(context(1))) {
    auto more = rd.read_boolean(context(1));
    if (!more) return more.error();
    resp.more_follows = *more;
  }
  if (auto r = rd.expect_end(); !r) return r.error();
  return resp;
}

result<file_directory_response> decode_file_directory_response(ber::reader rd) {
  file_directory_response resp;
  auto outer = rd.expect(context(0, true));
  if (!outer) return outer.error();
  auto list = single(*outer);
  if (!list) return list.error();
  if (list->tag != ber::tags::sequence) return errc::malformed_encoding;
  auto entries = decode_list<directory_entry>(list->value, &decode_directory_entry);
  if (!entries) return entries.error();
  resp.entries = *entries;
  if (rd.next_is(context(1))) {
    auto more = rd.read_boolean(context(1));
    if (!more) return more.error();
    resp.more_follows = *more;
  }
  if (auto r = rd.expect_end(); !r) return r.error();
  return resp;
}

bool is_ext_service(std::uint32_t tag) noexcept {
  switch (static_cast<confirmed_service>(tag)) {
    case confirmed_service::read_journal:
    case confirmed_service::initialize_journal:
    case confirmed_service::report_journal_status:
    case confirmed_service::file_open:
    case confirmed_service::file_read:
    case confirmed_service::file_close:
    case confirmed_service::file_rename:
    case confirmed_service::file_delete:
    case confirmed_service::file_directory:
      return tag >= 65 && tag <= 77;
    default:
      return false;
  }
}

template <typename T>
result<confirmed_service_request> as_request(result<T> r);
template <typename T>
result<confirmed_service_response> as_response(result<T> r);

result<std::int32_t> decode_i32(const ber::tlv& e) {
  if (e.tag.constructed) return errc::malformed_encoding;
  return ber::decode_integer_as<std::int32_t>(e.value);
}

result<confirmed_service_request> decode_ext_request(const ber::tlv& e) {
  const auto svc = static_cast<confirmed_service>(e.tag.number);
  if (svc == confirmed_service::file_read || svc == confirmed_service::file_close) {
    auto id = decode_i32(e);
    if (!id) return id.error();
    if (svc == confirmed_service::file_read) return confirmed_service_request{file_read_request{*id}};
    return confirmed_service_request{file_close_request{*id}};
  }
  if (!e.tag.constructed) return errc::malformed_encoding;
  const ber::reader rd{e.value};
  switch (svc) {
    case confirmed_service::read_journal:
      return as_request(decode_read_journal_request(rd));
    case confirmed_service::initialize_journal:
      return as_request(decode_initialize_journal_request(rd));
    case confirmed_service::report_journal_status: {
      auto name = decode_wrapped_name(e);
      if (!name) return name.error();
      return confirmed_service_request{report_journal_status_request{*name}};
    }
    case confirmed_service::file_open:
      return as_request(decode_file_open_request(rd));
    case confirmed_service::file_rename:
      return as_request(decode_file_rename_request(rd));
    case confirmed_service::file_delete: {
      auto n = decode_file_name(e);
      if (!n) return n.error();
      return confirmed_service_request{file_delete_request{*n}};
    }
    case confirmed_service::file_directory:
      return as_request(decode_file_directory_request(rd));
    default:
      return errc::malformed_encoding;
  }
}

result<confirmed_service_response> decode_ext_response(const ber::tlv& e,
                                                       const decode_options& opts) {
  const auto svc = static_cast<confirmed_service>(e.tag.number);
  switch (svc) {
    case confirmed_service::initialize_journal: {
      if (e.tag.constructed) return errc::malformed_encoding;
      auto n = ber::decode_integer_as<std::uint32_t>(e.value);
      if (!n) return n.error();
      return confirmed_service_response{initialize_journal_response{*n}};
    }
    case confirmed_service::file_close:
    case confirmed_service::file_rename:
    case confirmed_service::file_delete:
      if (auto r = ber::decode_null(e); !r) return r.error();
      if (svc == confirmed_service::file_close) return confirmed_service_response{file_close_response{}};
      if (svc == confirmed_service::file_rename) {
        return confirmed_service_response{file_rename_response{}};
      }
      return confirmed_service_response{file_delete_response{}};
    default:
      break;
  }
  if (!e.tag.constructed) return errc::malformed_encoding;
  const ber::reader rd{e.value};
  switch (svc) {
    case confirmed_service::read_journal:
      return as_response(decode_read_journal_response(rd, opts));
    case confirmed_service::report_journal_status:
      return as_response(decode_report_journal_status_response(rd));
    case confirmed_service::file_open:
      return as_response(decode_file_open_response(rd));
    case confirmed_service::file_read:
      return as_response(decode_file_read_response(rd));
    case confirmed_service::file_directory:
      return as_response(decode_file_directory_response(rd));
    default:
      return errc::malformed_encoding;
  }
}

template <typename T>
result<confirmed_service_request> as_request(result<T> r) {
  if (!r) return r.error();
  return confirmed_service_request{std::move(*r)};
}

template <typename T>
result<confirmed_service_response> as_response(result<T> r) {
  if (!r) return r.error();
  return confirmed_service_response{std::move(*r)};
}

result<confirmed_service_request> decode_service_request(const ber::tlv& e,
                                                         const decode_options& opts) {
  if (e.tag.cls != ber::tag_class::context) return errc::malformed_encoding;
  const auto svc = static_cast<confirmed_service>(e.tag.number);
  const bool known = e.tag.number <= 13 &&
                     (svc == confirmed_service::get_name_list || svc == confirmed_service::identify ||
                      svc == confirmed_service::read || svc == confirmed_service::write ||
                      svc == confirmed_service::get_variable_access_attributes ||
                      svc == confirmed_service::define_named_variable_list ||
                      svc == confirmed_service::get_named_variable_list_attributes ||
                      svc == confirmed_service::delete_named_variable_list);
  if (!known) {
    if (is_ext_service(e.tag.number)) return decode_ext_request(e);
    return confirmed_service_request{other_service{e.tag.number, e.encoding}};
  }
  if (svc == confirmed_service::identify) {
    if (auto r = ber::decode_null(e); !r) return r.error();
    return confirmed_service_request{identify_request{}};
  }
  if (!e.tag.constructed) return errc::malformed_encoding;
  const ber::reader rd{e.value};
  switch (svc) {
    case confirmed_service::get_name_list:
      return as_request(decode_get_name_list_request(rd));
    case confirmed_service::read:
      return as_request(decode_read_request(rd));
    case confirmed_service::write:
      return as_request(decode_write_request(rd, opts));
    case confirmed_service::get_variable_access_attributes: {
      auto choice = single(e);
      if (!choice) return choice.error();
      if (choice->tag.same_id(context(1))) return errc::unsupported;  // address
      if (choice->tag != context(0, true)) return errc::malformed_encoding;
      auto name = decode_wrapped_name(*choice);
      if (!name) return name.error();
      return confirmed_service_request{get_variable_access_attributes_request{*name}};
    }
    case confirmed_service::define_named_variable_list:
      return as_request(decode_define_nvl_request(rd));
    case confirmed_service::get_named_variable_list_attributes: {
      auto name = decode_wrapped_name(e);
      if (!name) return name.error();
      return confirmed_service_request{get_named_variable_list_attributes_request{*name}};
    }
    case confirmed_service::delete_named_variable_list:
      return as_request(decode_delete_nvl_request(rd));
    default:
      return errc::malformed_encoding;
  }
}

// ----- confirmed service responses -----

result<get_name_list_response> decode_get_name_list_response(ber::reader rd) {
  get_name_list_response resp;
  auto list = rd.expect(context(0, true));
  if (!list) return list.error();
  auto ids = decode_list<std::string_view>(list->value, &decode_identifier);
  if (!ids) return ids.error();
  resp.identifiers = *ids;
  if (rd.next_is(context(1))) {
    auto more = rd.read_boolean(context(1));
    if (!more) return more.error();
    resp.more_follows = *more;
  }
  if (auto r = rd.expect_end(); !r) return r.error();
  return resp;
}

result<identify_response> decode_identify_response(ber::reader rd) {
  identify_response resp;
  auto vendor = rd.read_utf8_string(context(0));
  if (!vendor) return vendor.error();
  auto model = rd.read_utf8_string(context(1));
  if (!model) return model.error();
  auto revision = rd.read_utf8_string(context(2));
  if (!revision) return revision.error();
  resp.vendor_name = *vendor;
  resp.model_name = *model;
  resp.revision = *revision;
  auto list = next_if(rd, context(3, true));
  if (!list) return list.error();
  if (*list) {
    auto oids = decode_list<ber::oid>((*list)->value, &decode_oid_element);
    if (!oids) return oids.error();
    resp.abstract_syntaxes = *oids;
  }
  if (auto r = rd.expect_end(); !r) return r.error();
  return resp;
}

result<read_response> decode_read_response(ber::reader rd, const decode_options& opts) {
  read_response resp;
  auto spec = next_if(rd, context(0, true));
  if (!spec) return spec.error();
  if (*spec) {
    auto inner = single(**spec);
    if (!inner) return inner.error();
    auto vas = decode_vas(*inner);
    if (!vas) return vas.error();
    resp.spec = *vas;
  }
  auto list = rd.expect(context(1, true));
  if (!list) return list.error();
  auto results = decode_access_results(list->value, opts);
  if (!results) return results.error();
  resp.results = *results;
  if (auto r = rd.expect_end(); !r) return r.error();
  return resp;
}

result<get_variable_access_attributes_response> decode_gvaa_response(ber::reader rd,
                                                                     const decode_options& opts) {
  get_variable_access_attributes_response resp;
  auto deletable = rd.read_boolean(context(0));
  if (!deletable) return deletable.error();
  resp.mms_deletable = *deletable;
  if (rd.next_is(context(1, true))) {  // address
    if (auto r = rd.skip(); !r) return r.error();
  }
  auto td = rd.expect(context(2, true));
  if (!td) return td.error();
  auto inner = single(*td);
  if (!inner) return inner.error();
  auto type = type_description::decode(*inner, opts);
  if (!type) return type.error();
  resp.type = std::move(*type);
  // accessControlList [3] and meaning [4] (ISO 9506-2:2003) are ignored.
  while (!rd.empty()) {
    auto t = rd.peek_tag();
    if (!t) return t.error();
    if (t->cls != ber::tag_class::context || t->number < 3) return errc::malformed_encoding;
    if (auto r = rd.skip(); !r) return r.error();
  }
  return resp;
}

result<get_named_variable_list_attributes_response> decode_gnvla_response(ber::reader rd) {
  get_named_variable_list_attributes_response resp;
  auto deletable = rd.read_boolean(context(0));
  if (!deletable) return deletable.error();
  resp.mms_deletable = *deletable;
  auto list = rd.expect(context(1, true));
  if (!list) return list.error();
  auto vars = decode_list<variable_spec>(list->value, &decode_variable_spec);
  if (!vars) return vars.error();
  resp.variables = *vars;
  if (rd.next_is(context(2))) {  // accessControlList
    if (auto r = rd.skip(); !r) return r.error();
  }
  if (auto r = rd.expect_end(); !r) return r.error();
  return resp;
}

result<delete_named_variable_list_response> decode_delete_nvl_response(ber::reader rd) {
  delete_named_variable_list_response resp;
  auto matched = read_int<std::uint32_t>(rd, context(0));
  if (!matched) return matched.error();
  auto deleted = read_int<std::uint32_t>(rd, context(1));
  if (!deleted) return deleted.error();
  resp.number_matched = *matched;
  resp.number_deleted = *deleted;
  if (auto r = rd.expect_end(); !r) return r.error();
  return resp;
}

result<confirmed_service_response> decode_service_response(const ber::tlv& e,
                                                           const decode_options& opts) {
  if (e.tag.cls != ber::tag_class::context) return errc::malformed_encoding;
  const auto svc = static_cast<confirmed_service>(e.tag.number);
  const bool known = e.tag.number <= 13 &&
                     (svc == confirmed_service::get_name_list || svc == confirmed_service::identify ||
                      svc == confirmed_service::read || svc == confirmed_service::write ||
                      svc == confirmed_service::get_variable_access_attributes ||
                      svc == confirmed_service::define_named_variable_list ||
                      svc == confirmed_service::get_named_variable_list_attributes ||
                      svc == confirmed_service::delete_named_variable_list);
  if (!known) {
    if (is_ext_service(e.tag.number)) return decode_ext_response(e, opts);
    return confirmed_service_response{other_service{e.tag.number, e.encoding}};
  }
  if (svc == confirmed_service::define_named_variable_list) {
    if (auto r = ber::decode_null(e); !r) return r.error();
    return confirmed_service_response{define_named_variable_list_response{}};
  }
  if (!e.tag.constructed) return errc::malformed_encoding;
  const ber::reader rd{e.value};
  switch (svc) {
    case confirmed_service::get_name_list:
      return as_response(decode_get_name_list_response(rd));
    case confirmed_service::identify:
      return as_response(decode_identify_response(rd));
    case confirmed_service::read:
      return as_response(decode_read_response(rd, opts));
    case confirmed_service::write: {
      auto results = decode_list<write_result>(e.value, &decode_write_result);
      if (!results) return results.error();
      return confirmed_service_response{write_response{*results}};
    }
    case confirmed_service::get_variable_access_attributes:
      return as_response(decode_gvaa_response(rd, opts));
    case confirmed_service::get_named_variable_list_attributes:
      return as_response(decode_gnvla_response(rd));
    case confirmed_service::delete_named_variable_list:
      return as_response(decode_delete_nvl_response(rd));
    default:
      return errc::malformed_encoding;
  }
}

// ----- PDUs -----

result<void> skip_extension(ber::reader& rd) {
  if (rd.next_is(context(79, true))) return rd.skip();  // service-ext
  return {};
}

result<mms_pdu> decode_confirmed_request(ber::reader rd, const decode_options& opts) {
  confirmed_request pdu;
  auto id = read_int<std::uint32_t>(rd, ber::tags::integer);
  if (!id) return id.error();
  pdu.invoke_id = *id;
  auto modifiers = next_if(rd, ber::tags::sequence);
  if (!modifiers) return modifiers.error();
  if (*modifiers) pdu.modifiers = (*modifiers)->value;
  auto svc = rd.next();
  if (!svc) return svc.error();
  auto service = decode_service_request(*svc, opts);
  if (!service) return service.error();
  pdu.service = std::move(*service);
  if (auto r = skip_extension(rd); !r) return r.error();
  if (auto r = rd.expect_end(); !r) return r.error();
  return mms_pdu{std::move(pdu)};
}

result<mms_pdu> decode_confirmed_response(ber::reader rd, const decode_options& opts) {
  confirmed_response pdu;
  auto id = read_int<std::uint32_t>(rd, ber::tags::integer);
  if (!id) return id.error();
  pdu.invoke_id = *id;
  auto svc = rd.next();
  if (!svc) return svc.error();
  auto service = decode_service_response(*svc, opts);
  if (!service) return service.error();
  pdu.service = std::move(*service);
  if (auto r = skip_extension(rd); !r) return r.error();
  if (auto r = rd.expect_end(); !r) return r.error();
  return mms_pdu{std::move(pdu)};
}

result<mms_pdu> decode_confirmed_error(ber::reader rd) {
  confirmed_error pdu;
  auto id = read_int<std::uint32_t>(rd, context(0));
  if (!id) return id.error();
  pdu.invoke_id = *id;
  if (rd.next_is(context(1))) {
    auto mp = read_int<std::uint32_t>(rd, context(1));
    if (!mp) return mp.error();
    pdu.modifier_position = *mp;
  }
  auto se = rd.expect(context(2, true));
  if (!se) return se.error();
  auto err = decode_service_error(se->value);
  if (!err) return err.error();
  pdu.error = *err;
  if (auto r = rd.expect_end(); !r) return r.error();
  return mms_pdu{pdu};
}

result<mms_pdu> decode_unconfirmed(ber::reader rd, const decode_options& opts) {
  unconfirmed_pdu pdu;
  auto svc = rd.next();
  if (!svc) return svc.error();
  if (svc->tag == context(0, true)) {
    ber::reader body{svc->value};
    information_report report;
    auto spec = body.next();
    if (!spec) return spec.error();
    auto vas = decode_vas(*spec);
    if (!vas) return vas.error();
    report.spec = *vas;
    auto list = body.expect(context(0, true));
    if (!list) return list.error();
    auto results = decode_access_results(list->value, opts);
    if (!results) return results.error();
    report.results = *results;
    if (auto r = body.expect_end(); !r) return r.error();
    pdu.service = report;
  } else if (svc->tag.cls == ber::tag_class::context) {
    pdu.service = other_service{svc->tag.number, svc->encoding};
  } else {
    return errc::malformed_encoding;
  }
  if (auto r = skip_extension(rd); !r) return r.error();
  if (auto r = rd.expect_end(); !r) return r.error();
  return mms_pdu{pdu};
}

result<mms_pdu> decode_reject(ber::reader rd) {
  reject_pdu pdu;
  if (rd.next_is(context(0))) {
    auto id = read_int<std::uint32_t>(rd, context(0));
    if (!id) return id.error();
    pdu.original_invoke_id = *id;
  }
  auto reason = rd.next();
  if (!reason) return reason.error();
  if (reason->tag.cls != ber::tag_class::context || reason->tag.constructed ||
      reason->tag.number < 1 || reason->tag.number > 11) {
    return errc::malformed_encoding;
  }
  pdu.type = static_cast<reject_type>(reason->tag.number);
  auto code = ber::decode_integer(reason->value);
  if (!code) return code.error();
  pdu.reason = *code;
  if (auto r = rd.expect_end(); !r) return r.error();
  return mms_pdu{pdu};
}

template <typename Pdu>
result<mms_pdu> decode_initiate(ber::reader rd) {
  Pdu pdu;
  if (rd.next_is(context(0))) {
    auto v = read_int<std::int32_t>(rd, context(0));
    if (!v) return v.error();
    if constexpr (std::is_same_v<Pdu, initiate_request>) {
      pdu.local_detail_calling = *v;
    } else {
      pdu.local_detail_called = *v;
    }
  } else {
    if constexpr (std::is_same_v<Pdu, initiate_request>) {
      pdu.local_detail_calling.reset();
    } else {
      pdu.local_detail_called.reset();
    }
  }
  auto calling = read_int<std::int16_t>(rd, context(1));
  if (!calling) return calling.error();
  auto called = read_int<std::int16_t>(rd, context(2));
  if (!called) return called.error();
  pdu.max_serv_outstanding_calling = *calling;
  pdu.max_serv_outstanding_called = *called;
  pdu.data_structure_nesting_level.reset();
  if (rd.next_is(context(3))) {
    auto v = read_int<std::int8_t>(rd, context(3));
    if (!v) return v.error();
    pdu.data_structure_nesting_level = *v;
  }
  auto detail = rd.enter(context(4, true));
  if (!detail) return detail.error();
  auto version = read_int<std::int16_t>(*detail, context(0));
  if (!version) return version.error();
  auto cbb = detail->read_bit_string(context(1));
  if (!cbb) return cbb.error();
  auto services = detail->read_bit_string(context(2));
  if (!services) return services.error();
  // Additional CS fields ([3]..[5], ISO 9506-2 §8.2.1.1.4) are ignored.
  pdu.detail.version_number = *version;
  pdu.detail.parameter_cbb = support_options::from_bits(*cbb);
  pdu.detail.services = support_options::from_bits(*services);
  if (auto r = rd.expect_end(); !r) return r.error();
  return mms_pdu{pdu};
}

result<service_error> decode_error_body(const ber::tlv& e) {
  if (!e.tag.constructed) return errc::malformed_encoding;
  return decode_service_error(e.value);
}

result<std::uint32_t> decode_u32(const ber::tlv& e) {
  if (e.tag.constructed) return errc::malformed_encoding;
  return ber::decode_integer_as<std::uint32_t>(e.value);
}

}  // namespace

result<mms_pdu> decode_pdu(byte_view input, const decode_options& opts) {
  auto e = ber::decode_tlv(input);
  if (!e) return e.error();
  if (e->encoding.size() != input.size()) return errc::malformed_encoding;
  if (e->tag.cls != ber::tag_class::context) return errc::malformed_encoding;
  if (e->tag.number > 13) return errc::unsupported;
  const auto type = static_cast<pdu_type>(e->tag.number);

  switch (type) {
    case pdu_type::cancel_request:
    case pdu_type::cancel_response: {
      auto id = decode_u32(*e);
      if (!id) return id.error();
      if (type == pdu_type::cancel_request) return mms_pdu{cancel_request{*id}};
      return mms_pdu{cancel_response{*id}};
    }
    case pdu_type::conclude_request:
    case pdu_type::conclude_response:
      if (auto r = ber::decode_null(*e); !r) return r.error();
      if (type == pdu_type::conclude_request) return mms_pdu{conclude_request{}};
      return mms_pdu{conclude_response{}};
    case pdu_type::initiate_error:
    case pdu_type::conclude_error: {
      auto se = decode_error_body(*e);
      if (!se) return se.error();
      if (type == pdu_type::initiate_error) return mms_pdu{initiate_error{*se}};
      return mms_pdu{conclude_error{*se}};
    }
    default:
      break;
  }

  if (!e->tag.constructed) return errc::malformed_encoding;
  ber::reader rd{e->value};
  switch (type) {
    case pdu_type::confirmed_request:
      return decode_confirmed_request(rd, opts);
    case pdu_type::confirmed_response:
      return decode_confirmed_response(rd, opts);
    case pdu_type::confirmed_error:
      return decode_confirmed_error(rd);
    case pdu_type::unconfirmed:
      return decode_unconfirmed(rd, opts);
    case pdu_type::reject:
      return decode_reject(rd);
    case pdu_type::cancel_error: {
      cancel_error pdu;
      auto id = read_int<std::uint32_t>(rd, context(0));
      if (!id) return id.error();
      pdu.invoke_id = *id;
      auto se = rd.expect(context(1, true));
      if (!se) return se.error();
      auto err = decode_service_error(se->value);
      if (!err) return err.error();
      pdu.error = *err;
      if (auto r = rd.expect_end(); !r) return r.error();
      return mms_pdu{pdu};
    }
    case pdu_type::initiate_request:
      return decode_initiate<initiate_request>(rd);
    case pdu_type::initiate_response:
      return decode_initiate<initiate_response>(rd);
    default:
      return errc::malformed_encoding;
  }
}

result<std::uint32_t> peek_invoke_id(byte_view input) noexcept {
  auto e = ber::decode_tlv(input);
  if (!e) return e.error();
  if (e->tag.cls != ber::tag_class::context || !e->tag.constructed) {
    return errc::malformed_encoding;
  }
  ber::reader rd{e->value};
  switch (e->tag.number) {
    case 0:
    case 1:
      return read_int<std::uint32_t>(rd, ber::tags::integer);
    case 2:
      return read_int<std::uint32_t>(rd, context(0));
    default:
      return errc::malformed_encoding;
  }
}

support_options support_options::from_bits(const ber::bit_string_view& bits) noexcept {
  support_options s{bits.bit_count};
  const std::size_t n = (s.bit_count_ + 7) / 8;
  for (std::size_t i = 0; i < n && i < bits.bytes.size(); ++i) s.bytes_[i] = bits.bytes[i];
  if (s.bit_count_ % 8 != 0) {
    s.bytes_[n - 1] = static_cast<std::uint8_t>(s.bytes_[n - 1] & (0xFFU << (8 - s.bit_count_ % 8)));
  }
  return s;
}

support_options support_options::intersect(const support_options& other) const noexcept {
  support_options s{bit_count_ > other.bit_count_ ? bit_count_ : other.bit_count_};
  for (std::size_t i = 0; i < s.bytes_.size(); ++i) {
    s.bytes_[i] = static_cast<std::uint8_t>(bytes_[i] & other.bytes_[i]);
  }
  return s;
}

}  // namespace openiec61850::mms
