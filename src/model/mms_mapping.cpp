#include "openiec61850/model/mms_mapping.hpp"

#include <vector>

#include "openiec61850/ber/reader.hpp"
#include "openiec61850/ber/writer.hpp"

namespace openiec61850::model {
namespace {

// Bound on nested AlternateAccess levels accepted from the peer.
constexpr std::size_t max_alternate_access_depth = 128;

result<std::string> build_item(const object_reference& ref, std::vector<access_selector>* alt,
                               const name_limits& limits, bool inline_index = false) {
  if (ref.empty() || ref.is_association_specific() || !ref.has_ln()) return errc::invalid_state;
  const auto path = ref.path();
  std::string item{ref.ln()};
  if (const auto f = ref.fc()) {
    if (*f == fc::XX) return errc::invalid_state;
    item.push_back('$');
    item.append(to_string(*f));
  } else if (!path.empty()) {
    return errc::invalid_state;
  }
  bool in_alt = false;
  for (const auto e : path) {
    if (in_alt) {
      alt->push_back({e.name, std::nullopt});
      if (e.index) alt->push_back({{}, e.index});
      continue;
    }
    item.push_back('$');
    item.append(e.name);
    if (e.index && inline_index) {
      item.push_back('(');
      item.append(std::to_string(*e.index));
      item.push_back(')');
    } else if (e.index) {
      if (alt == nullptr) return errc::invalid_state;
      alt->push_back({{}, e.index});
      in_alt = true;
    }
  }
  if (ref.ld().size() > limits.max_mms_identifier || item.size() > limits.max_mms_identifier) {
    return errc::length_overflow;
  }
  return item;
}

void append_index(std::string& text, std::uint32_t v) {
  text.push_back('(');
  text.append(std::to_string(v));
  text.push_back(')');
}

result<std::uint32_t> read_index(const ber::tlv& e) {
  if (e.constructed()) return errc::malformed_encoding;
  auto v = ber::decode_integer_as<std::uint32_t>(e.value);
  if (!v) return errc::malformed_encoding;
  return *v;
}

result<void> append_selector(std::string& text, const ber::tlv& e, bool is_index) {
  if (is_index) {
    auto v = read_index(e);
    if (!v) return v.error();
    if (text.ends_with(')')) return errc::unsupported;  // multi-dimensional
    append_index(text, *v);
    return {};
  }
  auto name = ber::decode_visible_string(e);
  if (!name) return errc::malformed_encoding;
  if (!is_identifier(*name)) return errc::malformed_encoding;
  text.push_back('.');
  text.append(*name);
  return {};
}

// Appends ".name" / "(n)" for each selector of an AlternateAccess (contents octets).
result<void> decode_alternate_access(byte_view contents, std::string& text) {
  byte_view cur = contents;
  for (std::size_t depth = 0;; ++depth) {
    if (depth >= max_alternate_access_depth) return errc::nesting_too_deep;
    ber::reader rd{cur};
    auto e = rd.next();
    if (!e) return e.error();
    if (!rd.empty()) return errc::unsupported;  // more than one selection
    const auto t = e->tag;
    if (t == ber::context(0, true)) {  // selectAlternateAccess
      auto inner = rd.enter(*e);
      if (!inner) return inner.error();
      auto sel = inner->next();
      if (!sel) return sel.error();
      if (sel->tag.same_id(ber::context(0)) || sel->tag.same_id(ber::context(1))) {
        if (auto r = append_selector(text, *sel, sel->tag.number == 1); !r) return r;
      } else if (sel->tag.same_id(ber::context(2)) || sel->tag.same_id(ber::context(3))) {
        return errc::unsupported;  // indexRange, allElements
      } else {
        return errc::malformed_encoding;
      }
      auto seq = inner->expect(ber::tags::sequence);
      if (!seq) return seq.error();
      if (auto end = inner->expect_end(); !end) return end;
      cur = seq->value;
      continue;
    }
    if (t.same_id(ber::context(1)) || t.same_id(ber::context(2))) {  // selectAccess
      return append_selector(text, *e, t.number == 2);
    }
    if (t.same_id(ber::context(3)) || t.same_id(ber::context(4)) || t.same_id(ber::context(5))) {
      return errc::unsupported;  // indexRange, allElements, named
    }
    return errc::malformed_encoding;
  }
}

// Splits the index off "name(n)" (`index` is left empty without one). Only the canonical decimal
// form is accepted: the text must map back to itself.
result<std::string_view> split_index(std::string_view segment, std::string_view& index) {
  index = {};
  if (!segment.ends_with(')')) return segment;
  const auto open = segment.find('(');
  if (open == std::string_view::npos) return errc::malformed_encoding;
  const auto digits = segment.substr(open + 1, segment.size() - open - 2);
  if (digits.empty() || (digits.size() > 1 && digits.front() == '0')) return errc::malformed_encoding;
  for (const char c : digits) {
    if (c < '0' || c > '9') return errc::malformed_encoding;
  }
  index = segment.substr(open);
  return segment.substr(0, open);
}

result<object_reference> from_domain_item(std::string_view domain, std::string_view item,
                                          byte_view alt, const parse_options& opts,
                                          bool inline_index = false) {
  if (domain.size() > opts.limits.max_mms_identifier ||
      item.size() > opts.limits.max_mms_identifier) {
    return errc::length_overflow;
  }
  if (!is_identifier(domain)) return errc::malformed_encoding;
  std::string text{domain};
  text.push_back('/');
  std::optional<functional_constraint> f;
  std::size_t pos = 0;
  for (std::size_t seg = 0; pos <= item.size(); ++seg) {
    auto end = item.find('$', pos);
    if (end == std::string_view::npos) end = item.size();
    const auto name = item.substr(pos, end - pos);
    if (seg == 1) {
      f = parse_functional_constraint(name);
      if (!f || *f == fc::XX) return errc::malformed_encoding;
    } else {
      std::string_view index;
      auto base = name;
      if (inline_index && seg > 1) {
        auto split = split_index(name, index);
        if (!split) return split.error();
        base = *split;
      }
      if (!is_identifier(base)) return errc::malformed_encoding;
      if (seg != 0) text.push_back('.');
      text.append(base);
      text.append(index);
    }
    pos = end + 1;
  }
  if (!alt.empty()) {
    if (!f) return errc::malformed_encoding;
    if (auto r = decode_alternate_access(alt, text); !r) return r.error();
  }
  auto ref = object_reference::parse(text, opts);
  if (!ref) return ref.error();
  ref->set_fc(f);
  return ref;
}

result<object_reference> from_nvl_item(std::string_view domain, std::string_view item,
                                       const parse_options& opts) {
  if (domain.size() > opts.limits.max_mms_identifier ||
      item.size() > opts.limits.max_mms_identifier) {
    return errc::length_overflow;
  }
  const auto sep = item.find('$');
  if (sep == std::string_view::npos) return errc::malformed_encoding;
  const auto ln = item.substr(0, sep);
  const auto ds = item.substr(sep + 1);
  if (!is_identifier(domain) || !is_identifier(ln) || !is_identifier(ds)) {
    return errc::malformed_encoding;
  }
  return object_reference::make(domain, ln, {{ds, std::nullopt}}, std::nullopt, opts);
}

result<std::string> nvl_item(const object_reference& ds, const name_limits& limits) {
  if (ds.empty() || ds.is_association_specific() || !ds.has_ln() || ds.fc()) {
    return errc::invalid_state;
  }
  const auto path = ds.path();
  auto it = path.begin();
  if (it == path.end()) return errc::invalid_state;
  const auto e = *it;
  if (e.index || ++it != path.end()) return errc::invalid_state;
  std::string item{ds.ln()};
  item.push_back('$');
  item.append(e.name);
  if (ds.ld().size() > limits.max_mms_identifier || item.size() > limits.max_mms_identifier) {
    return errc::length_overflow;
  }
  return item;
}

}  // namespace

result<void> encode_alternate_access(std::span<const access_selector> selectors,
                                     byte_buffer& out) {
  // Never emit what decode_alternate_access would refuse from a peer.
  if (selectors.size() > max_alternate_access_depth) return errc::nesting_too_deep;
  for (const auto& s : selectors) {
    if (s.index ? !s.component.empty() : !is_identifier(s.component)) return errc::invalid_state;
  }
  ber::writer w{out};
  std::vector<ber::writer::marker> open;
  open.reserve(selectors.size() * 2);
  for (std::size_t i = 0; i < selectors.size(); ++i) {
    const auto& s = selectors[i];
    if (i + 1 == selectors.size()) {  // selectAccess
      if (s.index) {
        w.write_unsigned(*s.index, ber::context(2));
      } else {
        w.write_visible_string(s.component, ber::context(1));
      }
      break;
    }
    open.push_back(w.begin(ber::context(0, true)));  // selectAlternateAccess
    if (s.index) {
      w.write_unsigned(*s.index, ber::context(1));
    } else {
      w.write_visible_string(s.component, ber::context(0));
    }
    open.push_back(w.begin(ber::tags::sequence));
  }
  while (!open.empty()) {
    w.end(open.back());
    open.pop_back();
  }
  return {};
}

result<std::string> to_mms_item_id(const object_reference& ref, const name_limits& limits) {
  return build_item(ref, nullptr, limits);
}

result<mms_variable> to_mms_variable(const object_reference& ref, const name_limits& limits) {
  std::vector<access_selector> alt;
  auto item = build_item(ref, &alt, limits);
  if (!item) return item.error();
  mms_variable v{{mms::object_scope::domain_specific, std::string{ref.ld()}, std::move(*item)},
                 {}};
  if (auto r = encode_alternate_access(alt, v.alternate_access); !r) return r.error();
  return v;
}

result<object_reference> from_mms_variable(const mms::object_name& name, byte_view alternate_access,
                                           const parse_options& opts) {
  if (name.scope != mms::object_scope::domain_specific) return errc::malformed_encoding;
  return from_domain_item(name.domain_id, name.item_id, alternate_access, opts);
}

result<mms_name> to_mms_named_variable_list(const object_reference& data_set,
                                            const name_limits& limits) {
  if (data_set.is_association_specific()) {
    const auto name = data_set.text().substr(1);
    if (name.size() > limits.max_mms_identifier) return errc::length_overflow;
    return mms_name{mms::object_scope::aa_specific, {}, std::string{name}};
  }
  auto item = nvl_item(data_set, limits);
  if (!item) return item.error();
  return mms_name{mms::object_scope::domain_specific, std::string{data_set.ld()},
                  std::move(*item)};
}

result<object_reference> from_mms_named_variable_list(const mms::object_name& name,
                                                      const parse_options& opts) {
  switch (name.scope) {
    case mms::object_scope::aa_specific:
      if (name.item_id.size() > opts.limits.max_mms_identifier) return errc::length_overflow;
      return object_reference::association_specific(name.item_id, opts);
    case mms::object_scope::domain_specific:
      return from_nvl_item(name.domain_id, name.item_id, opts);
    default:
      return errc::malformed_encoding;
  }
}

result<std::string> to_mms_reference(const object_reference& ref, const name_limits& limits) {
  auto item = build_item(ref, nullptr, limits);
  if (!item) return item.error();
  std::string s{ref.ld()};
  s.push_back('/');
  s.append(*item);
  return s;
}

result<object_reference> from_mms_reference(std::string_view text, const parse_options& opts) {
  const auto slash = text.find('/');
  if (slash == std::string_view::npos) return errc::malformed_encoding;
  return from_domain_item(text.substr(0, slash), text.substr(slash + 1), {}, opts);
}

result<std::string> to_mms_data_reference(const object_reference& ref, const name_limits& limits) {
  auto item = build_item(ref, nullptr, limits, true);
  if (!item) return item.error();
  std::string s{ref.ld()};
  s.push_back('/');
  s.append(*item);
  return s;
}

result<object_reference> from_mms_data_reference(std::string_view text, const parse_options& opts) {
  const auto slash = text.find('/');
  if (slash == std::string_view::npos) return errc::malformed_encoding;
  return from_domain_item(text.substr(0, slash), text.substr(slash + 1), {}, opts, true);
}

result<std::string> to_mms_data_set_reference(const object_reference& data_set,
                                              const name_limits& limits) {
  if (data_set.is_association_specific()) {
    if (data_set.text().size() - 1 > limits.max_mms_identifier) return errc::length_overflow;
    return std::string{data_set.text()};
  }
  auto item = nvl_item(data_set, limits);
  if (!item) return item.error();
  std::string s{data_set.ld()};
  s.push_back('/');
  s.append(*item);
  return s;
}

result<object_reference> from_mms_data_set_reference(std::string_view text,
                                                     const parse_options& opts) {
  if (text.starts_with('@')) {
    if (text.size() - 1 > opts.limits.max_mms_identifier) return errc::length_overflow;
    return object_reference::association_specific(text.substr(1), opts);
  }
  const auto slash = text.find('/');
  if (slash == std::string_view::npos) return errc::malformed_encoding;
  return from_nvl_item(text.substr(0, slash), text.substr(slash + 1), opts);
}

}  // namespace openiec61850::model
