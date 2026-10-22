#include "openiec61850/model/object_reference.hpp"

#include <limits>

namespace openiec61850::model {
namespace {

constexpr std::size_t hard_cap = std::numeric_limits<std::uint16_t>::max();

constexpr bool is_upper(char c) noexcept { return c >= 'A' && c <= 'Z'; }
constexpr bool is_alpha(char c) noexcept { return is_upper(c) || (c >= 'a' && c <= 'z'); }
constexpr bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }
constexpr bool is_name_char(char c) noexcept { return is_alpha(c) || is_digit(c) || c == '_'; }

// Parses "(digits)" at text[pos]; on success sets `pos` past ')'.
std::optional<std::uint32_t> parse_index(std::string_view text, std::size_t& pos) noexcept {
  std::size_t i = pos + 1;
  const std::size_t start = i;
  std::uint64_t v = 0;
  while (i < text.size() && is_digit(text[i])) {
    if (i - start >= 10) return std::nullopt;
    v = v * 10 + static_cast<std::uint64_t>(text[i] - '0');
    ++i;
  }
  const std::size_t digits = i - start;
  if (digits == 0 || i >= text.size() || text[i] != ')') return std::nullopt;
  if (digits > 1 && text[start] == '0') return std::nullopt;
  if (v > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
  pos = i + 1;
  return static_cast<std::uint32_t>(v);
}

// Decodes the path element starting at `pos` and returns the position of the next one
// (text.size() at the end). The text has been validated.
std::size_t element_at(std::string_view text, std::size_t pos, path_element* out) noexcept {
  std::size_t i = pos;
  while (i < text.size() && is_name_char(text[i])) ++i;
  path_element e{text.substr(pos, i - pos), std::nullopt};
  if (i < text.size() && text[i] == '(') e.index = parse_index(text, i);
  if (out != nullptr) *out = e;
  if (i < text.size() && text[i] == '.') ++i;
  return i;
}

void append_index(std::string& out, std::uint32_t index) {
  char buf[10];
  std::size_t n = 0;
  do {
    buf[n++] = static_cast<char>('0' + index % 10);
    index /= 10;
  } while (index != 0);
  out.push_back('(');
  while (n > 0) out.push_back(buf[--n]);
  out.push_back(')');
}

}  // namespace

bool is_identifier(std::string_view s) noexcept {
  if (s.empty() || !is_alpha(s.front())) return false;
  for (char c : s) {
    if (!is_name_char(c)) return false;
  }
  return true;
}

std::optional<ln_name_parts> split_ln_name(std::string_view ln) noexcept {
  if (ln == "LLN0") return ln_name_parts{{}, ln, {}};
  std::size_t inst_begin = ln.size();
  while (inst_begin > 0 && is_digit(ln[inst_begin - 1])) --inst_begin;
  const std::size_t inst_len = ln.size() - inst_begin;
  if (inst_len == 0 || inst_len > 12 || inst_begin < 4) return std::nullopt;
  const std::size_t class_begin = inst_begin - 4;
  for (std::size_t i = class_begin; i < inst_begin; ++i) {
    if (!is_upper(ln[i])) return std::nullopt;
  }
  const auto prefix = ln.substr(0, class_begin);
  if (prefix.size() > 11) return std::nullopt;
  if (!prefix.empty() && !is_identifier(prefix)) return std::nullopt;
  return ln_name_parts{prefix, ln.substr(class_begin, 4), ln.substr(inst_begin)};
}

result<object_reference> object_reference::parse(std::string_view text,
                                                 const parse_options& opts) {
  std::optional<functional_constraint> f;
  std::string_view base = text;
  if (!base.empty() && base.back() == ']') {
    const auto open = base.rfind('[');
    if (open == std::string_view::npos) return errc::malformed_encoding;
    f = parse_functional_constraint(base.substr(open + 1, base.size() - open - 2));
    if (!f) return errc::malformed_encoding;
    base = base.substr(0, open);
    while (!base.empty() && base.back() == ' ') base.remove_suffix(1);
  }
  if (base.empty()) return errc::malformed_encoding;
  if (base.size() > opts.limits.max_object_reference || base.size() > hard_cap) {
    return errc::length_overflow;
  }

  object_reference r;
  if (base.front() == '@') {
    const auto name = base.substr(1);
    if (f || !is_identifier(name)) return errc::malformed_encoding;
    if (name.size() > opts.limits.max_mms_identifier) return errc::length_overflow;
    r.text_ = std::string{base};
    r.aa_ = true;
    return r;
  }

  const auto slash = base.find('/');
  const auto ld = base.substr(0, slash);
  if (!is_identifier(ld)) return errc::malformed_encoding;
  if (ld.size() > opts.limits.max_ld_name) return errc::length_overflow;
  r.ld_end_ = static_cast<std::uint16_t>(ld.size());
  r.ln_end_ = r.ld_end_;
  if (slash == std::string_view::npos) {
    if (f) return errc::malformed_encoding;
    r.text_ = std::string{base};
    return r;
  }

  const std::size_t ln_begin = slash + 1;
  std::size_t pos = ln_begin;
  while (pos < base.size() && base[pos] != '.') ++pos;
  const auto ln = base.substr(ln_begin, pos - ln_begin);
  if (!is_identifier(ln)) return errc::malformed_encoding;
  if (opts.strict_ln_names && !split_ln_name(ln)) return errc::malformed_encoding;
  r.ln_end_ = static_cast<std::uint16_t>(pos);

  while (pos < base.size()) {
    ++pos;  // '.'
    const std::size_t name_begin = pos;
    while (pos < base.size() && is_name_char(base[pos])) ++pos;
    if (!is_identifier(base.substr(name_begin, pos - name_begin))) {
      return errc::malformed_encoding;
    }
    if (pos < base.size() && base[pos] == '(') {
      if (!parse_index(base, pos)) return errc::malformed_encoding;
    }
    if (pos < base.size() && base[pos] != '.') return errc::malformed_encoding;
    if (pos + 1 == base.size()) return errc::malformed_encoding;  // trailing '.'
  }

  r.text_ = std::string{base};
  r.fc_ = f;
  return r;
}

result<object_reference> object_reference::make(std::string_view ld, std::string_view ln,
                                                std::initializer_list<path_element> path,
                                                std::optional<functional_constraint> constraint,
                                                const parse_options& opts) {
  std::string text{ld};
  if (ln.empty()) {
    if (path.size() != 0 || constraint) return errc::malformed_encoding;
  } else {
    text.push_back('/');
    text.append(ln);
  }
  for (const auto& e : path) {
    // Reject separators smuggled in names before they reach the parser.
    if (!is_identifier(e.name)) return errc::malformed_encoding;
    text.push_back('.');
    text.append(e.name);
    if (e.index) append_index(text, *e.index);
  }
  auto r = parse(text, opts);
  if (r) r->fc_ = constraint;
  return r;
}

result<object_reference> object_reference::association_specific(std::string_view name,
                                                                const parse_options& opts) {
  if (!is_identifier(name)) return errc::malformed_encoding;
  std::string text{"@"};
  text.append(name);
  return parse(text, opts);
}

std::string object_reference::to_string() const {
  std::string s = text_;
  if (fc_) {
    s.push_back('[');
    s.append(model::to_string(*fc_));
    s.push_back(']');
  }
  return s;
}

std::string_view object_reference::ln() const noexcept {
  if (!has_ln()) return {};
  return std::string_view{text_}.substr(std::size_t{ld_end_} + 1, std::size_t{ln_end_} - ld_end_ - 1);
}

ln_name_parts object_reference::ln_parts() const noexcept {
  const auto name = ln();
  if (auto p = split_ln_name(name)) return *p;
  return {{}, name, {}};
}

std::size_t object_reference::path_begin() const noexcept {
  if (aa_) return 1;
  if (ln_end_ < text_.size()) return std::size_t{ln_end_} + 1;
  return text_.size();
}

path_element object_reference::path_iterator::operator*() const noexcept {
  path_element e;
  (void)element_at(text_, pos_, &e);
  return e;
}

object_reference::path_iterator& object_reference::path_iterator::operator++() noexcept {
  pos_ = element_at(text_, pos_, nullptr);
  return *this;
}

std::size_t object_reference::path_range::size() const noexcept {
  std::size_t n = 0;
  for (auto it = begin_; it != end_; ++it) ++n;
  return n;
}

object_reference::path_range object_reference::path() const noexcept {
  const std::string_view t{text_};
  return {path_iterator{t, path_begin()}, path_iterator{t, t.size()}};
}

std::optional<path_element> object_reference::leaf() const noexcept {
  std::optional<path_element> last;
  for (auto e : path()) last = e;
  return last;
}

bool object_reference::has_index() const noexcept {
  return text_.find('(') != std::string::npos;
}

result<object_reference> object_reference::child(std::string_view name,
                                                 std::optional<std::uint32_t> index,
                                                 const parse_options& opts) const {
  if (empty() || aa_ || !is_identifier(name)) return errc::invalid_state;
  std::string text = text_;
  text.push_back(has_ln() ? '.' : '/');
  text.append(name);
  if (index) {
    if (!has_ln()) return errc::invalid_state;
    append_index(text, *index);
  }
  auto r = parse(text, opts);
  if (r && r->has_ln() && has_ln()) r->fc_ = fc_;
  return r;
}

result<object_reference> object_reference::parent() const {
  if (empty() || aa_ || !has_ln()) return errc::invalid_state;
  object_reference r = *this;
  if (ln_end_ == text_.size()) {
    r.text_.resize(ld_end_);
    r.ln_end_ = r.ld_end_;
    r.fc_.reset();
    return r;
  }
  const auto dot = text_.rfind('.');
  r.text_.resize(dot);
  return r;
}

bool object_reference::is_within(const object_reference& ancestor) const noexcept {
  const std::string_view t{text_};
  const std::string_view a{ancestor.text_};
  if (a.empty() || !t.starts_with(a)) return false;
  if (t.size() == a.size()) return true;
  const char next = t[a.size()];
  return next == '.' || next == '(' || (next == '/' && !ancestor.has_ln() && !ancestor.aa_);
}

}  // namespace openiec61850::model
