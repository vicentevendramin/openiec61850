#include "openiec61850/client/report.hpp"

#include <limits>
#include <utility>

#include "openiec61850/model/mms_mapping.hpp"

namespace openiec61850::client {

namespace {

constexpr auto violation = openiec61850::errc::protocol_violation;

class cursor {
 public:
  explicit cursor(const std::vector<mms::data>& items) : items_(items) {}

  const mms::data* next() noexcept { return pos_ < items_.size() ? &items_[pos_++] : nullptr; }
  [[nodiscard]] bool done() const noexcept { return pos_ == items_.size(); }

  result<std::string> string() {
    const auto* d = next();
    if (d == nullptr || d->type() != mms::data_type::visible_string) return violation;
    return std::string(*d->as_visible_string());
  }
  result<bool> boolean() {
    const auto* d = next();
    if (d == nullptr) return violation;
    auto v = d->as_boolean();
    if (!v) return violation;
    return *v;
  }
  result<std::uint32_t> unsigned32() {
    const auto* d = next();
    if (d == nullptr) return violation;
    auto v = d->as_uint64();
    if (!v || *v > std::numeric_limits<std::uint32_t>::max()) return violation;
    return static_cast<std::uint32_t>(*v);
  }

 private:
  const std::vector<mms::data>& items_;
  std::size_t pos_ = 0;
};

}  // namespace

bool is_report(const mms::information_report& ir) noexcept {
  return ir.spec.type == mms::variable_access_specification::kind::variable_list_name &&
         ir.spec.list_name.scope == mms::object_scope::vmd_specific &&
         ir.spec.list_name.item_id == "RPT";
}

result<report> parse_report(const mms::information_report& ir,
                            std::span<const model::object_reference> members,
                            const model::parse_options& opts) {
  if (!is_report(ir)) return openiec61850::errc::unsupported;

  // Owning copies: the report keeps the values, and locally built reports carry owned data.
  std::vector<mms::data> items;
  for (const auto& ar : ir.results) {
    if (!ar.success()) return violation;
    if (const auto* owned = ar.value.owned(); owned != nullptr) {
      items.push_back(*owned);
    } else {
      auto d = mms::data::from_view(ar.value.view());
      if (!d) return violation;
      items.push_back(std::move(*d));
    }
  }

  cursor c(items);
  report r;
  auto id = c.string();
  if (!id) return id.error();
  r.rpt_id = std::move(*id);
  const auto* opt = c.next();
  if (opt == nullptr) return violation;
  auto of = model::optional_fields::from_mms(*opt);
  if (!of) return violation;
  r.opt_flds = *of;

  if (r.opt_flds.sequence_number()) {
    auto v = c.unsigned32();
    if (!v) return v.error();
    r.seq_num = *v;
  }
  if (r.opt_flds.report_time_stamp()) {
    const auto* d = c.next();
    if (d == nullptr) return violation;
    auto t = model::entry_time_from_mms(*d);
    if (!t) return violation;
    r.time_of_entry = *t;
  }
  if (r.opt_flds.data_set_name()) {
    auto v = c.string();
    if (!v) return v.error();
    r.data_set = std::move(*v);
  }
  if (r.opt_flds.buffer_overflow()) {
    auto v = c.boolean();
    if (!v) return v.error();
    r.buffer_overflow = *v;
  }
  if (r.opt_flds.entry_id()) {
    const auto* d = c.next();
    if (d == nullptr) return violation;
    auto e = model::entry_id::from_mms(*d);
    if (!e) return violation;
    r.entry_id = *e;
  }
  if (r.opt_flds.conf_revision()) {
    auto v = c.unsigned32();
    if (!v) return v.error();
    r.conf_rev = *v;
  }
  if (r.opt_flds.segmentation()) {
    auto v = c.unsigned32();
    if (!v) return v.error();
    r.sub_seq_num = *v;
    auto more = c.boolean();
    if (!more) return more.error();
    r.more_segments_follow = *more;
  }

  const auto* inc = c.next();
  if (inc == nullptr) return violation;
  auto bits = inc->as_bit_string();
  if (!bits) return violation;
  if (!members.empty() && bits->bit_count > members.size()) return violation;
  r.inclusion.resize(bits->bit_count);
  for (std::size_t i = 0; i < bits->bit_count; ++i) {
    r.inclusion[i] = bits->test(i);
    if (r.inclusion[i]) {
      report_entry e;
      e.index = i;
      r.entries.push_back(std::move(e));
    }
  }

  if (r.opt_flds.data_reference()) {
    for (auto& e : r.entries) {
      auto v = c.string();
      if (!v) return v.error();
      e.data_reference = std::move(*v);
    }
  }
  for (auto& e : r.entries) {
    const auto* d = c.next();
    if (d == nullptr) return violation;
    e.value = *d;
  }
  if (r.opt_flds.reason_for_inclusion()) {
    for (auto& e : r.entries) {
      const auto* d = c.next();
      if (d == nullptr) return violation;
      auto reason = model::trigger_conditions::from_mms(*d);
      if (!reason) return violation;
      e.reason = *reason;
    }
  }
  if (!c.done()) return violation;

  for (auto& e : r.entries) {
    if (!e.data_reference.empty()) {
      if (auto ref = model::from_mms_reference(e.data_reference, opts)) {
        e.reference = std::move(*ref);
        continue;
      }
    }
    if (e.index < members.size()) e.reference = members[e.index];
  }
  return r;
}

}  // namespace openiec61850::client
