// Control services (IEC 61850-7-2 §20) mapped onto MMS (IEC 61850-8-1 §20).

#include "openiec61850/client/control.hpp"

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <limits>
#include <mutex>
#include <utility>
#include <vector>

#include <asio/as_tuple.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>

#include "detail.hpp"

namespace openiec61850::client {

namespace {

constexpr auto violation = openiec61850::errc::protocol_violation;

class add_cause_category_impl final : public std::error_category {
 public:
  const char* name() const noexcept override { return "openiec61850.control"; }
  std::string message(int value) const override {
    return std::string(to_string(static_cast<add_cause>(value - 1)));
  }
};

}  // namespace

std::string_view to_string(add_cause v) noexcept {
  switch (v) {
    case add_cause::unknown: return "unknown";
    case add_cause::not_supported: return "not-supported";
    case add_cause::blocked_by_switching_hierarchy: return "blocked-by-switching-hierarchy";
    case add_cause::select_failed: return "select-failed";
    case add_cause::invalid_position: return "invalid-position";
    case add_cause::position_reached: return "position-reached";
    case add_cause::parameter_change_in_execution: return "parameter-change-in-execution";
    case add_cause::step_limit: return "step-limit";
    case add_cause::blocked_by_mode: return "blocked-by-mode";
    case add_cause::blocked_by_process: return "blocked-by-process";
    case add_cause::blocked_by_interlocking: return "blocked-by-interlocking";
    case add_cause::blocked_by_synchrocheck: return "blocked-by-synchrocheck";
    case add_cause::command_already_in_execution: return "command-already-in-execution";
    case add_cause::blocked_by_health: return "blocked-by-health";
    case add_cause::one_of_n_control: return "1-of-n-control";
    case add_cause::abortion_by_cancel: return "abortion-by-cancel";
    case add_cause::time_limit_over: return "time-limit-over";
    case add_cause::abortion_by_trip: return "abortion-by-trip";
    case add_cause::object_not_selected: return "object-not-selected";
    case add_cause::object_already_selected: return "object-already-selected";
    case add_cause::no_access_authority: return "no-access-authority";
    case add_cause::ended_with_overshoot: return "ended-with-overshoot";
    case add_cause::abortion_due_to_deviation: return "abortion-due-to-deviation";
    case add_cause::abortion_by_communication_loss: return "abortion-by-communication-loss";
    case add_cause::blocked_by_command: return "blocked-by-command";
    case add_cause::none: return "none";
    case add_cause::inconsistent_parameters: return "inconsistent-parameters";
    case add_cause::locked_by_other_client: return "locked-by-other-client";
  }
  return "unknown-add-cause";
}

std::string_view to_string(control_error v) noexcept {
  switch (v) {
    case control_error::no_error: return "no-error";
    case control_error::unknown: return "unknown";
    case control_error::timeout_test_not_ok: return "timeout-test-not-ok";
    case control_error::operator_test_not_ok: return "operator-test-not-ok";
  }
  return "unknown-error";
}

const std::error_category& add_cause_category() noexcept {
  static const add_cause_category_impl instance;
  return instance;
}

std::error_code make_error_code(add_cause c) noexcept {
  return {static_cast<int>(c) + 1, add_cause_category()};
}

std::optional<add_cause> to_add_cause(const std::error_code& ec) noexcept {
  if (ec.category() != add_cause_category() || ec.value() <= 0) return std::nullopt;
  return static_cast<add_cause>(ec.value() - 1);
}

// ---------------------------------------------------------------------------------------------
// Parsing

namespace {

result<mms::data> owned_value(const mms::access_result& ar) {
  if (!ar.success()) return violation;
  if (const auto* o = ar.value.owned(); o != nullptr) return *o;
  auto d = mms::data::from_view(ar.value.view());
  if (!d) return violation;
  return std::move(*d);
}

bool is_last_appl_error_name(const mms::object_name& n) noexcept {
  return n.scope == mms::object_scope::vmd_specific && n.item_id == "LastApplError";
}

bool is_oper_name(const mms::object_name& n) noexcept {
  return n.scope == mms::object_scope::domain_specific && n.item_id.ends_with("$Oper") &&
         n.item_id.find("$CO$") != std::string_view::npos;
}

template <typename T>
result<T> small_integer(const mms::data& d, std::int64_t lo, std::int64_t hi) {
  auto v = d.as_int64();
  if (!v || *v < lo || *v > hi) return violation;
  return static_cast<T>(*v);
}

}  // namespace

result<last_appl_error> parse_last_appl_error(const mms::data& value) {
  if (value.type() != mms::data_type::structure) return violation;
  const auto e = value.elements();
  if (e.size() < 5) return violation;
  last_appl_error out;
  if (e[0].type() == mms::data_type::visible_string) {
    out.control_object = std::string(*e[0].as_visible_string());
  } else if (e[0].type() == mms::data_type::mms_string) {
    out.control_object = std::string(*e[0].as_mms_string());
  } else {
    return violation;
  }
  auto err = small_integer<control_error>(e[1], 0, 255);
  if (!err) return err.error();
  out.error = *err;
  if (e[2].type() != mms::data_type::structure || e[2].elements().size() < 2) return violation;
  const auto origin = e[2].elements();
  auto cat = small_integer<model::orcat>(origin[0], 0, 255);
  if (!cat) return cat.error();
  out.origin.category = *cat;
  auto ident = origin[1].as_octet_string();
  if (!ident) return violation;
  out.origin.identifier.assign(ident->begin(), ident->end());
  auto num = small_integer<std::uint8_t>(e[3], 0, 255);
  if (!num) return num.error();
  out.ctl_num = *num;
  auto cause = small_integer<add_cause>(e[4], std::numeric_limits<std::int16_t>::min(),
                                        std::numeric_limits<std::int16_t>::max());
  if (!cause) return cause.error();
  out.cause = *cause;
  return out;
}

bool is_control_message(const mms::information_report& ir) noexcept {
  if (ir.spec.type != mms::variable_access_specification::kind::list_of_variable) return false;
  const auto vars = ir.spec.variables;
  const auto first = vars.begin();
  if (first == vars.end()) return false;
  const auto v = *first;
  return is_last_appl_error_name(v.name) || is_oper_name(v.name);
}

result<control_message> parse_control_message(const mms::information_report& ir) {
  if (!is_control_message(ir)) return openiec61850::errc::unsupported;
  std::vector<mms::object_name> names;
  for (const auto v : ir.spec.variables) names.push_back(v.name);
  std::vector<mms::access_result> results;
  for (const auto r : ir.results) results.push_back(r);
  if (names.size() != results.size()) return violation;

  control_message m;
  if (is_last_appl_error_name(names[0])) {
    auto d = owned_value(results[0]);
    if (!d) return d.error();
    auto e = parse_last_appl_error(*d);
    if (!e) return e.error();
    if (names.size() == 1) {
      m.type = control_message::kind::last_appl_error;
      m.control_object = e->control_object;
      m.error = std::move(*e);
      return m;
    }
    if (names.size() != 2 || !is_oper_name(names[1])) return violation;
    m.type = control_message::kind::command_termination;
    m.control_object = std::string(names[1].domain_id) + "/" + std::string(names[1].item_id);
    m.error = std::move(*e);
    if (auto o = owned_value(results[1])) m.oper = std::move(*o);
    return m;
  }
  if (names.size() != 1) return violation;
  auto d = owned_value(results[0]);
  if (!d) return d.error();
  m.type = control_message::kind::command_termination;
  m.control_object = std::string(names[0].domain_id) + "/" + std::string(names[0].item_id);
  m.oper = std::move(*d);
  return m;
}

// ---------------------------------------------------------------------------------------------
// Handle state

namespace detail {

using asio::awaitable;

std::string control_key(std::string_view control_object) {
  std::string s(control_object);
  for (const std::string_view suffix : {"$Oper", "$SBOw", "$Cancel", "$SBO"}) {
    if (s.ends_with(suffix)) {
      s.resize(s.size() - suffix.size());
      break;
    }
  }
  if (s.find('$') == std::string::npos) {
    // ACSI form "LD/LN.DO[.SDO]".
    const auto slash = s.find('/');
    const auto dot = slash == std::string::npos ? std::string::npos : s.find('.', slash);
    if (dot != std::string::npos) {
      std::string rest = s.substr(dot + 1);
      std::replace(rest.begin(), rest.end(), '.', '$');
      s = s.substr(0, dot) + "$CO$" + rest;
    }
  }
  return s;
}

struct control_state {
  std::shared_ptr<client_state> client;
  model::object_reference object;
  std::string key;      // "LD/LN$CO$DO"
  std::string domain;   // "LD"
  std::string co_item;  // "LN$CO$DO"
  model::ctl_model model = model::ctl_model::status_only;
  std::optional<std::chrono::milliseconds> sbo_timeout;
  std::optional<mms::type_description> structure;
  std::optional<mms::data_type> ctl_val_type;
  std::optional<bool> has_oper_time;

  // Sequence (strand), mirrored in atomics for the accessors.
  std::uint8_t next_num = 0;
  std::atomic<std::uint8_t> current_num{0};
  bool in_sequence = false;
  std::atomic<bool> selected{false};
  std::optional<mms::data> sequence_value;

  mutable std::mutex mutex;  // guards last_error
  std::optional<last_appl_error> last_error;

  static control make(std::shared_ptr<control_state> s) { return control(std::move(s)); }

  std::uint8_t begin_sequence() {
    const auto n = next_num++;
    current_num.store(n);
    in_sequence = true;
    selected.store(false);
    sequence_value.reset();
    return n;
  }
  void end_sequence() {
    in_sequence = false;
    selected.store(false);
    sequence_value.reset();
  }
  void set_last_error(last_appl_error e) {
    const std::lock_guard lock(mutex);
    last_error = std::move(e);
  }

  // A component of the CO structure ("Oper", "SBOw"...); nullptr when unknown or absent.
  [[nodiscard]] const mms::type_description* component(std::string_view name) const noexcept {
    if (!structure || structure->type != mms::data_type::structure) return nullptr;
    for (const auto& c : structure->components) {
      if (c.name == name) return &c.type;
    }
    return nullptr;
  }
  // True when the structure is known and lacks `name`.
  [[nodiscard]] bool lacks(std::string_view name) const noexcept {
    return structure && component(name) == nullptr;
  }

  [[nodiscard]] model::mms_variable variable(std::string_view attr) const {
    model::mms_variable v;
    v.name = {mms::object_scope::domain_specific, domain, co_item + "$" + std::string(attr)};
    return v;
  }
};

namespace {

std::error_code err(errc e) noexcept { return make_error_code(e); }

const mms::type_description* find_component(const mms::type_description& t,
                                             std::string_view name) noexcept {
  if (t.type != mms::data_type::structure) return nullptr;
  for (const auto& c : t.components) {
    if (c.name == name) return &c.type;
  }
  return nullptr;
}

mms::data default_value(const mms::type_description& t) {
  switch (t.type) {
    case mms::data_type::structure: {
      std::vector<mms::data> v;
      for (const auto& c : t.components) v.push_back(default_value(c.type));
      return mms::data::structure(std::move(v));
    }
    case mms::data_type::array: {
      std::vector<mms::data> v;
      if (!t.components.empty()) {
        for (std::uint32_t i = 0; i < t.number_of_elements && i < 4096; ++i) {
          v.push_back(default_value(t.components.front().type));
        }
      }
      return mms::data::array(std::move(v));
    }
    case mms::data_type::bit_string: {
      const auto n = static_cast<std::size_t>(std::abs(static_cast<long long>(t.size)));
      const byte_buffer zeros((n + 7) / 8, 0);
      return mms::data::bit_string(zeros, n);
    }
    case mms::data_type::integer: return mms::data::integer(0);
    case mms::data_type::unsigned_: return mms::data::unsigned_integer(0);
    case mms::data_type::floating_point:
      return t.format_width == 64 ? mms::data::floating_point(0.0) : mms::data::floating_point(0.0F);
    case mms::data_type::octet_string: {
      const byte_buffer zeros(t.size > 0 ? static_cast<std::size_t>(t.size) : 0, 0);
      return mms::data::octet_string(zeros);
    }
    case mms::data_type::visible_string: return mms::data::visible_string("");
    case mms::data_type::mms_string: return mms::data::mms_string("");
    case mms::data_type::utc_time: return mms::data::utc_time({});
    case mms::data_type::binary_time:
      return mms::data::binary_time(
          {0, t.with_date ? std::optional<std::uint16_t>(0) : std::nullopt});
    default: return mms::data::boolean(false);
  }
}

// ctlVal in the server's type: integer and unsigned are converted into each other.
result<mms::data> coerce(const mms::data& v, const mms::type_description* t) {
  if (!v.valid()) return openiec61850::errc::invalid_state;
  if (t == nullptr || v.type() == t->type) return v;
  if (t->type == mms::data_type::integer && v.type() == mms::data_type::unsigned_) {
    auto u = v.as_uint64();
    if (!u || *u > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
      return openiec61850::errc::value_out_of_range;
    }
    return mms::data::integer(static_cast<std::int64_t>(*u));
  }
  if (t->type == mms::data_type::unsigned_ && v.type() == mms::data_type::integer) {
    auto i = v.as_int64();
    if (!i || *i < 0) return openiec61850::errc::value_out_of_range;
    return mms::data::unsigned_integer(static_cast<std::uint64_t>(*i));
  }
  return err(errc::type_mismatch);
}

mms::data integer_as(const mms::type_description* t, std::int64_t v) {
  if (t != nullptr && t->type == mms::data_type::unsigned_) {
    return mms::data::unsigned_integer(static_cast<std::uint64_t>(v));
  }
  return mms::data::integer(v);
}

mms::data origin_value(const mms::type_description* t, const originator& o) {
  const auto cat = static_cast<std::int64_t>(o.category);
  if (t == nullptr || t->type != mms::data_type::structure) {
    return mms::data::structure(
        {mms::data::integer(cat), mms::data::octet_string(o.identifier)});
  }
  std::vector<mms::data> v;
  for (const auto& c : t->components) {
    if (c.name == "orCat") {
      v.push_back(integer_as(&c.type, cat));
    } else if (c.name == "orIdent") {
      if (c.type.type == mms::data_type::visible_string) {
        v.push_back(mms::data::visible_string(
            std::string_view(reinterpret_cast<const char*>(o.identifier.data()), o.identifier.size())));
      } else {
        v.push_back(mms::data::octet_string(o.identifier));
      }
    } else {
      v.push_back(default_value(c.type));
    }
  }
  return mms::data::structure(std::move(v));
}

enum class service : std::uint8_t { sbow, oper, cancel };

// The SBOw / Oper / Cancel structure, following the server's type `t` when known.
result<mms::data> build_request(const mms::type_description* t, service svc,
                                const mms::data& value, const control_options& o,
                                std::uint8_t num) {
  const auto now = model::timestamp::now();
  if (t == nullptr || t->type != mms::data_type::structure) {
    auto ctl_val = coerce(value, nullptr);
    if (!ctl_val) return ctl_val.error();
    std::vector<mms::data> v;
    v.push_back(std::move(*ctl_val));
    if (o.oper_time) v.push_back(o.oper_time->to_mms());
    v.push_back(origin_value(nullptr, o.origin));
    v.push_back(mms::data::unsigned_integer(num));
    v.push_back(now.to_mms());
    v.push_back(mms::data::boolean(o.test));
    if (svc != service::cancel) v.push_back(o.check.to_mms());
    return mms::data::structure(std::move(v));
  }
  if (o.oper_time && find_component(*t, "operTm") == nullptr) {
    return openiec61850::errc::unsupported;
  }
  std::vector<mms::data> v;
  for (const auto& c : t->components) {
    if (c.name == "ctlVal") {
      auto ctl_val = coerce(value, &c.type);
      if (!ctl_val) return ctl_val.error();
      v.push_back(std::move(*ctl_val));
    } else if (c.name == "operTm") {
      v.push_back(o.oper_time && c.type.type == mms::data_type::utc_time ? o.oper_time->to_mms()
                                                                         : default_value(c.type));
    } else if (c.name == "origin") {
      v.push_back(origin_value(&c.type, o.origin));
    } else if (c.name == "ctlNum") {
      v.push_back(integer_as(&c.type, num));
    } else if (c.name == "T" && c.type.type == mms::data_type::utc_time) {
      v.push_back(now.to_mms());
    } else if (c.name == "Test" && c.type.type == mms::data_type::boolean) {
      v.push_back(mms::data::boolean(o.test));
    } else if (c.name == "Check" && c.type.type == mms::data_type::bit_string) {
      v.push_back(o.check.to_mms());
    } else {
      v.push_back(default_value(c.type));
    }
  }
  return mms::data::structure(std::move(v));
}

// Clears the busy flag of a channel on scope exit.
struct busy_guard {
  control_channel* ch;
  ~busy_guard() {
    if (ch != nullptr) ch->busy = false;
  }
};

result<control_channel*> acquire(control_state& cs) {
  auto& ch = cs.client->controls[cs.key];
  if (ch.busy) return openiec61850::errc::invalid_state;
  ch.busy = true;
  ch.messages.clear();
  return &ch;
}

// A request failed with `ec`: when the server sent a LastApplError for the object (8-1 sends it
// before the response), that becomes the error.
awaitable<std::error_code> refusal(control_state& cs, control_channel& ch, std::error_code ec) {
  // The InformationReport precedes the response on the wire and both reach this strand in that
  // order; one round trip through the strand lets a LastApplError still being posted arrive.
  co_await asio::post(cs.client->strand, asio::use_awaitable);
  for (auto it = ch.messages.rbegin(); it != ch.messages.rend(); ++it) {
    if (it->type == control_message::kind::last_appl_error && it->error) {
      const auto cause = it->error->cause;
      cs.set_last_error(*it->error);
      co_return make_error_code(cause);
    }
  }
  co_return ec;
}

// Waits until notified or `deadline`; false on timeout or cancellation.
awaitable<bool> wait_until(waiter& w, clock::time_point deadline) {
  if (w.notified) co_return true;
  w.timer.expires_at(deadline);
  auto [ec] = co_await w.timer.async_wait(asio::as_tuple(asio::use_awaitable));
  (void)ec;
  co_return w.notified;
}

// Enhanced security: the CommandTermination of the Oper just accepted.
awaitable<result<void>> wait_termination(control_state& cs, control_channel& ch, assoc_ptr a,
                                         std::chrono::milliseconds timeout) {
  const auto deadline = clock::now() + timeout;
  for (;;) {
    while (!ch.messages.empty()) {
      auto m = std::move(ch.messages.front());
      ch.messages.pop_front();
      if (m.error) {
        // A negative termination, or a lone LastApplError after the Oper was accepted.
        const auto cause = m.error->cause;
        cs.set_last_error(std::move(*m.error));
        co_return make_error_code(cause);
      }
      if (m.type == control_message::kind::command_termination) co_return result<void>{};
    }
    if (a->state() == association::association_state::closed || cs.client->assoc != a) {
      if (cs.client->closed() && cs.client->close_error) co_return cs.client->close_error;
      co_return co_await a->wait_closed();
    }
    waiter w(cs.client->strand);
    ch.consumer = &w;
    struct reset {
      waiter*& slot;
      ~reset() { slot = nullptr; }
    } guard{ch.consumer};
    if (!co_await wait_until(w, deadline)) {
      const auto cs_state = co_await asio::this_coro::cancellation_state;
      if (cs_state.cancelled() != asio::cancellation_type::none) {
        co_return make_error_code(asio::error::operation_aborted);
      }
      if (clock::now() >= deadline) co_return err(errc::termination_timeout);
    }
  }
}

bool enhanced(model::ctl_model m) noexcept {
  return m == model::ctl_model::direct_with_enhanced_security ||
         m == model::ctl_model::sbo_with_enhanced_security;
}

// ctlNum for a request: starts a sequence unless `continues` and one is open; an explicit
// ctlNum sets the new sequence's number, or overrides it for this request only.
std::uint8_t number_for(control_state& cs, const control_options& o, bool continues) {
  if (continues && cs.in_sequence) return o.ctl_num.value_or(cs.current_num.load());
  auto n = cs.begin_sequence();
  if (o.ctl_num) {
    n = *o.ctl_num;
    cs.current_num.store(n);
  }
  return n;
}

awaitable<result<void>> select_impl(std::shared_ptr<control_state> cs, control_options o) {
  if (cs->model != model::ctl_model::sbo_with_normal_security) {
    co_return err(errc::control_model_mismatch);
  }
  auto a = cs->client->current();
  if (!a) co_return a.error();
  auto ch = acquire(*cs);
  if (!ch) co_return ch.error();
  const busy_guard guard{*ch};
  std::vector<model::mms_variable> vars{cs->variable("SBO")};
  auto r = co_await read_variables_on(*a, std::move(vars));
  if (!r) co_return r.error();
  const auto& v = (*r)[0];
  if (!v) co_return co_await refusal(*cs, **ch, v.error());
  auto text = to_string(*v);
  if (!text) co_return err(errc::type_mismatch);
  if (text->empty()) co_return co_await refusal(*cs, **ch, err(errc::select_failed));
  (void)number_for(*cs, o, false);
  cs->selected.store(true);
  co_return result<void>{};
}

awaitable<result<void>> select_with_value_impl(std::shared_ptr<control_state> cs, mms::data value,
                                               control_options o) {
  if (cs->model != model::ctl_model::sbo_with_enhanced_security) {
    co_return err(errc::control_model_mismatch);
  }
  auto a = cs->client->current();
  if (!a) co_return a.error();
  auto ch = acquire(*cs);
  if (!ch) co_return ch.error();
  const busy_guard guard{*ch};
  const auto num = number_for(*cs, o, false);
  auto req = build_request(cs->component("SBOw"), service::sbow, value, o, num);
  if (!req) co_return req.error();
  auto w = co_await write_variable_on(*a, cs->variable("SBOw"), std::move(*req));
  if (!w) co_return co_await refusal(*cs, **ch, w.error());
  cs->sequence_value = std::move(value);
  cs->selected.store(true);
  co_return result<void>{};
}

awaitable<result<void>> operate_impl(std::shared_ptr<control_state> cs, mms::data value,
                                     control_options o) {
  if (cs->model == model::ctl_model::status_only) co_return err(errc::control_model_mismatch);
  auto a = cs->client->current();
  if (!a) co_return a.error();
  auto ch = acquire(*cs);
  if (!ch) co_return ch.error();
  const busy_guard guard{*ch};
  const auto num = number_for(*cs, o, true);
  auto req = build_request(cs->component("Oper"), service::oper, value, o, num);
  if (!req) co_return req.error();
  auto w = co_await write_variable_on(*a, cs->variable("Oper"), std::move(*req));
  if (!w) co_return co_await refusal(*cs, **ch, w.error());
  cs->sequence_value = std::move(value);
  if (enhanced(cs->model)) {
    auto t = co_await wait_termination(*cs, **ch, *a, o.termination_timeout);
    if (!t) {
      // A negative termination ends the sequence on the server too; a timeout leaves it open.
      if (to_add_cause(t.error())) cs->end_sequence();
      co_return t;
    }
  }
  cs->end_sequence();
  co_return result<void>{};
}

awaitable<result<void>> cancel_impl(std::shared_ptr<control_state> cs, control_options o) {
  if (cs->model == model::ctl_model::status_only ||
      cs->model == model::ctl_model::direct_with_normal_security) {
    co_return err(errc::control_model_mismatch);
  }
  auto a = cs->client->current();
  if (!a) co_return a.error();
  std::optional<mms::data> value = cs->in_sequence ? cs->sequence_value : std::nullopt;
  if (!value) {
    const auto* t = cs->component("Cancel");
    const auto* ctl_val = t != nullptr ? find_component(*t, "ctlVal") : nullptr;
    if (ctl_val == nullptr) {
      t = cs->component("Oper");
      ctl_val = t != nullptr ? find_component(*t, "ctlVal") : nullptr;
    }
    if (ctl_val == nullptr) co_return openiec61850::errc::invalid_state;
    value = default_value(*ctl_val);
  }
  auto ch = acquire(*cs);
  if (!ch) co_return ch.error();
  const busy_guard guard{*ch};
  const auto num = number_for(*cs, o, true);
  auto req = build_request(cs->component("Cancel"), service::cancel, *value, o, num);
  if (!req) co_return req.error();
  auto w = co_await write_variable_on(*a, cs->variable("Cancel"), std::move(*req));
  if (!w) co_return co_await refusal(*cs, **ch, w.error());
  cs->end_sequence();
  co_return result<void>{};
}

}  // namespace

awaitable<result<control>> get_control_op(std::shared_ptr<client_state> s,
                                          model::object_reference object, control_config config) {
  object.set_fc(std::nullopt);
  if (!object.has_ln() || object.path().empty() || object.has_index()) {
    co_return openiec61850::errc::invalid_state;
  }
  auto a = s->current();
  if (!a) co_return a.error();

  auto cs = std::make_shared<control_state>();
  cs->client = s;
  cs->object = object;
  const auto co_ref = object.with_fc(model::fc::CO);
  auto key = model::to_mms_reference(co_ref, s->limits);
  if (!key) co_return key.error();
  cs->key = std::move(*key);
  auto item = model::to_mms_item_id(co_ref, s->limits);
  if (!item) co_return item.error();
  cs->co_item = std::move(*item);
  cs->domain = std::string(object.ld());

  // CF.ctlModel and CF.sboTimeout in one Read.
  std::vector<model::mms_variable> vars;
  for (const std::string_view attr : {"ctlModel", "sboTimeout"}) {
    if (attr == "ctlModel" && config.ctl_model) continue;
    if (attr == "sboTimeout" && !config.read_sbo_timeout) continue;
    auto child = object.child(attr, std::nullopt, s->parse);
    if (!child) co_return child.error();
    auto v = model::to_mms_variable(child->with_fc(model::fc::CF), s->limits);
    if (!v) co_return v.error();
    vars.push_back(std::move(*v));
  }
  std::size_t next = 0;
  if (!vars.empty()) {
    auto values = co_await read_variables_on(*a, std::move(vars));
    if (!values) co_return values.error();
    if (!config.ctl_model) {
      const auto& m = (*values)[next++];
      if (!m) co_return m.error();
      auto model = model::ctl_model_from_mms(*m);
      if (!model) {
        co_return model.error() == openiec61850::errc::invalid_state ? err(errc::type_mismatch)
                                                                     : model.error();
      }
      cs->model = *model;
    }
    if (config.read_sbo_timeout) {
      const auto& t = (*values)[next++];
      if (t) {
        if (auto ms = to_uint64(*t)) cs->sbo_timeout = std::chrono::milliseconds(*ms);
      }
    }
  }
  if (config.ctl_model) cs->model = *config.ctl_model;

  if (config.read_structure && cs->model != model::ctl_model::status_only) {
    auto t = co_await type_description_on(*a, cs->domain, cs->co_item);
    if (t && t->type == mms::data_type::structure) cs->structure = std::move(*t);
  }
  for (const char* name : {"Oper", "SBOw", "Cancel"}) {
    const auto* svc = cs->component(name);
    if (svc == nullptr) continue;
    if (const auto* ctl_val = find_component(*svc, "ctlVal"); ctl_val != nullptr) {
      cs->ctl_val_type = ctl_val->type;
      break;
    }
  }
  if (const auto* oper = cs->component("Oper"); oper != nullptr) {
    cs->has_oper_time = find_component(*oper, "operTm") != nullptr;
  }
  (void)s->controls[cs->key];  // start routing LastApplError / CommandTermination
  co_return control_state::make(std::move(cs));
}

awaitable<result<void>> operate_once_op(std::shared_ptr<client_state> s,
                                        model::object_reference object, mms::data value,
                                        control_options options) {
  auto c = co_await get_control_op(s, std::move(object), {});
  if (!c) co_return c.error();
  const auto m = c->ctl_model();
  if (m == model::ctl_model::sbo_with_normal_security) {
    auto r = co_await c->select(options);
    if (!r) co_return r;
  } else if (m == model::ctl_model::sbo_with_enhanced_security) {
    auto r = co_await c->select_with_value(value, options);
    if (!r) co_return r;
  }
  co_return co_await c->operate(std::move(value), std::move(options));
}

}  // namespace detail

// ---------------------------------------------------------------------------------------------
// control

namespace {

template <typename... P, typename... A>
asio::awaitable<result<void>> run(const std::shared_ptr<detail::control_state>& s,
                                  asio::awaitable<result<void>> (*op)(
                                      std::shared_ptr<detail::control_state>, P...),
                                  A&&... args) {
  if (!s) return detail::ready(result<void>(openiec61850::errc::invalid_state));
  return detail::on_strand(s->client->strand, op(s, std::forward<A>(args)...));
}

}  // namespace

control::control(std::shared_ptr<detail::control_state> state) noexcept
    : state_(std::move(state)) {}

const model::object_reference& control::reference() const noexcept {
  static const model::object_reference empty;
  return state_ ? state_->object : empty;
}

model::ctl_model control::ctl_model() const noexcept {
  return state_ ? state_->model : model::ctl_model::status_only;
}

std::optional<std::chrono::milliseconds> control::sbo_timeout() const noexcept {
  return state_ ? state_->sbo_timeout : std::nullopt;
}

const std::optional<mms::type_description>& control::structure() const noexcept {
  static const std::optional<mms::type_description> none;
  return state_ ? state_->structure : none;
}

std::optional<mms::data_type> control::ctl_val_type() const noexcept {
  return state_ ? state_->ctl_val_type : std::nullopt;
}

std::optional<bool> control::has_oper_time() const noexcept {
  return state_ ? state_->has_oper_time : std::nullopt;
}

std::uint8_t control::ctl_num() const noexcept { return state_ ? state_->current_num.load() : 0; }

bool control::selected() const noexcept { return state_ && state_->selected.load(); }

std::optional<last_appl_error> control::last_error() const {
  if (!state_) return std::nullopt;
  const std::lock_guard lock(state_->mutex);
  return state_->last_error;
}

asio::awaitable<result<void>> control::select(control_options options) {
  return run(state_, &detail::select_impl, std::move(options));
}

asio::awaitable<result<void>> control::select_with_value(mms::data value, control_options options) {
  return run(state_, &detail::select_with_value_impl, std::move(value), std::move(options));
}

asio::awaitable<result<void>> control::operate(mms::data value, control_options options) {
  return run(state_, &detail::operate_impl, std::move(value), std::move(options));
}

asio::awaitable<result<void>> control::cancel(control_options options) {
  return run(state_, &detail::cancel_impl, std::move(options));
}

}  // namespace openiec61850::client
