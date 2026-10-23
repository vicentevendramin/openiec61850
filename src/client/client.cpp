#include "openiec61850/client/client.hpp"

#include <algorithm>
#include <utility>

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/dispatch.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>

#include "detail.hpp"

namespace openiec61850::client {
namespace detail {

using asio::awaitable;

awaitable<bool> wait(waiter& w) {
  if (w.notified) co_return true;
  w.timer.expires_at(clock::time_point::max());
  auto [ec] = co_await w.timer.async_wait(asio::as_tuple(asio::use_awaitable));
  (void)ec;
  const auto cs = co_await asio::this_coro::cancellation_state;
  if (cs.cancelled() != asio::cancellation_type::none) co_return false;
  co_return w.notified;
}

client_state::client_state(asio::any_io_executor ex, client_options o)
    : executor(ex),
      strand(asio::make_strand(ex)),
      options(std::move(o)),
      limits(model::name_limits::for_edition(options.edition)),
      parse{limits, options.strict_ln_names} {
  reports.capacity = std::max<std::size_t>(1, options.report_queue_capacity);
  events.capacity = std::max<std::size_t>(1, options.event_queue_capacity);
}

result<assoc_ptr> client_state::current() const {
  if (state.load() != connection_state::established || !assoc) {
    return make_error_code(errc::not_connected);
  }
  return assoc;
}

void client_state::adopt(association::client_association a) {
  auto p = std::make_shared<association::client_association>(std::move(a));
  {
    const std::lock_guard lock(mutex);
    info = p->info();
  }
  // The handler runs on the association's strand; reports are handled on the client's.
  p->set_unconfirmed_handler(
      [weak = weak_from_this(), s = strand](association::unconfirmed_message m) {
        asio::post(s, [weak, m = std::move(m)] {
          if (auto self = weak.lock()) self->on_unconfirmed(m);
        });
      });
  assoc = std::move(p);
}

namespace {

// The subscription a report belongs to: by RptID (the RCB reference when RptID is empty,
// 7-2 §17.2.2.2), then by DatSet when several share the RptID.
subscription* match(std::map<std::string, subscription>& subs, const report& r) {
  subscription* found = nullptr;
  for (auto& [key, sub] : subs) {
    const bool id = sub.rpt_id.empty()
                        ? (r.rpt_id == sub.mms_reference || r.rpt_id == sub.rcb.text())
                        : r.rpt_id == sub.rpt_id;
    if (!id) continue;
    if (r.data_set && sub.data_set && *r.data_set != *sub.data_set) continue;
    if (found == nullptr) found = &sub;
  }
  return found;
}

}  // namespace

void client_state::on_unconfirmed(const association::unconfirmed_message& m) {
  lost_reports += m.lost_before();
  dropped.fetch_add(m.lost_before());
  const auto* ir = m.information_report();
  if (ir == nullptr) return;  // other unconfirmed services are not used by IEC 61850
  if (is_control_message(*ir)) {
    auto msg = parse_control_message(*ir);
    if (!msg) return;
    const auto it = controls.find(control_key(msg->control_object));
    if (it != controls.end()) it->second.push(std::move(*msg));
    return;
  }
  if (!is_report(*ir)) return;
  auto r = parse_report(*ir, {}, parse);
  if (!r) {
    ++lost_reports;
    dropped.fetch_add(1);
    return;
  }
  if (auto* sub = match(subscriptions, *r)) {
    r->rcb = sub->rcb;
    for (auto& e : r->entries) {
      if (!e.reference && e.index < sub->members.size()) e.reference = sub->members[e.index];
    }
    if (sub->buffered && r->entry_id) {
      sub->last_entry_id = *r->entry_id;
      const std::lock_guard lock(mutex);
      entry_ids.insert_or_assign(sub->rcb.to_string(), *r->entry_id);
    }
  }
  r->lost_before += lost_reports;
  lost_reports = 0;
  dropped.fetch_add(reports.push(std::move(*r)));
}

void client_state::emit(connection_event e) { (void)events.push(std::move(e)); }

void client_state::notify_controls() {
  for (auto& [key, ch] : controls) {
    if (ch.consumer != nullptr) ch.consumer->notify();
  }
}

void client_state::finish(std::error_code reason) {
  if (closed()) return;
  close_error = reason;
  state.store(connection_state::closed);
  if (backoff) backoff->cancel();
  assoc.reset();
  notify_controls();
  if (reports.consumer != nullptr) reports.consumer->notify();
  if (events.consumer != nullptr) events.consumer->notify();
  for (auto* w : closed_waiters) w->notify();
}

awaitable<void> client_state::supervise(std::shared_ptr<client_state> self) {
  for (;;) {
    const auto a = self->assoc;
    if (!a) co_return;
    const auto ec = co_await a->wait_closed();
    if (self->closing || self->closed()) {
      self->finish(ec);
      co_return;
    }
    self->assoc.reset();
    self->notify_controls();
    if (!self->options.recovery.enabled) {
      self->emit({connection_event::kind::lost, ec, 0, {}});
      self->finish(ec);
      co_return;
    }
    self->state.store(connection_state::reconnecting);
    self->emit({connection_event::kind::lost, ec, 0, {}});

    std::error_code last = ec;
    std::size_t attempt = 0;
    bool restored = false;
    const auto& rec = self->options.recovery;
    while (!restored && (rec.max_attempts == 0 || attempt < rec.max_attempts)) {
      ++attempt;
      self->emit({connection_event::kind::reconnecting, {}, attempt, {}});
      if (!rec.backoff.empty()) {
        self->backoff.emplace(self->strand, rec.backoff[std::min(attempt, rec.backoff.size()) - 1]);
        auto [timer_ec] = co_await self->backoff->async_wait(asio::as_tuple(asio::use_awaitable));
        (void)timer_ec;
        self->backoff.reset();
      }
      if (self->closing) {
        self->finish(association::errc::aborted);
        co_return;
      }
      auto c = co_await association::client_association::connect(self->executor,
                                                                  self->options.association);
      if (self->closing) {
        if (c) c->abort();
        self->finish(association::errc::aborted);
        co_return;
      }
      if (!c) {
        last = c.error();
        continue;
      }
      self->adopt(std::move(*c));
      const auto fresh = self->assoc;
      auto errors = co_await restore_on(self, fresh);
      if (self->closing) break;  // the outer loop sees the closed association and finishes
      if (fresh->state() == association::association_state::closed) {
        last = co_await fresh->wait_closed();
        self->assoc.reset();
        continue;
      }
      self->state.store(connection_state::established);
      self->emit({connection_event::kind::restored, {}, attempt, std::move(errors)});
      restored = true;
    }
    if (self->closing) {
      if (!self->assoc) {
        self->finish(association::errc::aborted);
        co_return;
      }
      continue;
    }
    if (!restored) {
      self->emit({connection_event::kind::failed, last, attempt, {}});
      self->finish(errc::recovery_failed);
      co_return;
    }
  }
}

namespace {

awaitable<result<void>> connect_op(std::shared_ptr<client_state> self) {
  auto c = co_await association::client_association::connect(self->executor,
                                                             self->options.association);
  if (!c) co_return c.error();
  self->adopt(std::move(*c));
  self->state.store(connection_state::established);
  asio::co_spawn(self->strand, client_state::supervise(self), asio::detached);
  co_return result<void>{};
}

awaitable<std::error_code> wait_closed_op(std::shared_ptr<client_state> self) {
  if (self->closed()) co_return self->close_error;
  waiter w(self->strand);
  self->closed_waiters.push_back(&w);
  struct unregister {
    std::vector<waiter*>& list;
    waiter* item;
    ~unregister() { std::erase(list, item); }
  } guard{self->closed_waiters, &w};
  if (!co_await wait(w) && !self->closed()) {
    co_return make_error_code(asio::error::operation_aborted);
  }
  co_return self->close_error;
}

awaitable<result<void>> release_op(std::shared_ptr<client_state> self) {
  if (self->closed()) co_return self->close_error;
  if (self->closing) co_return openiec61850::errc::invalid_state;
  self->closing = true;
  if (self->state.load() == connection_state::reconnecting) {
    if (self->backoff) self->backoff->cancel();
    if (self->assoc) self->assoc->abort();
    (void)co_await wait_closed_op(self);
    co_return result<void>{};
  }
  self->state.store(connection_state::closing);
  const auto a = self->assoc;
  auto r = co_await a->release();
  if (!r && r.error() == association::errc::conclude_refused) {
    self->closing = false;
    self->state.store(connection_state::established);
    co_return r;
  }
  (void)co_await wait_closed_op(self);
  co_return r;
}

template <typename T>
awaitable<result<T>> next_op(std::shared_ptr<client_state> self,
                             delivery_queue<T> client_state::*member) {
  auto& q = (*self).*member;
  if (q.consumer != nullptr) co_return openiec61850::errc::invalid_state;
  for (;;) {
    if (!q.items.empty()) {
      T v = std::move(q.items.front());
      q.items.pop_front();
      co_return v;
    }
    if (self->closed()) co_return self->close_error;
    waiter w(self->strand);
    q.consumer = &w;
    struct reset {
      waiter*& slot;
      ~reset() { slot = nullptr; }
    } guard{q.consumer};
    if (!co_await wait(w)) co_return make_error_code(asio::error::operation_aborted);
  }
}

awaitable<result<report>> next_report_op(std::shared_ptr<client_state> self) {
  co_return co_await next_op(std::move(self), &client_state::reports);
}

awaitable<result<connection_event>> next_event_op(std::shared_ptr<client_state> self) {
  co_return co_await next_op(std::move(self), &client_state::events);
}

}  // namespace
}  // namespace detail

namespace {

// Runs op(state, args...) on the client strand. The arguments are moved into the coroutine frame
// before this returns, so the handle may be moved or destroyed meanwhile.
template <typename R, typename... P, typename... A>
asio::awaitable<R> invoke(const std::shared_ptr<detail::client_state>& s,
                          asio::awaitable<R> (*op)(std::shared_ptr<detail::client_state>, P...),
                          A&&... args) {
  if (!s) return detail::ready(R(openiec61850::errc::invalid_state));
  return detail::on_strand(s->strand, op(s, std::forward<A>(args)...));
}

}  // namespace

client::client(std::shared_ptr<detail::client_state> state) noexcept : state_(std::move(state)) {}

client& client::operator=(client&& other) noexcept {
  if (this != &other) {
    abort();
    state_ = std::move(other.state_);
  }
  return *this;
}

client::~client() { abort(); }

asio::awaitable<result<client>> client::connect(asio::any_io_executor ex, client_options options) {
  auto state = std::make_shared<detail::client_state>(ex, std::move(options));
  auto r = co_await detail::on_strand(state->strand, detail::connect_op(state));
  if (!r) co_return r.error();
  co_return client(std::move(state));
}

asio::awaitable<result<void>> client::release() { return invoke(state_, &detail::release_op); }

void client::abort() noexcept {
  if (!state_) return;
  asio::dispatch(state_->strand, [s = state_] {
    s->closing = true;
    if (s->backoff) s->backoff->cancel();
    if (s->assoc) s->assoc->abort();
  });
}

asio::awaitable<std::error_code> client::wait_closed() {
  if (!state_) {
    return detail::ready(openiec61850::make_error_code(openiec61850::errc::invalid_state));
  }
  return detail::on_strand(state_->strand, detail::wait_closed_op(state_));
}

connection_state client::state() const noexcept {
  return state_ ? state_->state.load() : connection_state::closed;
}

association::association_info client::association_info() const {
  if (!state_) return {};
  const std::lock_guard lock(state_->mutex);
  return state_->info;
}

const client_options& client::options() const noexcept { return state_->options; }

client::executor_type client::get_executor() const noexcept { return state_->strand; }

asio::awaitable<result<std::vector<std::string>>> client::get_server_directory() {
  return invoke(state_, &detail::get_server_directory_op);
}

asio::awaitable<result<std::vector<std::string>>> client::get_logical_device_directory(
    std::string ld) {
  return invoke(state_, &detail::get_logical_device_directory_op, std::move(ld));
}

asio::awaitable<result<logical_node_directory>> client::get_logical_node_directory(
    model::object_reference ln) {
  return invoke(state_, &detail::get_logical_node_directory_op, std::move(ln));
}

asio::awaitable<result<std::vector<data_directory_entry>>> client::get_data_directory(
    model::object_reference ref) {
  return invoke(state_, &detail::get_data_directory_op, std::move(ref));
}

asio::awaitable<result<data_definition>> client::get_data_definition(model::object_reference ref) {
  return invoke(state_, &detail::get_data_definition_op, std::move(ref));
}

asio::awaitable<result<std::vector<std::string>>> client::get_name_list(mms::object_class cls,
                                                                         std::string domain) {
  return invoke(state_, &detail::get_name_list_op, cls, std::move(domain));
}

asio::awaitable<result<mms::data>> client::read(model::object_reference ref) {
  return invoke(state_, &detail::read_op, std::move(ref));
}

asio::awaitable<result<std::vector<result<mms::data>>>> client::read_many(
    std::vector<model::object_reference> refs) {
  return invoke(state_, &detail::read_many_op, std::move(refs));
}

asio::awaitable<result<void>> client::write(model::object_reference ref, mms::data value) {
  return invoke(state_, &detail::write_op, std::move(ref), std::move(value));
}

asio::awaitable<result<std::vector<result<void>>>> client::write_many(std::vector<write_item> items) {
  return invoke(state_, &detail::write_many_op, std::move(items));
}

asio::awaitable<result<data_set_directory>> client::get_data_set_directory(
    model::object_reference data_set) {
  return invoke(state_, &detail::get_data_set_directory_op, std::move(data_set));
}

asio::awaitable<result<void>> client::create_data_set(model::object_reference data_set,
                                                      std::vector<model::object_reference> members) {
  return invoke(state_, &detail::create_data_set_op, std::move(data_set), std::move(members));
}

asio::awaitable<result<void>> client::delete_data_set(model::object_reference data_set) {
  return invoke(state_, &detail::delete_data_set_op, std::move(data_set));
}

asio::awaitable<result<std::vector<result<mms::data>>>> client::get_data_set_values(
    model::object_reference data_set) {
  return invoke(state_, &detail::get_data_set_values_op, std::move(data_set));
}

asio::awaitable<result<std::vector<result<void>>>> client::set_data_set_values(
    model::object_reference data_set, std::vector<mms::data> values) {
  return invoke(state_, &detail::set_data_set_values_op, std::move(data_set), std::move(values));
}

asio::awaitable<result<rcb_values>> client::get_rcb_values(model::object_reference rcb) {
  return invoke(state_, &detail::get_rcb_values_op, std::move(rcb));
}

asio::awaitable<result<void>> client::set_rcb_values(model::object_reference rcb,
                                                     rcb_settings settings) {
  return invoke(state_, &detail::set_rcb_values_op, std::move(rcb), std::move(settings));
}

asio::awaitable<result<rcb_values>> client::enable_reporting(model::object_reference rcb,
                                                             report_settings settings) {
  return invoke(state_, &detail::enable_reporting_op, std::move(rcb), std::move(settings));
}

asio::awaitable<result<void>> client::disable_reporting(model::object_reference rcb) {
  return invoke(state_, &detail::disable_reporting_op, std::move(rcb));
}

asio::awaitable<result<void>> client::trigger_gi(model::object_reference rcb) {
  return invoke(state_, &detail::trigger_gi_op, std::move(rcb));
}

asio::awaitable<result<control>> client::get_control(model::object_reference object,
                                                     control_config config) {
  return invoke(state_, &detail::get_control_op, std::move(object), std::move(config));
}

asio::awaitable<result<void>> client::operate(model::object_reference object, mms::data value,
                                              control_options options) {
  return invoke(state_, &detail::operate_once_op, std::move(object), std::move(value),
                std::move(options));
}

std::optional<model::entry_id> client::last_entry_id(const model::object_reference& rcb) const {
  if (!state_) return std::nullopt;
  const std::lock_guard lock(state_->mutex);
  const auto it = state_->entry_ids.find(rcb.to_string());
  if (it == state_->entry_ids.end()) return std::nullopt;
  return it->second;
}

asio::awaitable<result<report>> client::next_report() {
  return invoke(state_, &detail::next_report_op);
}

void client::set_report_handler(std::function<void(report)> handler) {
  if (!state_) return;
  asio::dispatch(state_->strand, [s = state_, h = std::move(handler)]() mutable {
    s->reports.set_handler(std::move(h));
  });
}

std::uint64_t client::reports_dropped() const noexcept {
  return state_ ? state_->dropped.load() : 0;
}

asio::awaitable<result<connection_event>> client::next_event() {
  return invoke(state_, &detail::next_event_op);
}

void client::set_event_handler(std::function<void(connection_event)> handler) {
  if (!state_) return;
  asio::dispatch(state_->strand, [s = state_, h = std::move(handler)]() mutable {
    s->events.set_handler(std::move(h));
  });
}

}  // namespace openiec61850::client
