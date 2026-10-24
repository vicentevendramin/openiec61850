#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>
#include <asio/steady_timer.hpp>
#include <asio/strand.hpp>
#include <asio/this_coro.hpp>

#include "openiec61850/association/client_association.hpp"
#include "openiec61850/client/client.hpp"
#include "openiec61850/model/mms_mapping.hpp"
#include "openiec61850/transport/spawn.hpp"

namespace openiec61850::client::detail {

using strand_type = client::executor_type;
using clock = std::chrono::steady_clock;

// The association an operation sends its requests on, plus where those requests record the
// details of their failures (the caller's error_details, or nothing).
class assoc_ptr {
 public:
  assoc_ptr() noexcept = default;
  assoc_ptr(std::shared_ptr<association::client_association> p,  // NOLINT: implicit on purpose
            error_details* details = nullptr) noexcept
      : p_(std::move(p)), details_(details) {}

  association::client_association* operator->() const noexcept { return p_.get(); }
  association::client_association& operator*() const noexcept { return *p_; }
  explicit operator bool() const noexcept { return p_ != nullptr; }
  [[nodiscard]] const std::shared_ptr<association::client_association>& shared() const noexcept {
    return p_;
  }
  [[nodiscard]] error_details* details() const noexcept { return details_; }

  // A request failed: keep the server's answer (replaces that of an earlier request).
  void record(const association::request_error& e) const {
    if (details_ == nullptr) return;
    details_->service_error = e.service_error;
    details_->modifier_position = e.modifier_position;
    details_->reject = e.reject;
  }
  void record(const last_appl_error& e) const {
    if (details_ != nullptr) details_->last_appl_error = e;
  }

  friend bool operator==(const assoc_ptr& a,
                         const std::shared_ptr<association::client_association>& b) noexcept {
    return a.p_ == b;
  }

 private:
  std::shared_ptr<association::client_association> p_;
  error_details* details_ = nullptr;
};

template <typename T>
asio::awaitable<T> on_strand(strand_type strand, asio::awaitable<T> op) {
  const auto current = co_await asio::this_coro::executor;
  if (current == asio::any_io_executor(strand)) co_return co_await std::move(op);
  co_return co_await transport::run_on(strand, std::move(op));
}

template <typename T>
asio::awaitable<T> ready(T value) {
  co_return value;
}

// Runs `op` (a service that records request failures in `d`), then sets d.code; clears `d`
// first and again on success.
template <typename R>
asio::awaitable<R> with_details(error_details& d, asio::awaitable<R> op) {
  d = {};
  auto r = co_await std::move(op);
  if (r) {
    d = {};
  } else {
    d.code = r.error();
  }
  co_return r;
}

// One coroutine waiting on the strand. notify() may come before the wait.
struct waiter {
  explicit waiter(const strand_type& s) : timer(s, clock::time_point::max()) {}
  void notify() noexcept {
    notified = true;
    timer.cancel();
  }
  asio::steady_timer timer;
  bool notified = false;
};

// True when notified; false when the awaiting coroutine was cancelled.
[[nodiscard]] asio::awaitable<bool> wait(waiter& w);

// Request failure -> error code (service errors naming a missing object etc. -> client::errc).
[[nodiscard]] std::error_code request_error_code(const association::request_error& e);

// A bounded delivery queue for one consumer, or a handler.
template <typename T>
struct delivery_queue {
  std::deque<T> items;
  std::size_t capacity = 1;
  waiter* consumer = nullptr;
  std::function<void(T)> handler;

  // Returns the number of items dropped by the overflow policy.
  std::size_t push(T v) {
    if (handler) {
      handler(std::move(v));
      return 0;
    }
    std::size_t dropped = 0;
    if (items.size() >= capacity) {
      if constexpr (std::is_same_v<T, report>) {
        const auto lost = items.front().lost_before + 1;
        items.pop_front();
        if (!items.empty()) {
          items.front().lost_before += lost;
        } else {
          v.lost_before += lost;
        }
      } else {
        items.pop_front();
      }
      dropped = 1;
    }
    items.push_back(std::move(v));
    if (consumer != nullptr) consumer->notify();
    return dropped;
  }

  void set_handler(std::function<void(T)> h) {
    handler = std::move(h);
    if (!handler) return;
    while (!items.empty()) {
      auto v = std::move(items.front());
      items.pop_front();
      handler(std::move(v));
    }
  }
};

// An RCB enabled with enable_reporting(), restored by the recovery.
struct subscription {
  model::object_reference rcb;
  bool buffered = false;
  report_settings settings;
  std::string rpt_id;          // as read back
  std::string mms_reference;   // "LD/LN$BR$name"
  std::optional<std::string> data_set;  // MMS form, as read back
  std::vector<model::object_reference> members;
  std::optional<model::entry_id> last_entry_id;
  bool reserved = false;
};

// Control InformationReports (LastApplError, CommandTermination) for one controllable object,
// key "LD/LN$CO$DO". Created by get_control(); messages for objects without a channel are
// dropped.
struct control_channel {
  static constexpr std::size_t capacity = 16;
  std::deque<control_message> messages;
  waiter* consumer = nullptr;
  bool busy = false;  // an operation is in progress

  void push(control_message m) {
    if (messages.size() >= capacity) messages.pop_front();
    messages.push_back(std::move(m));
    if (consumer != nullptr) consumer->notify();
  }
};

// "LD/LN$CO$DO" from a CntrlObj or termination variable ("LD/LN$CO$DO$Oper", "...$SBOw",
// "...$Cancel", "...$SBO"; an ACSI "LD/LN.DO" is mapped too).
[[nodiscard]] std::string control_key(std::string_view control_object);

struct client_state : std::enable_shared_from_this<client_state> {
  client_state(asio::any_io_executor ex, client_options o);

  asio::any_io_executor executor;
  strand_type strand;
  client_options options;
  model::name_limits limits;
  model::parse_options parse;

  // The current association; null while reconnecting and once closed.
  std::shared_ptr<association::client_association> assoc;
  std::atomic<connection_state> state{connection_state::established};
  bool closing = false;  // close()/abort() requested: no recovery
  std::error_code close_error;
  std::vector<waiter*> closed_waiters;
  std::optional<asio::steady_timer> backoff;

  std::map<std::string, subscription> subscriptions;  // key: rcb.to_string()
  std::map<std::string, control_channel> controls;    // key: control_key()

  mutable std::mutex mutex;  // guards info and entry_ids (read from any thread)
  association::association_info info;
  std::map<std::string, model::entry_id> entry_ids;

  delivery_queue<report> reports;
  delivery_queue<connection_event> events;
  std::size_t lost_reports = 0;  // to add to the next report's lost_before
  std::atomic<std::uint64_t> dropped{0};

  [[nodiscard]] bool closed() const noexcept { return state.load() == connection_state::closed; }
  // The established association, or errc::not_connected. Its requests record their failures in
  // `details` when not null.
  [[nodiscard]] result<assoc_ptr> current(error_details* details = nullptr) const;

  void adopt(association::client_association a);
  void on_unconfirmed(const association::unconfirmed_message& m);
  void emit(connection_event e);
  // Wakes the operations waiting for a CommandTermination (association lost or closed).
  void notify_controls();
  void finish(std::error_code reason);

  static asio::awaitable<void> supervise(std::shared_ptr<client_state> self);
};

// --- services (services.cpp). The *_on variants use the given association; the others the
// current one. All run on the client strand.

asio::awaitable<result<std::vector<std::string>>> name_list_on(assoc_ptr a, mms::object_class cls,
                                                                std::string domain);

asio::awaitable<result<std::vector<std::string>>> get_name_list_op(std::shared_ptr<client_state> s, error_details* d,
                                                                    mms::object_class cls,
                                                                    std::string domain);
asio::awaitable<result<std::vector<std::string>>> get_server_directory_op(
    std::shared_ptr<client_state> s, error_details* d);
asio::awaitable<result<std::vector<std::string>>> get_logical_device_directory_op(
    std::shared_ptr<client_state> s, error_details* d, std::string ld);
asio::awaitable<result<logical_node_directory>> get_logical_node_directory_op(
    std::shared_ptr<client_state> s, error_details* d, model::object_reference ln);
asio::awaitable<result<std::vector<data_directory_entry>>> get_data_directory_op(
    std::shared_ptr<client_state> s, error_details* d, model::object_reference ref);
asio::awaitable<result<data_definition>> get_data_definition_op(std::shared_ptr<client_state> s, error_details* d,
                                                                model::object_reference ref);

asio::awaitable<result<mms::data>> read_op(std::shared_ptr<client_state> s, error_details* d,
                                           model::object_reference ref);
asio::awaitable<result<std::vector<result<mms::data>>>> read_many_op(
    std::shared_ptr<client_state> s, error_details* d, std::vector<model::object_reference> refs);
asio::awaitable<result<void>> write_op(std::shared_ptr<client_state> s, error_details* d, model::object_reference ref,
                                       mms::data value);
asio::awaitable<result<std::vector<result<void>>>> write_many_op(std::shared_ptr<client_state> s, error_details* d,
                                                                 std::vector<write_item> items);

asio::awaitable<result<data_set_directory>> get_data_set_directory_op(
    std::shared_ptr<client_state> s, error_details* d, model::object_reference ds);
asio::awaitable<result<void>> create_data_set_op(std::shared_ptr<client_state> s, error_details* d,
                                                 model::object_reference ds,
                                                 std::vector<model::object_reference> members);
asio::awaitable<result<void>> delete_data_set_op(std::shared_ptr<client_state> s, error_details* d,
                                                 model::object_reference ds);
asio::awaitable<result<std::vector<result<mms::data>>>> get_data_set_values_op(
    std::shared_ptr<client_state> s, error_details* d, model::object_reference ds);
asio::awaitable<result<std::vector<result<void>>>> set_data_set_values_op(
    std::shared_ptr<client_state> s, error_details* d, model::object_reference ds, std::vector<mms::data> values);

asio::awaitable<result<rcb_values>> get_rcb_values_op(std::shared_ptr<client_state> s, error_details* d,
                                                      model::object_reference rcb);
asio::awaitable<result<void>> set_rcb_values_op(std::shared_ptr<client_state> s, error_details* d,
                                                model::object_reference rcb, rcb_settings w);
asio::awaitable<result<rcb_values>> enable_reporting_op(std::shared_ptr<client_state> s, error_details* d,
                                                        model::object_reference rcb,
                                                        report_settings settings);
asio::awaitable<result<void>> disable_reporting_op(std::shared_ptr<client_state> s, error_details* d,
                                                   model::object_reference rcb);
asio::awaitable<result<void>> trigger_gi_op(std::shared_ptr<client_state> s, error_details* d,
                                            model::object_reference rcb);

// Request helpers on a given association (services.cpp).
asio::awaitable<result<std::vector<result<mms::data>>>> read_variables_on(
    assoc_ptr a, std::vector<model::mms_variable> vars);
asio::awaitable<result<void>> write_variable_on(assoc_ptr a, model::mms_variable var,
                                                mms::data value);
asio::awaitable<result<mms::type_description>> type_description_on(assoc_ptr a,
                                                                   std::string domain,
                                                                   std::string item);

// --- control (control.cpp)

asio::awaitable<result<control>> get_control_op(std::shared_ptr<client_state> s, error_details* d,
                                               model::object_reference object,
                                               control_config config);
asio::awaitable<result<void>> operate_once_op(std::shared_ptr<client_state> s, error_details* d,
                                              model::object_reference object, mms::data value,
                                              control_options options);

// Re-enables every subscription on `a` (recovery); returns the RCBs that failed.
asio::awaitable<std::vector<rcb_error>> restore_on(std::shared_ptr<client_state> s, assoc_ptr a);

}  // namespace openiec61850::client::detail
