#include "openiec61850/server/server.hpp"

#include <algorithm>
#include <chrono>
#include <string>
#include <utility>

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/dispatch.hpp>
#include <asio/post.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include "detail.hpp"
#include "openiec61850/transport/spawn.hpp"
#include "values.hpp"

namespace openiec61850::server {

namespace {

class category final : public std::error_category {
 public:
  const char* name() const noexcept override { return "openiec61850.server"; }
  std::string message(int ev) const override {
    switch (static_cast<errc>(ev)) {
      case errc::ok: return "success";
      case errc::object_not_found: return "object not found";
      case errc::object_exists: return "object already exists";
      case errc::type_mismatch: return "value does not match the attribute type";
      case errc::invalid_model: return "invalid data model";
      case errc::not_running: return "server not running";
      case errc::access_denied: return "attribute managed by the server";
    }
    return "unknown server error";
  }
};

}  // namespace

const std::error_category& error_category() noexcept {
  static const category c;
  return c;
}

namespace detail {

namespace {

using asio::awaitable;
using model::fc;

void add_names(const server_state& st, node_id id, std::optional<model::functional_constraint> f,
               const std::string& prefix, std::vector<std::string>& out) {
  const auto& n = st.at(id);
  for (const auto c : n.children) {
    const auto& cn = st.at(c);
    if (!n.is_attribute() && f && !cn.has_fc(*f)) continue;
    std::string name = prefix + "$" + cn.name;
    if (!cn.holds_value()) add_names(st, c, f, name, out);
    out.push_back(std::move(name));
  }
}

}  // namespace

server_state::server_state(asio::any_io_executor ex, data_model m, server_options o)
    : strand(asio::make_strand(ex)), model(std::move(m)), options(std::move(o)) {}

result<void> server_state::init() {
  limits = model::name_limits::for_edition(model.edition());
  const auto nodes = model.nodes();
  values.resize(nodes.size());
  for (std::size_t i = 0; i < nodes.size(); ++i) {
    if (nodes[i].holds_value()) values[i] = nodes[i].value;
  }
  for (const auto ld : model.logical_devices()) {
    domains.push_back(at(ld).name);
    auto& names = variable_names[ld];
    for (const auto ln : at(ld).children) {
      const auto& lnn = at(ln);
      names.push_back(lnn.name);
      for (std::size_t i = 0; i < model::functional_constraint_count; ++i) {
        const auto f = static_cast<model::functional_constraint>(i);
        if (f == fc::XX || !lnn.has_fc(f)) continue;
        const std::string prefix = lnn.name + "$" + std::string(model::to_string(f));
        names.push_back(prefix);
        add_names(*this, ln, f, prefix, names);
      }
    }
    std::sort(names.begin(), names.end());
  }
  std::sort(domains.begin(), domains.end());

  for (const auto& def : model.data_sets()) {
    std::vector<model::mms_variable> vars;
    for (const auto& m : def.members) {
      auto v = model::to_mms_variable(m, model::name_limits::unlimited());
      if (!v) return make_error_code(errc::invalid_model);
      vars.push_back(std::move(*v));
    }
    std::vector<mms::variable_spec> specs;
    for (const auto& v : vars) specs.push_back(v.spec());
    const node_id ld = model.logical_device_of(def.ln);
    auto ds = make_data_set(at(ld).name, at(def.ln).name + "$" + def.name,
                            mms::list_view<mms::variable_spec>(specs));
    if (!ds) return make_error_code(errc::invalid_model);
    data_sets.emplace(std::make_pair((*ds)->domain, (*ds)->item), std::move(*ds));
  }
  for (const auto& def : model.report_controls()) init_rcb(def);

  // EntryIDs grow across restarts: the start time in the high bits, a counter below.
  const auto secs = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
  next_entry = static_cast<std::uint64_t>(secs) << 24;
  return {};
}

session* server_state::find_session(std::uint64_t id) const {
  if (id == 0) return nullptr;
  const auto it = sessions.find(id);
  return it == sessions.end() ? nullptr : it->second.get();
}

void server_state::shutdown() {
  if (stopped.exchange(true)) return;
  if (listener) listener->close();
  for (auto& [id, s] : sessions) {
    if (s->assoc) s->assoc->abort();
  }
  for (auto& r : rcbs) {
    ++r->buf_gen;
    ++r->intg_gen;
    ++r->hold_gen;
    r->buf_timer.cancel();
    r->intg_timer.cancel();
    r->resv_timer.cancel();
  }
  control_shutdown();
  for (auto* w : stop_waiters) w->cancel();
}

result<std::shared_ptr<server_state>> make_offline_state(asio::any_io_executor ex, data_model m,
                                                        server_options o) {
  auto st = std::make_shared<server_state>(std::move(ex), std::move(m), std::move(o));
  if (auto r = st->init(); !r) return r.error();
  return st;
}

namespace {

void task_done(server_state& st) {
  if (st.live_tasks.fetch_sub(1) == 1) {
    for (auto* w : st.stop_waiters) w->cancel();
  }
}

void handle_request(server_state& st, session& s, association::incoming_request req) {
  ++st.tick;
  reply out;
  st.dispatch(s, req.service(), out);
  switch (out.type) {
    case reply::kind::response:
      if (s.max_pdu > 0) {
        byte_buffer probe;
        const auto encoded =
            mms::encode_pdu(mms::confirmed_response{req.invoke_id(), out.response}, probe);
        if (encoded && probe.size() > s.max_pdu) {
          s.push(req.respond_error(mms::service_error(
              mms::error_class::resource, mms::error_code::resource::capability_unavailable)));
          return;
        }
      }
      s.push(req.respond(out.response));
      break;
    case reply::kind::error:
      s.push(req.respond_error(out.error));
      break;
    case reply::kind::reject:
      s.push(req.reject(out.reject_reason));
      break;
  }
}

awaitable<void> sender(std::shared_ptr<server_state> st, std::shared_ptr<session> s) {
  for (;;) {
    while (!s->outbox.empty()) {
      auto next = std::move(s->outbox.front());
      s->outbox.pop_front();
      auto r = co_await std::move(next);
      if (!r) {
        s->closed = true;
        s->outbox.clear();
      }
    }
    if (s->closed) break;
    s->wake.expires_at(clock::time_point::max());
    (void)co_await s->wake.async_wait(asio::as_tuple(asio::use_awaitable));
  }
  task_done(*st);
}

void session_closed(server_state& st, session& s) {
  s.closed = true;
  s.wake.cancel();
  st.control_session_closed(s);
  std::vector<std::shared_ptr<data_set>> lists;
  for (auto& [name, ds] : s.aa_sets) lists.push_back(ds);
  s.aa_sets.clear();
  for (const auto& ds : lists) st.data_set_deleted(ds);
  st.release_session_rcbs(s);
  st.sessions.erase(s.id);
  st.associations.fetch_sub(1);
}

awaitable<void> connection(std::shared_ptr<server_state> st, asio::ip::tcp::socket socket) {
  auto counted = std::make_shared<std::atomic<bool>>(false);
  auto opts = st->options.association;
  opts.authorize = [w = std::weak_ptr<server_state>(st), counted,
                    user = st->options.association.authorize](
                       const association::association_request& req,
                       mms::initiate_response& negotiated) {
    auto self = w.lock();
    if (!self || self->stopped) return association::association_decision::rejected();
    const auto max = self->options.max_associations;
    const auto now = self->associations.fetch_add(1) + 1;
    if (max > 0 && now > max) {
      self->associations.fetch_sub(1);
      return association::association_decision::rejected(
          iso::acse::service_user_diagnostic::no_reason_given);
    }
    if (user) {
      auto d = user(req, negotiated);
      if (!d.accept) {
        self->associations.fetch_sub(1);
        return d;
      }
    }
    counted->store(true);
    return association::association_decision::accepted();
  };
  auto a = co_await association::server_association::accept(std::move(socket), std::move(opts));
  if (!a) {
    if (counted->load()) st->associations.fetch_sub(1);
    task_done(*st);
    co_return;
  }
  if (st->stopped) {
    a->abort();
    st->associations.fetch_sub(1);
    task_done(*st);
    co_return;
  }
  auto s = std::make_shared<session>(st->strand);
  s->id = st->next_session++;
  const auto& info = a->info();
  const auto addr = info.remote_endpoint.address();
  s->address = addr.to_string();
  if (addr.is_v4()) {
    const auto b = addr.to_v4().to_bytes();
    s->address_bytes.assign(b.begin(), b.end());
  } else {
    const auto b = addr.to_v6().to_bytes();
    s->address_bytes.assign(b.begin(), b.end());
  }
  if (info.negotiated.local_detail_calling && *info.negotiated.local_detail_calling > 0) {
    s->max_pdu = static_cast<std::size_t>(*info.negotiated.local_detail_calling);
  }
  s->assoc.emplace(std::move(*a));
  st->sessions.emplace(s->id, s);
  st->live_tasks.fetch_add(1);
  asio::co_spawn(st->strand, sender(st, s), asio::detached);

  for (;;) {
    auto req = co_await s->assoc->next_request();
    if (!req) break;
    handle_request(*st, *s, std::move(*req));
  }
  session_closed(*st, *s);
  task_done(*st);
}

awaitable<void> accept_loop(std::shared_ptr<server_state> st) {
  for (;;) {
    auto socket = co_await st->listener->accept_socket();
    if (st->stopped) break;
    if (!socket) {
      if (socket.error() == asio::error::operation_aborted) break;
      // e.g. too many open files: retry a little later.
      asio::steady_timer t(st->strand, std::chrono::milliseconds(50));
      (void)co_await t.async_wait(asio::as_tuple(asio::use_awaitable));
      continue;
    }
    st->live_tasks.fetch_add(1);
    asio::co_spawn(st->strand, connection(st, std::move(*socket)), asio::detached);
  }
  task_done(*st);
}

struct resolved_update {
  std::vector<assignment> plan;
  node_id t_node = no_node;  // sibling `t` for the automatic timestamp
  bool has_timestamp = false;
};

// The DO holding a data attribute (the attribute's top-level ancestor's parent), or the node
// itself for a DO.
node_id owning_object(const server_state& st, node_id id) {
  node_id n = id;
  while (n != no_node && st.at(n).kind == node_kind::data_attribute) n = st.at(n).parent;
  return n;
}

node_id sibling(const server_state& st, node_id owner, std::string_view name,
                std::optional<model::functional_constraint> f) {
  const node_id c = st.model.find_child(owner, name);
  if (c == no_node || !st.at(c).holds_value()) return no_node;
  if (f && st.at(c).fc != f) return no_node;
  return c;
}

result<resolved_update> resolve_update(const server_state& st, const data_update& u) {
  auto t = st.resolve_ref(u.reference);
  if (!t) return t.error();
  if (t->fc == fc::BR || t->fc == fc::RP || !t->fc ||
      st.at(t->node).kind == node_kind::logical_node) {
    return make_error_code(t->fc == fc::BR || t->fc == fc::RP ? errc::access_denied
                                                              : errc::object_not_found);
  }
  auto type = st.type_of(*t);
  if (!type) return type.error();
  auto c = conform(u.value, *type);
  if (std::holds_alternative<dae>(c)) return make_error_code(errc::type_mismatch);
  resolved_update out;
  st.plan(*t, std::get<mms::data>(c), out.plan);
  const node_id owner = owning_object(st, t->node);
  if (u.quality) {
    const node_id q = sibling(st, owner, "q", t->fc);
    if (q == no_node) return make_error_code(errc::object_not_found);
    out.plan.push_back({q, {}, u.quality->to_mms()});
  }
  out.t_node = sibling(st, owner, "t", t->fc);
  if (u.timestamp) {
    if (out.t_node == no_node) return make_error_code(errc::object_not_found);
    out.plan.push_back({out.t_node, {}, u.timestamp->to_mms()});
    out.has_timestamp = true;
  }
  return out;
}

}  // namespace

}  // namespace detail

using detail::server_state;

server::server(std::shared_ptr<server_state> state) noexcept : state_(std::move(state)) {}

server& server::operator=(server&& other) noexcept {
  if (this != &other) {
    stop();
    state_ = std::move(other.state_);
  }
  return *this;
}

server::~server() { stop(); }

result<server> server::start(asio::any_io_executor ex, data_model model,
                             const asio::ip::tcp::endpoint& endpoint, server_options options) {
  if (model.logical_devices().empty()) return make_error_code(errc::invalid_model);
  auto st = std::make_shared<server_state>(ex, std::move(model), std::move(options));
  if (auto r = st->init(); !r) return r.error();
  auto l = association::association_listener::listen(ex, endpoint, st->options.association);
  if (!l) return l.error();
  st->endpoint = l->local_endpoint();
  st->listener.emplace(std::move(*l));
  st->live_tasks.fetch_add(1);
  asio::co_spawn(st->strand, detail::accept_loop(st), asio::detached);
  return server(std::move(st));
}

void server::stop() noexcept {
  if (!state_) return;
  asio::dispatch(state_->strand, [s = state_] { s->shutdown(); });
}

asio::awaitable<void> server::wait_stopped() {
  if (!state_) co_return;
  auto st = state_;
  auto op = [](std::shared_ptr<server_state> s) -> asio::awaitable<result<bool>> {
    while (!s->stopped || s->live_tasks.load() > 0) {
      asio::steady_timer t(s->strand, detail::clock::time_point::max());
      s->stop_waiters.push_back(&t);
      (void)co_await t.async_wait(asio::as_tuple(asio::use_awaitable));
      std::erase(s->stop_waiters, &t);
    }
    co_return true;
  };
  (void)co_await transport::run_on(st->strand, op(st));
}

result<void> server::update(const model::object_reference& ref, mms::data value,
                            std::optional<model::quality> quality,
                            std::optional<model::timestamp> timestamp) {
  std::vector<data_update> batch;
  batch.push_back({ref, std::move(value), quality, timestamp});
  return update(std::move(batch));
}

result<void> server::update(std::vector<data_update> batch) {
  if (!state_ || state_->stopped) return make_error_code(errc::not_running);
  std::vector<detail::resolved_update> items;
  items.reserve(batch.size());
  for (const auto& u : batch) {
    auto r = detail::resolve_update(*state_, u);
    if (!r) return r.error();
    items.push_back(std::move(*r));
  }
  asio::post(state_->strand, [s = state_, items = std::move(items)]() mutable {
    if (s->stopped) return;
    ++s->tick;
    std::vector<detail::assignment> all;
    for (auto& item : items) {
      bool stamp = false;
      if (s->options.auto_timestamp && !item.has_timestamp && item.t_node != no_node) {
        for (const auto& a : item.plan) {
          const auto& tr = s->at(a.holder).triggers;
          if (!tr.dchg && !tr.qchg) continue;
          const mms::data* cur = &s->values[a.holder];
          for (const auto& sel : a.path) cur = &cur->elements()[sel.value];
          if (!(*cur == a.value)) {
            stamp = true;
            break;
          }
        }
      }
      for (auto& a : item.plan) all.push_back(std::move(a));
      if (stamp) all.push_back({item.t_node, {}, model::timestamp::now().to_mms()});
    }
    s->apply(std::move(all));
  });
  return {};
}

asio::awaitable<result<mms::data>> server::read(model::object_reference ref) const {
  if (!state_) co_return make_error_code(errc::not_running);
  auto op = [](std::shared_ptr<server_state> s, model::object_reference r)
      -> asio::awaitable<result<mms::data>> {
    if (!r.has_ln()) co_return make_error_code(errc::object_not_found);
    if (r.path().empty() && !r.fc()) {
      auto t = s->resolve_mms(mms::object_name::domain(r.ld(), r.ln()), {});
      if (!t) co_return make_error_code(errc::object_not_found);
      co_return s->value_of(*t);
    }
    auto t = s->resolve_ref(r);
    if (!t) co_return t.error();
    co_return s->value_of(*t);
  };
  co_return co_await transport::run_on(state_->strand, op(state_, std::move(ref)));
}

std::size_t server::association_count() const noexcept {
  return state_ ? state_->associations.load() : 0;
}

const asio::ip::tcp::endpoint& server::local_endpoint() const noexcept { return state_->endpoint; }

const data_model& server::model() const noexcept { return state_->model; }

server::executor_type server::get_executor() const noexcept { return state_->strand; }

}  // namespace openiec61850::server
