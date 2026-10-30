// openiec61850-server: serves the data model of an SCL file (ICD / IID / CID / SCD) over MMS.
//
// Every control is accepted and its ctlVal mirrored into stVal; with --simulate the MX analog
// values follow a random walk and the status-only BOOLEAN stVal toggle, so reports flow.

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/address.hpp>
#include <asio/redirect_error.hpp>
#include <asio/signal_set.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include "openiec61850/model/basic_type.hpp"
#include "common.hpp"
#include "openiec61850/model/enums.hpp"
#include "openiec61850/model/object_reference.hpp"
#include "openiec61850/server/scl_model.hpp"
#include "openiec61850/server/server.hpp"

namespace {

namespace srv = openiec61850::server;
namespace model = openiec61850::model;
namespace mms = openiec61850::mms;
namespace tools = openiec61850::tools;
using model::functional_constraint;

constexpr const char* usage_text =
    "usage: openiec61850-server --scl FILE [options]\n"
    "\n"
    "Serves the IED data model of an SCL file over IEC 61850 MMS.\n"
    "\n"
    "  --scl FILE            SCL file (ICD, IID, CID or SCD)\n"
    "  --ied NAME            IED to serve (default: the first one)\n"
    "  --ap NAME             access point (default: the first one with a server)\n"
    "  --port N              TCP port (default 102; 0 picks a free port)\n"
    "  --bind ADDR           local address (default 0.0.0.0)\n"
    "  --password PW         require ACSE password authentication\n"
    "  --tls                 use TLS (IEC 62351-3); the port stays --port, usually 3782\n"
    "  --tls-ca FILE         trust anchors (PEM)\n"
    "  --tls-cert FILE       own certificate chain (PEM)\n"
    "  --tls-key FILE        own private key (PEM)\n"
    "  --tls-crl FILE        certificate revocation lists (PEM)\n"
    "  --tls-peer-name NAME  name the peer certificate must carry\n"
    "  --tls-no-verify       accept any peer certificate\n"
    "  --simulate            random-walk MX analog values, toggle status-only BOOLEAN stVal\n"
    "  --period MS           simulation period (default 1000)\n"
    "  --control-delay MS    complete operations after MS (enhanced security: CommandTermination)\n"
    "  --verbose             log associations, writes, controls and SCL diagnostics\n"
    "  --help                this text\n"
    "\n"
    "Prints \"listening on ADDR:PORT\" once ready; SIGINT / SIGTERM stop it.\n";

bool verbose = false;

void log(const std::string& line) {
  if (!verbose) return;
  std::fprintf(stderr, "%s\n", line.c_str());
  std::fflush(stderr);
}

std::optional<model::object_reference> make_ref(const std::string& text) {
  auto r = model::object_reference::parse(text);
  if (!r) return std::nullopt;
  return std::move(*r);
}

std::string ref_with_fc(const srv::data_model& m, srv::node_id id, functional_constraint fc) {
  return m.reference_of(id) + "[" + std::string(model::to_string(fc)) + "]";
}

struct simulated_value {
  model::object_reference reference;
  double value = 0;
  bool is_double = false;
};

// What --simulate drives, found once in the model.
struct simulation {
  std::vector<simulated_value> analogs;          // MX FLOAT32 / FLOAT64 leaves
  std::vector<model::object_reference> toggles;  // ST BOOLEAN stVal of non-controllable DOs
  std::vector<bool> toggle_state;
  std::size_t next_toggle = 0;
  std::mt19937 rng{std::random_device{}()};
};

simulation find_simulated(const srv::data_model& m) {
  simulation s;
  const auto nodes = m.nodes();
  for (srv::node_id id = 0; id < nodes.size(); ++id) {
    const auto& n = nodes[id];
    if (!n.is_attribute() || !n.type || n.count > 0 || !n.fc) continue;
    if (*n.fc == functional_constraint::MX &&
        (*n.type == model::basic_type::float32 || *n.type == model::basic_type::float64)) {
      if (auto r = make_ref(ref_with_fc(m, id, functional_constraint::MX))) {
        double start = 0;
        if (auto d = n.value.as_double()) start = *d;
        s.analogs.push_back({*r, start, *n.type == model::basic_type::float64});
      }
    } else if (*n.fc == functional_constraint::ST && *n.type == model::basic_type::boolean &&
               n.name == "stVal" && n.parent != srv::no_node &&
               !m.at(n.parent).has_fc(functional_constraint::CO)) {
      if (auto r = make_ref(ref_with_fc(m, id, functional_constraint::ST))) {
        s.toggles.push_back(*r);
        s.toggle_state.push_back(n.value.as_boolean() && *n.value.as_boolean());
      }
    }
  }
  return s;
}

void simulate_step(srv::server& server, simulation& s, std::uint64_t tick) {
  std::normal_distribution<double> step(0.0, 1.0);
  std::vector<srv::data_update> batch;
  for (auto& a : s.analogs) {
    a.value += step(s.rng);
    mms::data v = a.is_double ? mms::data::floating_point(a.value)
                              : mms::data::floating_point(static_cast<float>(a.value));
    batch.push_back({a.reference, std::move(v), std::nullopt, std::nullopt});
  }
  // One indication every other period, round robin.
  if (!s.toggles.empty() && tick % 2 == 0) {
    const auto i = s.next_toggle++ % s.toggles.size();
    s.toggle_state[i] = !s.toggle_state[i];
    batch.push_back({s.toggles[i], mms::data::boolean(s.toggle_state[i]), std::nullopt, std::nullopt});
  }
  if (batch.empty()) return;
  if (auto r = server.update(std::move(batch)); !r) {
    log("simulation update failed: " + r.error().message());
  }
}

// stVal (or, for an analogue control, mxVal is left alone) following ctlVal: same type, or a
// BOOLEAN ctlVal onto a Dbpos stVal (DPC).
std::optional<mms::data> mirrored(const srv::data_model& m, const model::object_reference& st,
                                  const mms::data& ctl_val) {
  auto id = m.find(st);
  if (!id) return std::nullopt;
  const auto& n = m.at(*id);
  if (!n.type) return std::nullopt;
  if (*n.type == model::basic_type::dbpos && ctl_val.type() == mms::data_type::boolean) {
    return model::to_mms(*ctl_val.as_boolean() ? model::dbpos::on : model::dbpos::off);
  }
  if (n.value.type() == ctl_val.type()) return ctl_val;
  return std::nullopt;
}

const char* action_name(srv::control_action a) {
  switch (a) {
    case srv::control_action::select: return "select";
    case srv::control_action::operate: return "operate";
    case srv::control_action::cancel: return "cancel";
  }
  return "?";
}

}  // namespace

int main(int argc, char** argv) {
  const tools::arguments args(argc, argv,
                              {"scl", "ied", "ap", "port", "bind", "password", "period", "control-delay",
                               "tls-ca", "tls-cert", "tls-key", "tls-crl", "tls-peer-name"});
  if (args.flag("help")) {
    std::fputs(usage_text, stdout);
    return 0;
  }
  if (auto u = args.unknown({"scl", "ied", "ap", "port", "bind", "password", "period", "control-delay",
                             "simulate", "verbose", "tls", "tls-ca", "tls-cert", "tls-key", "tls-crl",
                             "tls-peer-name", "tls-no-verify"})) {
    std::fprintf(stderr, "openiec61850-server: unknown option --%s\n%s", u->c_str(), usage_text);
    return 2;
  }
  if (auto m = args.missing_value()) {
    std::fprintf(stderr, "openiec61850-server: --%s needs a value\n", m->c_str());
    return 2;
  }
  const auto scl = args.value("scl");
  if (!scl || !args.positional().empty()) {
    std::fputs(usage_text, stderr);
    return 2;
  }
  verbose = args.flag("verbose");
  const auto port = tools::parse_number(args.value("port").value_or("102"), 0, 65535);
  const auto period = tools::parse_number(args.value("period").value_or("1000"), 10, 3600000);
  const auto delay = tools::parse_number(args.value("control-delay").value_or("0"), 0, 3600000);
  if (!port || !period || !delay) {
    std::fputs("openiec61850-server: invalid --port, --period or --control-delay\n", stderr);
    return 2;
  }
  std::error_code ec;
  const auto address = asio::ip::make_address(args.value("bind").value_or("0.0.0.0"), ec);
  if (ec) {
    std::fprintf(stderr, "openiec61850-server: invalid --bind address: %s\n", ec.message().c_str());
    return 2;
  }

  openiec61850::scl::diagnostics diags;
  auto data_model = srv::load_model_file(*scl, args.value("ied").value_or(""),
                                         args.value("ap").value_or(""), {}, &diags);
  for (const auto& d : diags) {
    if (verbose || d.level == openiec61850::scl::severity::error) {
      std::fprintf(stderr, "%s: %s\n", scl->c_str(), openiec61850::scl::to_string(d).c_str());
    }
  }
  if (!data_model) {
    std::fprintf(stderr, "openiec61850-server: cannot load %s: %s\n", scl->c_str(),
                 data_model.error().message().c_str());
    return 1;
  }

  asio::io_context ctx(1);
  std::optional<srv::server> server;
  const std::chrono::milliseconds control_delay{*delay};

  srv::server_options opts;
  opts.max_associations = 32;
  auto tls = tools::tls_from_arguments(args, true);
  if (!tls) {
    std::fprintf(stderr, "openiec61850-server: TLS configuration: %s\n", tls.error().message().c_str());
    return 2;
  }
  opts.association.transport.tls = std::move(*tls);
  opts.association.authorize = [pw = args.value("password")](
                                   const openiec61850::association::association_request& req,
                                   mms::initiate_response&) {
    const auto peer = req.remote_endpoint.address().to_string() + ":" +
                      std::to_string(req.remote_endpoint.port());
    if (pw && req.password != pw) {
      log("association from " + peer + " refused: authentication failure");
      return openiec61850::association::association_decision::rejected(
          openiec61850::iso::acse::service_user_diagnostic::authentication_failure);
    }
    log("association from " + peer + " accepted");
    return openiec61850::association::association_decision::accepted();
  };
  opts.on_write = [](const srv::write_event& w) -> std::optional<mms::data_access_error> {
    log("[" + std::to_string(w.association) + "] write " + w.reference.to_string() + " = " +
        tools::format_value(w.value));
    return std::nullopt;
  };
  opts.on_control = [&](const srv::control_request& r) -> srv::control_result {
    log("[" + std::to_string(r.association) + "] " + action_name(r.action) + " " +
        r.object.to_string() + " ctlVal=" + (r.ctl_val.valid() ? tools::format_value(r.ctl_val) : "-") +
        " ctlNum=" + std::to_string(r.ctl_num));
    if (r.action != srv::control_action::operate || !server) return srv::control_result::ok();
    auto st = make_ref(std::string(r.object.text()) + ".stVal[ST]");
    std::optional<mms::data> value;
    if (st) value = mirrored(server->model(), *st, r.ctl_val);
    auto apply = [srv_ptr = &*server, st, value] {
      if (st && value) {
        if (auto u = srv_ptr->update(*st, *value); !u) {
          log("stVal update of " + st->to_string() + " failed: " + u.error().message());
        }
      }
    };
    if (control_delay.count() == 0) {
      apply();
      return srv::control_result::ok();
    }
    auto timer = std::make_shared<asio::steady_timer>(server->get_executor(), control_delay);
    timer->async_wait([timer, apply, completion = r.completion](std::error_code e) {
      if (e) return;
      apply();
      completion.complete(srv::control_result::ok());
    });
    return srv::control_result::pending();
  };

  const auto lds = data_model->logical_devices().size();
  auto started = srv::server::start(ctx.get_executor(), std::move(*data_model),
                                    asio::ip::tcp::endpoint(address, static_cast<std::uint16_t>(*port)),
                                    std::move(opts));
  if (!started) {
    std::fprintf(stderr, "openiec61850-server: cannot listen on %s:%lld: %s\n",
                 address.to_string().c_str(), *port, started.error().message().c_str());
    return 1;
  }
  server.emplace(std::move(*started));
  const auto& ep = server->local_endpoint();
  std::printf("listening on %s:%u (%zu logical devices)\n", ep.address().to_string().c_str(),
              static_cast<unsigned>(ep.port()), lds);
  std::fflush(stdout);

  asio::steady_timer sim_timer(ctx);
  simulation sim;
  if (args.flag("simulate")) {
    sim = find_simulated(server->model());
    log("simulating " + std::to_string(sim.analogs.size()) + " analog values and " +
        std::to_string(sim.toggles.size()) + " indications");
    asio::co_spawn(
        ctx,
        [&]() -> asio::awaitable<void> {
          for (std::uint64_t tick = 1;; ++tick) {
            sim_timer.expires_after(std::chrono::milliseconds{*period});
            std::error_code e;
            co_await sim_timer.async_wait(asio::redirect_error(asio::use_awaitable, e));
            if (e) co_return;
            simulate_step(*server, sim, tick);
          }
        },
        asio::detached);
  }

  asio::signal_set signals(ctx, SIGINT, SIGTERM);
  signals.async_wait([&](std::error_code e, int sig) {
    if (e) return;
    std::fprintf(stderr, "openiec61850-server: signal %d, stopping\n", sig);
    sim_timer.cancel();
    server->stop();
  });
  asio::co_spawn(
      ctx,
      [&]() -> asio::awaitable<void> {
        co_await server->wait_stopped();
        signals.cancel();
        sim_timer.cancel();
      },
      asio::detached);
  ctx.run();
  return 0;
}
