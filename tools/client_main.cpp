// openiec61850-client: explores an IEC 61850 server from the command line (interop debugging).

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <optional>
#include <string>
#include <vector>

#include <asio/co_spawn.hpp>
#include <asio/io_context.hpp>
#include <asio/redirect_error.hpp>
#include <asio/signal_set.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include "openiec61850/model/basic_type.hpp"
#include "common.hpp"
#include "openiec61850/client/client.hpp"
#include "openiec61850/model/enums.hpp"
#include "openiec61850/model/functional_constraint.hpp"
#include "openiec61850/model/object_reference.hpp"

namespace {

namespace client = openiec61850::client;
namespace model = openiec61850::model;
namespace mms = openiec61850::mms;
namespace tools = openiec61850::tools;
using asio::awaitable;

constexpr const char* usage_text =
    "usage: openiec61850-client [options] COMMAND [ARGS]\n"
    "\n"
    "Commands:\n"
    "  discover              print the server's model (LDs, LNs, DOs/DAs with FC and type,\n"
    "                        data sets, report control blocks)\n"
    "  read REF              read a functionally constrained reference, e.g. LD/LN.DO.stVal[ST]\n"
    "  write REF VALUE       write VALUE (read first to learn the type)\n"
    "  reports RCB           enable the RCB (LD/LN.name[RP] or [BR]) with GI and print reports\n"
    "  operate REF VALUE     operate the controllable data object REF (LD/LN.DO) per its ctlModel\n"
    "\n"
    "Options:\n"
    "  --host HOST           server address (default 127.0.0.1)\n"
    "  --port N              server port (default 102)\n"
    "  --password PW         ACSE password authentication\n"
    "  --tls                 use TLS (IEC 62351-3); the port stays --port, usually 3782\n"
    "  --tls-ca FILE         trust anchors (PEM)\n"
    "  --tls-cert FILE       own certificate chain (PEM)\n"
    "  --tls-key FILE        own private key (PEM)\n"
    "  --tls-crl FILE        certificate revocation lists (PEM)\n"
    "  --tls-peer-name NAME  name the peer certificate must carry\n"
    "  --tls-no-verify       accept any peer certificate\n"
    "  --timeout S           connect / request timeout in seconds (default 10)\n"
    "  --count N             reports: stop after N reports (default: until SIGINT)\n"
    "  --duration S          reports: stop after S seconds\n"
    "  --test                operate: set the Test flag\n"
    "  --help                this text\n"
    "\n"
    "Values: true/false, integers, floats, strings, bit strings as 0/1 digits (bit 0 first),\n"
    "octet strings as hex. Exit status: 0 success, 1 service failure, 2 usage error.\n";

struct options {
  client::client_options client;
  std::optional<std::size_t> count;
  std::optional<std::chrono::seconds> duration;
  bool test = false;
};

std::optional<model::object_reference> parse_ref(const std::string& text) {
  auto r = model::object_reference::parse(text, model::parse_options{model::name_limits::unlimited(), false});
  if (!r) {
    std::fprintf(stderr, "invalid reference \"%s\": %s\n", text.c_str(), r.error().message().c_str());
    return std::nullopt;
  }
  return std::move(*r);
}

int fail(const std::string& what, const std::error_code& ec) {
  std::fprintf(stderr, "%s: %s\n", what.c_str(), ec.message().c_str());
  return 1;
}

std::string mms_type_name(mms::data_type t) {
  switch (t) {
    case mms::data_type::array: return "array";
    case mms::data_type::structure: return "struct";
    case mms::data_type::boolean: return "boolean";
    case mms::data_type::bit_string: return "bit-string";
    case mms::data_type::integer: return "integer";
    case mms::data_type::unsigned_: return "unsigned";
    case mms::data_type::floating_point: return "float";
    case mms::data_type::octet_string: return "octet-string";
    case mms::data_type::visible_string: return "visible-string";
    case mms::data_type::generalized_time: return "generalized-time";
    case mms::data_type::binary_time: return "binary-time";
    case mms::data_type::bcd: return "bcd";
    case mms::data_type::boolean_array: return "boolean-array";
    case mms::data_type::obj_id: return "objId";
    case mms::data_type::mms_string: return "mms-string";
    case mms::data_type::utc_time: return "utc-time";
    case mms::data_type::invalid: break;
  }
  return "?";
}

void print_definition(const client::data_definition& d, int depth) {
  std::string line(static_cast<std::size_t>(depth) * 2, ' ');
  line += d.name;
  if (d.fc) line += " [" + std::string(model::to_string(*d.fc)) + "]";
  if (d.type == client::data_definition::kind::basic) {
    line += " : ";
    line += d.basic_type ? std::string(model::to_string(*d.basic_type)) : mms_type_name(d.mms_type);
    if (d.size != 0 && (d.mms_type == mms::data_type::visible_string ||
                        d.mms_type == mms::data_type::octet_string ||
                        d.mms_type == mms::data_type::mms_string ||
                        d.mms_type == mms::data_type::bit_string)) {
      line += "(" + std::to_string(d.size) + ")";
    }
  } else if (d.type == client::data_definition::kind::array) {
    line += " : array[" + std::to_string(d.array_size) + "]";
  }
  std::printf("%s\n", line.c_str());
  const auto& kids = d.children;
  if (d.type == client::data_definition::kind::array) {
    if (!kids.empty() && kids.front().type != client::data_definition::kind::basic) {
      for (const auto& k : kids.front().children) print_definition(k, depth + 1);
    }
    return;
  }
  for (const auto& k : kids) print_definition(k, depth + 1);
}

awaitable<int> discover(client::client& c) {
  auto lds = co_await c.get_server_directory();
  if (!lds) co_return fail("GetServerDirectory", lds.error());
  int status = 0;
  for (const auto& ld : *lds) {
    std::printf("LD %s\n", ld.c_str());
    auto lns = co_await c.get_logical_device_directory(ld);
    if (!lns) {
      status = fail("GetLogicalDeviceDirectory(" + ld + ")", lns.error());
      continue;
    }
    for (const auto& ln : *lns) {
      std::printf("  LN %s\n", ln.c_str());
      auto ln_ref = model::object_reference::parse(ld + "/" + ln);
      if (!ln_ref) continue;
      auto dos = co_await c.get_data_directory(*ln_ref);
      if (!dos) {
        status = fail("GetDataDirectory(" + ln_ref->to_string() + ")", dos.error());
        continue;
      }
      auto dir = co_await c.get_logical_node_directory(*ln_ref);
      for (const auto& e : *dos) {
        if (dir && (std::find(dir->brcbs.begin(), dir->brcbs.end(), e.name) != dir->brcbs.end() ||
                    std::find(dir->urcbs.begin(), dir->urcbs.end(), e.name) != dir->urcbs.end())) {
          continue;  // listed below
        }
        auto do_ref = model::object_reference::parse(ln_ref->to_string() + "." + e.name);
        if (!do_ref) continue;
        auto def = co_await c.get_data_definition(*do_ref);
        if (!def) {
          status = fail("GetDataDefinition(" + do_ref->to_string() + ")", def.error());
          continue;
        }
        def->name = "DO " + def->name;
        print_definition(*def, 2);
      }
      if (!dir) {
        status = fail("GetLogicalNodeDirectory(" + ln_ref->to_string() + ")", dir.error());
        continue;
      }
      for (const auto& ds : dir->data_sets) {
        std::printf("    DataSet %s\n", ds.c_str());
        auto ds_ref = model::object_reference::parse(ln_ref->to_string() + "." + ds);
        if (!ds_ref) continue;
        auto members = co_await c.get_data_set_directory(*ds_ref);
        if (!members) {
          std::printf("      (directory: %s)\n", members.error().message().c_str());
          continue;
        }
        for (const auto& m : members->members) std::printf("      %s\n", m.to_string().c_str());
      }
      for (const auto& [names, fc] : {std::pair{&dir->brcbs, "BR"}, std::pair{&dir->urcbs, "RP"}}) {
        for (const auto& n : *names) {
          std::string line = "    " + std::string(fc) + " " + n;
          if (auto r = model::object_reference::parse(ln_ref->to_string() + "." + n + "[" + fc + "]")) {
            if (auto v = co_await c.get_rcb_values(*r)) {
              line += "  RptID=\"" + v->rpt_id.value_or("") + "\" DatSet=\"" +
                      v->dat_set.value_or("") + "\" RptEna=" +
                      (v->rpt_ena.value_or(false) ? "true" : "false");
            }
          }
          std::printf("%s\n", line.c_str());
        }
      }
      for (const auto& n : dir->lcbs) std::printf("    LG %s\n", n.c_str());
      for (const auto& n : dir->gocbs) std::printf("    GO %s\n", n.c_str());
    }
  }
  co_return status;
}

awaitable<int> read(client::client& c, const model::object_reference& ref) {
  auto v = co_await c.read(ref);
  if (!v) co_return fail("read " + ref.to_string(), v.error());
  std::printf("%s = %s\n", ref.to_string().c_str(), tools::format_value(*v).c_str());
  co_return 0;
}

awaitable<int> write(client::client& c, const model::object_reference& ref, const std::string& text) {
  auto current = co_await c.read(ref);
  if (!current) co_return fail("read " + ref.to_string() + " (for its type)", current.error());
  auto value = tools::parse_value_like(text, *current);
  if (!value) co_return fail("value \"" + text + "\"", value.error());
  auto w = co_await c.write(ref, *value);
  if (!w) co_return fail("write " + ref.to_string(), w.error());
  std::printf("%s := %s\n", ref.to_string().c_str(), tools::format_value(*value).c_str());
  co_return 0;
}

void print_report(const client::report& r) {
  std::string head = "report RptID=\"" + r.rpt_id + "\"";
  if (r.seq_num) head += " SqNum=" + std::to_string(*r.seq_num);
  if (r.data_set) head += " DatSet=\"" + *r.data_set + "\"";
  std::printf("%s\n", head.c_str());
  for (const auto& e : r.entries) {
    std::string name = !e.data_reference.empty() ? e.data_reference
                       : e.reference          ? e.reference->to_string()
                                              : "#" + std::to_string(e.index);
    std::string reason;
    if (e.reason) {
      const auto& t = *e.reason;
      if (t.data_change()) reason += " dchg";
      if (t.quality_change()) reason += " qchg";
      if (t.data_update()) reason += " dupd";
      if (t.integrity()) reason += " integrity";
      if (t.general_interrogation()) reason += " GI";
    }
    std::printf("  %s = %s%s%s\n", name.c_str(), tools::format_value(e.value).c_str(),
                reason.empty() ? "" : "  reason:", reason.c_str());
  }
  std::fflush(stdout);
}

awaitable<int> reports(client::client& c, const model::object_reference& rcb, const options& o) {
  client::report_settings s;
  s.general_interrogation = true;
  s.opt_flds = model::optional_fields::of(
      {model::optional_field::sequence_number, model::optional_field::reason_for_inclusion,
       model::optional_field::data_set_name, model::optional_field::data_reference});
  auto en = co_await c.enable_reporting(rcb, s);
  if (!en) co_return fail("enable_reporting " + rcb.to_string(), en.error());
  std::printf("enabled %s (RptID \"%s\", DatSet \"%s\")\n", rcb.to_string().c_str(),
              en->rpt_id.value_or("").c_str(), en->dat_set.value_or("").c_str());
  std::fflush(stdout);

  auto ex = co_await asio::this_coro::executor;
  bool stop = false;
  std::size_t received = 0;
  std::vector<client::report> queue;
  asio::steady_timer wake(ex);
  asio::signal_set signals(ex, SIGINT, SIGTERM);
  signals.async_wait([&](std::error_code e, int) {
    if (e) return;
    stop = true;
    wake.cancel();
  });
  c.set_report_handler([&](client::report r) {
    queue.push_back(std::move(r));
    wake.cancel();
  });
  using clock = std::chrono::steady_clock;
  const auto end = o.duration ? clock::now() + *o.duration : clock::time_point::max();
  while (!stop && (!o.count || received < *o.count) && clock::now() < end &&
         c.state() != client::connection_state::closed) {
    if (queue.empty()) {
      auto next = clock::now() + std::chrono::seconds(1);
      wake.expires_at(next < end ? next : end);
      std::error_code e;
      co_await wake.async_wait(asio::redirect_error(asio::use_awaitable, e));
    }
    for (auto& r : queue) {
      if (o.count && received >= *o.count) break;
      print_report(r);
      ++received;
    }
    queue.clear();
  }
  c.set_report_handler({});
  signals.cancel();
  auto dis = co_await c.disable_reporting(rcb);
  if (!dis) co_return fail("disable_reporting " + rcb.to_string(), dis.error());
  std::printf("%zu report(s) received\n", received);
  co_return (o.count && received < *o.count) ? 1 : 0;
}

awaitable<int> operate(client::client& c, const model::object_reference& obj, const std::string& text,
                       const options& o) {
  auto h = co_await c.get_control(obj);
  if (!h) co_return fail("get_control " + obj.to_string(), h.error());
  std::optional<mms::data_type> type = h->ctl_val_type();
  std::size_t bits = 0;
  if (const auto& st = h->structure()) {
    for (const auto& comp : st->components) {
      if (comp.name != "Oper") continue;
      for (const auto& f : comp.type.components) {
        if (f.name == "ctlVal" && f.type.type == mms::data_type::bit_string) {
          bits = static_cast<std::size_t>(f.type.size < 0 ? -f.type.size : f.type.size);
        }
      }
    }
  }
  auto value = tools::parse_value(text, type.value_or(mms::data_type::boolean), bits);
  if (!value) co_return fail("value \"" + text + "\"", value.error());
  client::control_options co;
  co.test = o.test;
  // The control model decides the sequence (7-2 §20): Select (SBO read) or SelectWithValue
  // (SBOw write) before Operate.
  openiec61850::result<void> r;
  if (h->ctl_model() == model::ctl_model::sbo_with_normal_security) {
    r = co_await h->select(co);
  } else if (h->ctl_model() == model::ctl_model::sbo_with_enhanced_security) {
    r = co_await h->select_with_value(*value, co);
  }
  if (r) r = co_await h->operate(*value, co);
  if (!r) {
    std::string what = "operate " + obj.to_string();
    if (auto le = h->last_error()) {
      what += " (LastApplError AddCause " + std::string(client::to_string(le->cause)) + ")";
    }
    co_return fail(what, r.error());
  }
  std::printf("%s operated with %s (ctlModel %d)\n", obj.to_string().c_str(),
              tools::format_value(*value).c_str(), static_cast<int>(h->ctl_model()));
  co_return 0;
}

awaitable<int> run(const std::vector<std::string>& cmd, const options& o) {
  auto c = co_await client::client::connect(co_await asio::this_coro::executor, o.client);
  if (!c) co_return fail("connect to " + o.client.association.host + ":" +
                             std::to_string(o.client.association.port),
                         c.error());
  int status = 2;
  const auto& name = cmd[0];
  if (name == "discover" && cmd.size() == 1) {
    status = co_await discover(*c);
  } else if (name == "read" && cmd.size() == 2) {
    if (auto r = parse_ref(cmd[1])) status = co_await read(*c, *r);
  } else if (name == "write" && cmd.size() == 3) {
    if (auto r = parse_ref(cmd[1])) status = co_await write(*c, *r, cmd[2]);
  } else if (name == "reports" && cmd.size() == 2) {
    if (auto r = parse_ref(cmd[1])) status = co_await reports(*c, *r, o);
  } else if (name == "operate" && cmd.size() == 3) {
    if (auto r = parse_ref(cmd[1])) status = co_await operate(*c, *r, cmd[2], o);
  }
  auto rel = co_await c->release();
  if (!rel && status == 0) status = fail("release", rel.error());
  co_return status;
}

}  // namespace

int main(int argc, char** argv) {
  const tools::arguments args(argc, argv,
                              {"host", "port", "password", "timeout", "count", "duration", "tls-ca",
                               "tls-cert", "tls-key", "tls-crl", "tls-peer-name"});
  if (args.flag("help")) {
    std::fputs(usage_text, stdout);
    return 0;
  }
  if (auto u = args.unknown({"host", "port", "password", "timeout", "count", "duration", "test", "tls",
                             "tls-ca", "tls-cert", "tls-key", "tls-crl", "tls-peer-name", "tls-no-verify"})) {
    std::fprintf(stderr, "openiec61850-client: unknown option --%s\n%s", u->c_str(), usage_text);
    return 2;
  }
  const auto& cmd = args.positional();
  static const std::vector<std::pair<std::string, std::size_t>> commands{
      {"discover", 1}, {"read", 2}, {"write", 3}, {"reports", 2}, {"operate", 3}};
  const bool known = !cmd.empty() && std::any_of(commands.begin(), commands.end(), [&](const auto& c) {
    return c.first == cmd[0] && c.second == cmd.size();
  });
  const auto port = tools::parse_number(args.value("port").value_or("102"), 1, 65535);
  const auto timeout = tools::parse_number(args.value("timeout").value_or("10"), 1, 3600);
  if (!known || args.missing_value() || !port || !timeout) {
    std::fputs(usage_text, stderr);
    return 2;
  }
  options o;
  auto& a = o.client.association;
  a.host = args.value("host").value_or("127.0.0.1");
  a.port = static_cast<std::uint16_t>(*port);
  a.password = args.value("password");
  auto tls = tools::tls_from_arguments(args, false);
  if (!tls) {
    std::fprintf(stderr, "openiec61850-client: TLS configuration: %s\n", tls.error().message().c_str());
    return 2;
  }
  a.transport.tls = std::move(*tls);
  const std::chrono::seconds t{*timeout};
  a.transport.connect_timeout = t;
  a.transport.handshake_timeout = t;
  a.association_timeout = t;
  a.request_timeout = t;
  if (auto n = args.value("count")) {
    auto v = tools::parse_number(*n, 1, 1000000);
    if (!v) return 2;
    o.count = static_cast<std::size_t>(*v);
  }
  if (auto d = args.value("duration")) {
    auto v = tools::parse_number(*d, 1, 86400);
    if (!v) return 2;
    o.duration = std::chrono::seconds{*v};
  }
  o.test = args.flag("test");

  asio::io_context ctx(1);
  int status = 1;
  asio::co_spawn(
      ctx, [&]() -> awaitable<void> { status = co_await run(cmd, o); },
      [&](std::exception_ptr e) {
        if (!e) return;
        try {
          std::rethrow_exception(e);
        } catch (const std::exception& ex) {
          std::fprintf(stderr, "openiec61850-client: %s\n", ex.what());
        }
        status = 1;
      });
  ctx.run();
  return status;
}
