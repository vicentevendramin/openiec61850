// Interoperability runner (ADR 0007): drives an independent IEC 61850 server with the openiec61850
// C++ client and prints a PASS/WARN/SKIP/FAIL summary. It knows nothing about the server's model:
// everything it touches is found through the directory services first.
//
//   openiec61850_interop [--timeout SECONDS] [--no-control] [--expect-dchg] [--bean-defects]
//                        HOST[:PORT] [HOST[:PORT]...]
//
// Checks, per server:
//   connect    association established (ACSE/MMS Initiate)
//   discover   GetServerDirectory, GetLogicalDeviceDirectory, GetLogicalNodeDirectory and
//              GetDataDirectory of every LD/LN; GetDataDefinition of one data object
//   read       Read of the first data objects found under ST/MX (one Read, then a read_many)
//   write      Write-back of a value just read under CF/DC/SP (WARN when every candidate is
//              refused with a proper negative response: allowed by 7-2, but nothing was written)
//   data-set   GetDataSetDirectory and GetDataSetValues of the first data set; a dynamic data set
//              created, read back and deleted (WARN when the creation is refused)
//   report     enable_reporting(GI) on the first URCB (else BRCB), wait for a report, disable
//   report/brcb  the same on the first BRCB when the model has both, with EntryID
//   report/dchg  with --expect-dchg: a report with reason data-change; something else has to change
//              a member of the data set of the first RCB meanwhile
//   control/*  operate() on the first BOOLEAN-controlled object of each control model found
//              (direct / SBO, normal / enhanced security), toggling stVal and restoring it
//   release    orderly Conclude + A-RELEASE
// SKIP: the model has nothing to exercise (no RCB, no controllable object). Exit status 0 when
// nothing FAILed, 1 otherwise, 2 on usage errors.
//
// --bean-defects: the target is IEC61850bean, whose defects (interop/iec61850bean/README.md) are
// each asserted to still be there: WARN while the peer shows it, FAIL once it stops, so that a new
// release cannot leave a stale entry. Nothing here relaxes what the client accepts. Reports are
// requested without data-reference, because bean's are undecodable with it; that case is its own
// check, report/data-reference.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <asio/co_spawn.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include "openiec61850/client/client.hpp"
#include "openiec61850/client/values.hpp"
#include "openiec61850/model/enums.hpp"
#include "openiec61850/model/functional_constraint.hpp"
#include "openiec61850/model/object_reference.hpp"

namespace {

namespace client = openiec61850::client;
namespace mms = openiec61850::mms;
namespace model = openiec61850::model;
using asio::awaitable;
using model::functional_constraint;
using namespace std::chrono_literals;

enum class status : std::uint8_t { pass, warn, skip, fail };

std::string_view label(status s) {
  switch (s) {
    case status::pass: return "PASS";
    case status::warn: return "WARN";
    case status::skip: return "SKIP";
    case status::fail: return "FAIL";
  }
  return "?";
}

struct outcome {
  std::string target;
  std::string check;
  status result = status::fail;
  std::string detail;
};

struct settings {
  std::chrono::seconds timeout{5};
  bool control = true;
  bool expect_dchg = false;
  bool bean_defects = false;
};

struct target {
  std::string host;
  std::uint16_t port = 102;
  [[nodiscard]] std::string name() const { return host + ":" + std::to_string(port); }
};

// What discovery found, as references the later checks use.
struct model_summary {
  std::size_t lds = 0;
  std::size_t lns = 0;
  std::size_t data_objects = 0;
  std::vector<model::object_reference> readable;     // "LD/LN.DO[ST|MX]"
  std::vector<model::object_reference> writable;     // "LD/LN.DO[CF|DC|SP]"
  std::vector<model::object_reference> controllable;  // "LD/LN.DO" with a CO component
  std::optional<model::object_reference> urcb;       // "LD/LN.name[RP]"
  std::optional<model::object_reference> brcb;       // "LD/LN.name[BR]"
  std::vector<model::object_reference> urcbs;        // every URCB, in discovery order
  std::optional<model::object_reference> data_set;   // "LD/LN.name"
  std::string first_ln;                              // "LD/LN"
};

// What one enable / wait / disable cycle on an RCB gave.
struct report_cycle {
  std::vector<client::report> received;
  std::uint64_t dropped = 0;  // reports the client refused meanwhile
  std::optional<std::string> enable_error;
  std::optional<std::string> disable_error;
};

std::optional<model::object_reference> parse_ref(const std::string& text) {
  auto r = model::object_reference::parse(text);
  if (!r) return std::nullopt;
  return std::move(*r);
}

std::string with_fc(const std::string& base, functional_constraint fc) {
  return base + "[" + std::string(model::to_string(fc)) + "]";
}

bool bool_value(const mms::data& d) {
  auto b = client::to_bool(d);
  return b && *b;
}

bool has_fc(const client::data_directory_entry& e, functional_constraint fc) {
  return std::find(e.fcs.begin(), e.fcs.end(), fc) != e.fcs.end();
}

class runner {
 public:
  runner(target t, settings s) : target_(std::move(t)), settings_(s) {}

  awaitable<std::vector<outcome>> run() {
    client::client_options o;
    o.association.host = target_.host;
    o.association.port = target_.port;
    o.association.transport.connect_timeout = settings_.timeout;
    o.association.transport.handshake_timeout = settings_.timeout;
    o.association.association_timeout = settings_.timeout;
    o.association.request_timeout = settings_.timeout;
    o.association.release_timeout = settings_.timeout;
    auto c = co_await client::client::connect(co_await asio::this_coro::executor, o);
    if (!c) {
      record("connect", status::fail, c.error().message());
      co_return std::move(outcomes_);
    }
    record("connect", status::pass, "association established");

    model_summary m;
    co_await discover(*c, m);
    co_await read(*c, m);
    co_await write(*c, m);
    co_await data_set(*c, m);
    co_await report(*c, m);
    if (settings_.control) {
      co_await control(*c, m);
    } else {
      record("control", status::skip, "disabled with --no-control");
    }

    auto rel = co_await c->release();
    if (settings_.bean_defects) {
      known_defect("release", !rel, "no answer to a Conclude-RequestPDU",
                   rel ? "released" : rel.error().message());
    } else {
      record("release", rel ? status::pass : status::fail, rel ? "released" : rel.error().message());
    }
    co_return std::move(outcomes_);
  }

 private:
  void record(std::string check, status s, std::string detail) {
    std::printf("[%s] %-24s %-4s %s\n", target_.name().c_str(), check.c_str(),
                std::string(label(s)).c_str(), detail.c_str());
    std::fflush(stdout);
    outcomes_.push_back({target_.name(), std::move(check), s, std::move(detail)});
  }

  // `present`: the defect showed up. A defect that stopped reproducing is a FAIL, not a PASS: the
  // entry in interop/iec61850bean/README.md and this expectation have to go.
  void known_defect(std::string check, bool present, const std::string& defect, const std::string& detail) {
    if (present) {
      record(std::move(check), status::warn, "known peer defect, " + defect + " (" + detail + ")");
    } else {
      record(std::move(check), status::fail, "known peer defect no longer reproduces: " + defect);
    }
  }

  awaitable<void> discover(client::client& c, model_summary& m) {
    auto lds = co_await c.get_server_directory();
    if (!lds || lds->empty()) {
      record("discover", status::fail,
             lds ? "GetServerDirectory returned no logical device" : lds.error().message());
      co_return;
    }
    m.lds = lds->size();
    for (const auto& ld : *lds) {
      auto lns = co_await c.get_logical_device_directory(ld);
      if (!lns) {
        record("discover", status::fail, "GetLogicalDeviceDirectory(" + ld + "): " + lns.error().message());
        co_return;
      }
      for (const auto& ln : *lns) {
        ++m.lns;
        const std::string ln_text = ld + "/" + ln;
        if (m.first_ln.empty()) m.first_ln = ln_text;
        auto ln_ref = parse_ref(ln_text);
        if (!ln_ref) continue;  // a name our parser refuses; not this runner's concern
        auto dir = co_await c.get_logical_node_directory(*ln_ref);
        if (!dir) {
          record("discover", status::fail, "GetLogicalNodeDirectory(" + ln_text + "): " + dir.error().message());
          co_return;
        }
        if (!m.urcb && !dir->urcbs.empty()) m.urcb = parse_ref(ln_text + "." + dir->urcbs.front() + "[RP]");
        for (const auto& name : dir->urcbs) {
          if (auto r = parse_ref(ln_text + "." + name + "[RP]")) m.urcbs.push_back(*r);
        }
        if (!m.brcb && !dir->brcbs.empty()) m.brcb = parse_ref(ln_text + "." + dir->brcbs.front() + "[BR]");
        if (!m.data_set && !dir->data_sets.empty()) m.data_set = parse_ref(ln_text + "." + dir->data_sets.front());

        auto dos = co_await c.get_data_directory(*ln_ref);
        if (!dos) {
          record("discover", status::fail, "GetDataDirectory(" + ln_text + "): " + dos.error().message());
          co_return;
        }
        m.data_objects += dos->size();
        for (const auto& e : *dos) {
          const std::string base = ln_text + "." + e.name;
          for (auto fc : {functional_constraint::ST, functional_constraint::MX}) {
            if (has_fc(e, fc)) {
              if (auto r = parse_ref(with_fc(base, fc))) m.readable.push_back(*r);
            }
          }
          for (auto fc : {functional_constraint::CF, functional_constraint::DC, functional_constraint::SP}) {
            if (has_fc(e, fc)) {
              if (auto r = parse_ref(with_fc(base, fc))) m.writable.push_back(*r);
            }
          }
          if (has_fc(e, functional_constraint::CO)) {
            if (auto r = parse_ref(base)) m.controllable.push_back(*r);
          }
        }
      }
    }
    if (m.readable.empty()) {
      record("discover", status::fail, "no data object under ST or MX");
      co_return;
    }
    auto def = co_await c.get_data_definition(m.readable.front());
    if (!def) {
      record("discover", status::fail,
             "GetDataDefinition(" + m.readable.front().to_string() + "): " + def.error().message());
      co_return;
    }
    record("discover", status::pass,
           std::to_string(m.lds) + " LD, " + std::to_string(m.lns) + " LN, " +
               std::to_string(m.data_objects) + " DO, " + std::to_string(m.controllable.size()) +
               " controllable, URCB " + (m.urcb ? m.urcb->to_string() : "-") + ", BRCB " +
               (m.brcb ? m.brcb->to_string() : "-"));
  }

  awaitable<void> read(client::client& c, const model_summary& m) {
    if (m.readable.empty()) {
      record("read", status::skip, "nothing to read");
      co_return;
    }
    auto one = co_await c.read(m.readable.front());
    if (!one) {
      record("read", status::fail, m.readable.front().to_string() + ": " + one.error().message());
      co_return;
    }
    const auto count = std::min<std::size_t>(m.readable.size(), 16);
    std::vector<model::object_reference> refs(m.readable.begin(),
                                              m.readable.begin() + static_cast<std::ptrdiff_t>(count));
    auto many = co_await c.read_many(refs);
    if (!many) {
      record("read", status::fail, "read_many: " + many.error().message());
      co_return;
    }
    std::size_t ok = 0;
    for (const auto& r : *many) {
      if (r) ++ok;
    }
    record("read", ok == count ? status::pass : status::warn,
           std::to_string(ok) + "/" + std::to_string(count) + " values read in one Read request");
  }

  awaitable<void> write(client::client& c, const model_summary& m) {
    if (m.writable.empty()) {
      record("write", status::skip, "no data object under CF/DC/SP");
      co_return;
    }
    std::size_t refused = 0;
    std::string last_error;
    for (const auto& ref : m.writable) {
      auto v = co_await c.read(ref);
      if (!v) continue;
      auto w = co_await c.write(ref, *v);
      if (w) {
        record("write", status::pass, "wrote back " + ref.to_string());
        co_return;
      }
      ++refused;
      last_error = ref.to_string() + ": " + w.error().message();
      if (refused >= 8) break;
    }
    if (refused == 0) {
      record("write", status::skip, "no writable candidate could be read");
    } else {
      record("write", status::warn,
             std::to_string(refused) + " write(s) refused by the server (last " + last_error + ")");
    }
  }

  awaitable<void> data_set(client::client& c, const model_summary& m) {
    if (m.data_set) {
      auto dir = co_await c.get_data_set_directory(*m.data_set);
      if (!dir) {
        record("data-set", status::fail, "directory of " + m.data_set->to_string() + ": " + dir.error().message());
        co_return;
      }
      auto values = co_await c.get_data_set_values(*m.data_set);
      if (!values) {
        record("data-set", status::fail, "values of " + m.data_set->to_string() + ": " + values.error().message());
        co_return;
      }
      if (values->size() != dir->members.size()) {
        record("data-set", status::fail, m.data_set->to_string() + ": " + std::to_string(dir->members.size()) +
                                             " members but " + std::to_string(values->size()) + " values");
        co_return;
      }
      record("data-set", status::pass, m.data_set->to_string() + ": " + std::to_string(values->size()) + " members read");
    } else {
      record("data-set", status::skip, "no data set in the model");
    }

    const auto dyn = parse_ref(m.first_ln + ".openiecDyn");
    if (!dyn || m.readable.size() < 2) {
      record("data-set/dynamic", status::skip, "no place for a dynamic data set");
      co_return;
    }
    std::vector<model::object_reference> members(m.readable.begin(), m.readable.begin() + 2);
    auto created = co_await c.create_data_set(*dyn, members);
    if (!created) {
      record("data-set/dynamic", status::warn, "creation refused: " + created.error().message());
      co_return;
    }
    auto dir = co_await c.get_data_set_directory(*dyn);
    auto values = co_await c.get_data_set_values(*dyn);
    auto deleted = co_await c.delete_data_set(*dyn);
    auto after = co_await c.get_data_set_directory(*dyn);
    if (!dir || dir->members.size() != 2 || !dir->deletable) {
      record("data-set/dynamic", status::fail, "directory of the new data set is wrong");
    } else if (!values || values->size() != 2) {
      record("data-set/dynamic", status::fail, "values of the new data set are wrong");
    } else if (!deleted) {
      record("data-set/dynamic", status::fail, "delete: " + deleted.error().message());
    } else if (after) {
      record("data-set/dynamic", status::fail, "still there after the delete");
    } else {
      record("data-set/dynamic", status::pass, dyn->to_string() + " created, read and deleted");
    }
  }

  static model::optional_fields report_fields(bool buffered, bool data_reference) {
    auto f = model::optional_fields::of(
        {model::optional_field::sequence_number, model::optional_field::report_time_stamp,
         model::optional_field::reason_for_inclusion, model::optional_field::data_set_name,
         model::optional_field::conf_revision});
    if (data_reference) f.set(model::optional_field::data_reference, true);
    if (buffered) {
      f.set(model::optional_field::buffer_overflow, true);
      f.set(model::optional_field::entry_id, true);
    }
    return f;
  }

  // Enables `rcb`, waits until `enough` holds for what arrived (or the timeout) and disables it.
  template <typename Enough>
  awaitable<report_cycle> cycle(client::client& c, const model::object_reference& rcb,
                                const client::report_settings& s, Enough enough) {
    report_cycle out;
    const auto dropped_before = c.reports_dropped();
    asio::steady_timer wake(co_await asio::this_coro::executor);
    c.set_report_handler([&](client::report r) {
      out.received.push_back(std::move(r));
      wake.cancel();
    });
    auto en = co_await c.enable_reporting(rcb, s);
    if (!en) {
      c.set_report_handler({});
      out.enable_error = en.error().message();
      co_return out;
    }
    const auto deadline = std::chrono::steady_clock::now() + settings_.timeout;
    while (!enough(out.received) && std::chrono::steady_clock::now() < deadline) {
      wake.expires_at(deadline);
      try {
        co_await wake.async_wait(asio::use_awaitable);
      } catch (const std::exception&) {  // cancelled by the handler: a report arrived
      }
    }
    c.set_report_handler({});
    auto dis = co_await c.disable_reporting(rcb);
    if (!dis) out.disable_error = dis.error().message();
    out.dropped = c.reports_dropped() - dropped_before;
    co_return out;
  }

  static bool any_report(const std::vector<client::report>& received) { return !received.empty(); }

  static bool any_data_change(const std::vector<client::report>& received) {
    for (const auto& r : received) {
      for (const auto& e : r.entries) {
        if (e.reason && e.reason->data_change()) return true;
      }
    }
    return false;
  }

  awaitable<void> report_on(client::client& c, const model::object_reference& rcb, bool buffered,
                            std::string check) {
    client::report_settings s;
    s.general_interrogation = true;
    s.opt_flds = report_fields(buffered, !settings_.bean_defects);
    auto got = co_await cycle(c, rcb, s, any_report);
    if (got.enable_error) {
      record(check, status::fail, "enable_reporting(" + rcb.to_string() + "): " + *got.enable_error);
      co_return;
    }
    if (got.received.empty()) {
      record(check, status::fail, "no report within the timeout after GI on " + rcb.to_string() +
                                      " (" + std::to_string(got.dropped) + " refused by the client)");
      co_return;
    }
    const auto& r = got.received.front();
    std::string detail = rcb.to_string() + ": RptID \"" + r.rpt_id + "\", " +
                         std::to_string(r.entries.size()) + " entries";
    if (got.disable_error) detail += "; disable_reporting failed: " + *got.disable_error;
    bool complete = !r.entries.empty() && !got.disable_error;
    if (buffered && !r.entry_id) {
      detail += "; no EntryID";
      complete = false;
    }
    record(check, complete ? status::pass : status::warn, detail);
  }

  // bean sets OptFlds.data-reference in its reports without sending the references, so the client
  // has to refuse every one of them (8-1 report layout; the same request works on libiec61850).
  awaitable<void> report_data_reference(client::client& c, const model::object_reference& rcb, bool buffered) {
    client::report_settings s;
    s.opt_flds = report_fields(buffered, true);
    s.general_interrogation = true;
    auto got = co_await cycle(c, rcb, s, any_report);
    if (got.enable_error) {
      record("report/data-reference", status::fail, *got.enable_error);
      co_return;
    }
    known_defect("report/data-reference", got.received.empty() && got.dropped > 0,
                 "OptFlds.data-reference set but no references in the report",
                 std::to_string(got.dropped) + " refused by the client");
  }

  awaitable<void> report_dchg(client::client& c, const model::object_reference& rcb, bool buffered) {
    client::report_settings s;
    s.opt_flds = report_fields(buffered, !settings_.bean_defects);
    s.trg_ops = model::trigger_conditions::of({model::trigger::data_change});
    s.intg_pd = 0;
    auto got = co_await cycle(c, rcb, s, any_data_change);
    if (got.enable_error) {
      record("report/dchg", status::fail, "enable_reporting(" + rcb.to_string() + "): " + *got.enable_error);
    } else if (any_data_change(got.received)) {
      record("report/dchg", status::pass, rcb.to_string() + ": reason data-change received");
    } else {
      record("report/dchg", status::fail, std::to_string(got.received.size()) + " report(s), none for a data change");
    }
  }

  // bean accepts one write of OptFlds per RCB for as long as the server runs, even from another
  // association; the same frames work on libiec61850 and openiec61850-server.
  awaitable<void> report_opt_flds_rewrite(client::client& c, const model::object_reference& rcb) {
    client::report_settings s;
    s.opt_flds = report_fields(false, false);
    auto got = co_await cycle(c, rcb, s, any_report);
    known_defect("report/opt-flds-rewrite", got.enable_error.has_value(),
                 "second write of OptFlds refused", got.enable_error.value_or("accepted"));
  }

  // bean accepts RptEna and GI on a BRCB, then sends nothing: no GI and no integrity report.
  awaitable<void> report_brcb_silent(client::client& c, const model::object_reference& rcb) {
    client::report_settings s;
    s.general_interrogation = true;
    s.opt_flds = report_fields(true, false);
    auto got = co_await cycle(c, rcb, s, any_report);
    if (got.enable_error) {
      record("report/brcb", status::fail, "enable_reporting(" + rcb.to_string() + "): " + *got.enable_error);
      co_return;
    }
    known_defect("report/brcb", got.received.empty() && got.dropped == 0, "no report from a BRCB",
                 "nothing within " + std::to_string(settings_.timeout.count()) + " s of the GI");
  }

  awaitable<void> report(client::client& c, const model_summary& m) {
    const auto rcb = m.urcb ? m.urcb : m.brcb;
    if (!rcb) {
      record("report", status::skip, "no report control block");
      co_return;
    }
    const bool buffered = !m.urcb;
    co_await report_on(c, *rcb, buffered, "report");
    if (m.urcb && m.brcb) {
      if (settings_.bean_defects) {
        co_await report_brcb_silent(c, *m.brcb);
      } else {
        co_await report_on(c, *m.brcb, true, "report/brcb");
      }
    }
    // Each check takes its own URCB while there are any: see report_opt_flds_rewrite.
    std::size_t next = 1;
    const auto spare = [&]() -> const model::object_reference& {
      return next < m.urcbs.size() ? m.urcbs[next++] : *rcb;
    };
    if (settings_.expect_dchg) co_await report_dchg(c, spare(), buffered);
    if (settings_.bean_defects) {
      co_await report_data_reference(c, spare(), buffered);
      co_await report_opt_flds_rewrite(c, *rcb);
    }
  }

  // One operate() per control model found (the first BOOLEAN-controlled object of each), so
  // direct / SBO and normal / enhanced security are all exercised when the model has them.
  awaitable<void> control(client::client& c, const model_summary& m) {
    if (m.controllable.empty()) {
      record("control", status::skip, "no controllable data object");
      co_return;
    }
    constexpr std::size_t models = 5;
    bool tried[models] = {};
    for (const auto& obj : m.controllable) {
      auto h = co_await c.get_control(obj);
      if (!h) continue;
      const auto cm = h->ctl_model();
      const auto index = static_cast<std::size_t>(cm);
      if (cm == model::ctl_model::status_only || index >= models || tried[index]) continue;
      if (h->ctl_val_type() != mms::data_type::boolean) continue;
      tried[index] = true;
      const std::string check = "control/" + std::string(model_name(cm));

      auto st = parse_ref(obj.to_string() + ".stVal[ST]");
      bool current = false;
      if (st) {
        if (auto v = co_await c.read(*st)) current = bool_value(*v);
      }
      auto op = co_await c.operate(obj, mms::data::boolean(!current));
      const bool enhanced = cm == model::ctl_model::direct_with_enhanced_security ||
                            cm == model::ctl_model::sbo_with_enhanced_security;
      if (settings_.bean_defects && enhanced) {
        known_defect(check, !op, "enhanced security refused", op ? "operated" : op.error().message());
        continue;
      }
      if (!op) {
        record(check, status::fail, obj.to_string() + ": " + op.error().message());
        continue;
      }
      std::string detail = obj.to_string() + " operated";
      status s = status::pass;
      if (st) {
        auto after = co_await c.read(*st);
        if (after && bool_value(*after) == !current) {
          detail += ", stVal followed";
        } else {
          detail += ", stVal did not follow ctlVal";
          s = status::warn;
        }
      }
      if (!co_await c.operate(obj, mms::data::boolean(current))) detail += "; restore failed";
      record(check, s, detail);
    }
    if (std::none_of(std::begin(tried), std::end(tried), [](bool b) { return b; })) {
      record("control", status::skip, "no BOOLEAN-controlled object");
    }
  }

  static std::string_view model_name(model::ctl_model cm) {
    switch (cm) {
      case model::ctl_model::status_only: return "status-only";
      case model::ctl_model::direct_with_normal_security: return "direct-normal";
      case model::ctl_model::sbo_with_normal_security: return "sbo-normal";
      case model::ctl_model::direct_with_enhanced_security: return "direct-enhanced";
      case model::ctl_model::sbo_with_enhanced_security: return "sbo-enhanced";
    }
    return "unknown";
  }

  target target_;
  settings settings_;
  std::vector<outcome> outcomes_;
};

std::optional<target> parse_target(std::string_view arg) {
  target t;
  const auto colon = arg.rfind(':');
  if (colon == std::string_view::npos) {
    t.host = std::string(arg);
    return t;
  }
  t.host = std::string(arg.substr(0, colon));
  const auto port = std::string(arg.substr(colon + 1));
  char* end = nullptr;
  const long p = std::strtol(port.c_str(), &end, 10);
  if (t.host.empty() || end == port.c_str() || *end != '\0' || p <= 0 || p > 65535) return std::nullopt;
  t.port = static_cast<std::uint16_t>(p);
  return t;
}

int usage() {
  std::fprintf(stderr,
               "usage: openiec61850_interop [--timeout SECONDS] [--no-control] [--expect-dchg]\n"
               "                           [--bean-defects] HOST[:PORT]...\n");
  return 2;
}

}  // namespace

int main(int argc, char** argv) {
  settings s;
  std::vector<target> targets;
  for (int i = 1; i < argc; ++i) {
    const std::string_view a = argv[i];
    if (a == "--timeout" && i + 1 < argc) {
      const long v = std::strtol(argv[++i], nullptr, 10);
      if (v <= 0) return usage();
      s.timeout = std::chrono::seconds{v};
    } else if (a == "--no-control") {
      s.control = false;
    } else if (a == "--expect-dchg") {
      s.expect_dchg = true;
    } else if (a == "--bean-defects") {
      s.bean_defects = true;
    } else if (a == "-h" || a == "--help") {
      return usage();
    } else if (auto t = parse_target(a)) {
      targets.push_back(*t);
    } else {
      return usage();
    }
  }
  if (targets.empty()) return usage();

  std::vector<outcome> all;
  asio::io_context ctx;
  std::exception_ptr failure;
  asio::co_spawn(
      ctx,
      [&]() -> awaitable<void> {
        for (const auto& t : targets) {
          runner r(t, s);
          auto out = co_await r.run();
          all.insert(all.end(), out.begin(), out.end());
        }
      },
      [&](std::exception_ptr e) { failure = e; });
  ctx.run();
  if (failure) {
    try {
      std::rethrow_exception(failure);
    } catch (const std::exception& e) {
      std::fprintf(stderr, "runner aborted: %s\n", e.what());
    }
    return 1;
  }

  std::size_t counts[4] = {};
  for (const auto& o : all) ++counts[static_cast<std::size_t>(o.result)];
  std::printf("\nSummary: %zu PASS, %zu WARN, %zu SKIP, %zu FAIL\n", counts[0], counts[1],
              counts[2], counts[3]);
  return counts[3] == 0 ? 0 : 1;
}
