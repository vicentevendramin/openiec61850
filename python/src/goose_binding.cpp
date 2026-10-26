// _core GOOSE / SV classes (goose/*.hpp): links (loopback network, raw socket), the GOOSE and SV
// publishers, the receiver and its subscriptions. The pure Python layer
// (openiec61850/goose/__init__.py) builds the public API on top.
//
// Threading: links, publishers and receivers run on the shared I/O runtime (runtime.hpp).
// Subscriptions deliver their events through a pump (pump.hpp): the receiver strand hands each
// event to the pump without the GIL, and the pump schedules batches on the asyncio loop the
// subscription was created from. Every call into a native object that takes one of its mutexes
// releases the GIL first, so the I/O thread (which takes the GIL to schedule a batch or to call an
// SV sample source) can never wait for a thread that waits for it.

#include <nanobind/nanobind.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "bindings.hpp"
#include "convert.hpp"
#include "openiec61850/goose/goose.hpp"
#include "openiec61850/scl/load.hpp"
#include "pump.hpp"
#include "runtime.hpp"

namespace openiec61850::python {

namespace {

using goose::mac_address;

[[noreturn]] void raise_error(std::error_code ec) {
  nb::object e = make_error(ec);
  PyErr_SetObject(reinterpret_cast<PyObject*>(Py_TYPE(e.ptr())), e.ptr());
  throw nb::python_error();
}

template <typename T>
T value_or_raise(result<T> r) {
  if (!r) raise_error(r.error());
  return std::move(*r);
}

mac_address mac_from_py(nb::handle h) {
  const auto b = bytes_from_py(h);
  if (b.size() != 6) throw nb::value_error("a MAC address has 6 octets");
  mac_address m{};
  std::copy(b.begin(), b.end(), m.begin());
  return m;
}

nb::object mac_to_py(const mac_address& m) {
  return nb::bytes(reinterpret_cast<const char*>(m.data()), m.size());
}

std::optional<goose::vlan_tag> vlan_from_py(nb::handle h) {
  if (h.is_none()) return std::nullopt;
  const auto t = nb::cast<nb::tuple>(h);
  if (t.size() != 3) throw nb::type_error("expected (priority, dei, id)");
  const auto prio = nb::cast<int>(t[0]);
  const auto id = nb::cast<int>(t[2]);
  if (prio < 0 || prio > 7 || id < 0 || id > 4095) throw nb::value_error("VLAN priority 0..7, id 0..4095");
  return goose::vlan_tag{static_cast<std::uint8_t>(prio), nb::cast<bool>(t[1]), static_cast<std::uint16_t>(id)};
}

nb::object vlan_to_py(const std::optional<goose::vlan_tag>& v) {
  if (!v) return nb::none();
  return nb::make_tuple(v->priority, v->dei, v->id);
}

template <typename T>
nb::object opt(const std::optional<T>& v) {
  return v ? nb::cast(*v) : nb::none();
}

nb::object utc_to_py(const mms::utc_time& t) { return data_to_py(mms::data::utc_time(t)); }

std::optional<model::timestamp> when_from_py(nb::handle h) {
  if (h.is_none()) return std::nullopt;
  const auto d = data_from_py(h);
  const auto u = d.as_utc_time();
  if (!u) throw nb::type_error("expected a tagged utc-time");
  return model::timestamp(*u);
}

std::optional<mms::utc_time> utc_from_py(nb::handle h) {
  if (h.is_none()) return std::nullopt;
  const auto d = data_from_py(h);
  const auto u = d.as_utc_time();
  if (!u) throw nb::type_error("expected a tagged utc-time");
  return *u;
}

std::vector<mms::data> values_from_py(nb::handle seq) {
  std::vector<mms::data> v;
  for (nb::handle h : seq) v.push_back(data_from_py(h));
  return v;
}

std::chrono::milliseconds ms(nb::handle h) { return std::chrono::milliseconds{nb::cast<std::uint32_t>(h)}; }

// ------------------------------------------------------------------ configurations

struct dict_view {
  nb::dict d;
  [[nodiscard]] bool given(const char* k) const { return d.contains(k) && !d[k].is_none(); }
  [[nodiscard]] nb::object at(const char* k) const { return d[k]; }
  template <typename T>
  void read(const char* k, T& out) const {
    if (given(k)) out = nb::cast<T>(at(k));
  }
  template <typename T>
  void read_opt(const char* k, std::optional<T>& out) const {
    if (given(k)) out = nb::cast<T>(at(k));
  }
};

goose::publisher_config goose_pub_from_py(nb::dict dict) {
  const dict_view d{dict};
  goose::publisher_config c;
  if (d.given("destination")) c.destination = mac_from_py(d.at("destination"));
  if (d.given("source")) c.source = mac_from_py(d.at("source"));
  if (d.d.contains("vlan")) c.vlan = vlan_from_py(d.at("vlan"));
  d.read("app_id", c.app_id);
  d.read("gocb_ref", c.gocb_ref);
  d.read("dat_set", c.dat_set);
  d.read("go_id", c.go_id);
  d.read("conf_rev", c.conf_rev);
  d.read("nds_com", c.nds_com);
  d.read("simulation", c.simulation);
  if (d.given("min_time")) c.min_time = ms(d.at("min_time"));
  if (d.given("max_time")) c.max_time = ms(d.at("max_time"));
  d.read("tal_multiplier", c.tal_multiplier);
  if (d.given("tal_override")) c.tal_override = ms(d.at("tal_override"));
  d.read("time_accuracy", c.time_accuracy);
  return c;
}

nb::dict goose_pub_to_py(const goose::publisher_config& c) {
  nb::dict d;
  d["destination"] = mac_to_py(c.destination);
  d["source"] = c.source ? mac_to_py(*c.source) : nb::none();
  d["vlan"] = vlan_to_py(c.vlan);
  d["app_id"] = c.app_id;
  d["gocb_ref"] = c.gocb_ref;
  d["dat_set"] = c.dat_set;
  d["go_id"] = c.go_id;
  d["conf_rev"] = c.conf_rev;
  d["nds_com"] = c.nds_com;
  d["simulation"] = c.simulation;
  d["min_time"] = c.min_time.count();
  d["max_time"] = c.max_time.count();
  d["tal_multiplier"] = c.tal_multiplier;
  d["tal_override"] = c.tal_override ? nb::cast(c.tal_override->count()) : nb::none();
  d["time_accuracy"] = c.time_accuracy;
  return d;
}

goose::subscriber_config goose_sub_from_py(nb::dict dict) {
  const dict_view d{dict};
  goose::subscriber_config c;
  d.read_opt("app_id", c.app_id);
  if (d.given("destination")) c.destination = mac_from_py(d.at("destination"));
  d.read("gocb_ref", c.gocb_ref);
  d.read_opt("dat_set", c.dat_set);
  d.read_opt("go_id", c.go_id);
  d.read_opt("conf_rev", c.conf_rev);
  d.read_opt("num_entries", c.num_entries);
  d.read("accept_simulation", c.accept_simulation);
  if (d.given("tal_margin")) c.tal_margin = ms(d.at("tal_margin"));
  d.read("queue_capacity", c.queue_capacity);
  return c;
}

nb::dict goose_sub_to_py(const goose::subscriber_config& c) {
  nb::dict d;
  d["app_id"] = opt(c.app_id);
  d["destination"] = c.destination ? mac_to_py(*c.destination) : nb::none();
  d["gocb_ref"] = c.gocb_ref;
  d["dat_set"] = opt(c.dat_set);
  d["go_id"] = opt(c.go_id);
  d["conf_rev"] = opt(c.conf_rev);
  d["num_entries"] = opt(c.num_entries);
  d["accept_simulation"] = c.accept_simulation;
  d["tal_margin"] = c.tal_margin.count();
  d["queue_capacity"] = c.queue_capacity;
  return d;
}

sv::publisher_config sv_pub_from_py(nb::dict dict) {
  const dict_view d{dict};
  sv::publisher_config c;
  if (d.given("destination")) c.destination = mac_from_py(d.at("destination"));
  if (d.given("source")) c.source = mac_from_py(d.at("source"));
  if (d.d.contains("vlan")) c.vlan = vlan_from_py(d.at("vlan"));
  d.read("app_id", c.app_id);
  d.read("simulation", c.simulation);
  d.read("sv_id", c.sv_id);
  d.read_opt("dat_set", c.dat_set);
  d.read("conf_rev", c.conf_rev);
  d.read("smp_synch", c.smp_synch);
  d.read_opt("smp_rate", c.smp_rate);
  d.read_opt("smp_mod", c.smp_mod);
  d.read("refresh_time", c.refresh_time);
  d.read("asdus_per_frame", c.asdus_per_frame);
  d.read("smp_cnt_wrap", c.smp_cnt_wrap);
  return c;
}

nb::dict sv_pub_to_py(const sv::publisher_config& c) {
  nb::dict d;
  d["destination"] = mac_to_py(c.destination);
  d["source"] = c.source ? mac_to_py(*c.source) : nb::none();
  d["vlan"] = vlan_to_py(c.vlan);
  d["app_id"] = c.app_id;
  d["simulation"] = c.simulation;
  d["sv_id"] = c.sv_id;
  d["dat_set"] = opt(c.dat_set);
  d["conf_rev"] = c.conf_rev;
  d["smp_synch"] = c.smp_synch;
  d["smp_rate"] = opt(c.smp_rate);
  d["smp_mod"] = opt(c.smp_mod);
  d["refresh_time"] = c.refresh_time;
  d["asdus_per_frame"] = c.asdus_per_frame;
  d["smp_cnt_wrap"] = c.smp_cnt_wrap;
  return d;
}

sv::subscriber_config sv_sub_from_py(nb::dict dict) {
  const dict_view d{dict};
  sv::subscriber_config c;
  d.read_opt("app_id", c.app_id);
  if (d.given("destination")) c.destination = mac_from_py(d.at("destination"));
  d.read("sv_id", c.sv_id);
  d.read_opt("conf_rev", c.conf_rev);
  d.read("smp_cnt_wrap", c.smp_cnt_wrap);
  d.read("accept_simulation", c.accept_simulation);
  d.read("queue_capacity", c.queue_capacity);
  return c;
}

nb::dict sv_sub_to_py(const sv::subscriber_config& c) {
  nb::dict d;
  d["app_id"] = opt(c.app_id);
  d["destination"] = c.destination ? mac_to_py(*c.destination) : nb::none();
  d["sv_id"] = c.sv_id;
  d["conf_rev"] = opt(c.conf_rev);
  d["smp_cnt_wrap"] = c.smp_cnt_wrap;
  d["accept_simulation"] = c.accept_simulation;
  d["queue_capacity"] = c.queue_capacity;
  return d;
}

// kind: "goose_publisher", "goose_subscriber", "sv_publisher", "sv_subscriber".
nb::object config_from_scl(const std::string& kind, const std::string& source, bool is_text,
                           const std::string& ied, const std::string& ld, const std::string& cb,
                           const std::string& ap, std::uint16_t frequency) {
  if (kind != "goose_publisher" && kind != "goose_subscriber" && kind != "sv_publisher" &&
      kind != "sv_subscriber") {
    throw nb::value_error("unknown configuration kind");
  }
  std::optional<scl::load_result> loaded;
  {
    const nb::gil_scoped_release release;
    loaded.emplace(is_text ? scl::load_string(source) : scl::load_file(std::filesystem::path(source)));
  }
  if (!loaded->ok()) raise_error(loaded->doc.error());
  const auto& doc = *loaded->doc;
  if (kind == "goose_publisher") return goose_pub_to_py(value_or_raise(goose::publisher_config_from_scl(doc, ied, ld, cb, ap)));
  if (kind == "goose_subscriber") return goose_sub_to_py(value_or_raise(goose::subscriber_config_from_scl(doc, ied, ld, cb, ap)));
  if (kind == "sv_publisher") return sv_pub_to_py(value_or_raise(sv::publisher_config_from_scl(doc, ied, ld, cb, ap, frequency)));
  return sv_sub_to_py(value_or_raise(sv::subscriber_config_from_scl(doc, ied, ld, cb, ap, frequency)));
}

// ------------------------------------------------------------------ links

class native_link {
 public:
  native_link(std::shared_ptr<goose::link> l, std::shared_ptr<goose::loopback_link> lb)
      : l_(std::move(l)), lb_(std::move(lb)) {}

  [[nodiscard]] const std::shared_ptr<goose::link>& get() const noexcept { return l_; }
  [[nodiscard]] nb::object address() const { return mac_to_py(l_->address()); }
  void send(nb::handle frame) {
    const auto b = bytes_from_py(frame);
    std::optional<result<void>> r;
    {
      const nb::gil_scoped_release release;
      r.emplace(l_->send(b));
    }
    if (!*r) raise_error(r->error());
  }
  void close() {
    const nb::gil_scoped_release release;
    l_->close();
  }
  [[nodiscard]] nb::object dropped() const {
    if (!lb_) return nb::none();
    return nb::cast(lb_->dropped());
  }

 private:
  std::shared_ptr<goose::link> l_;
  std::shared_ptr<goose::loopback_link> lb_;
};

class native_network {
 public:
  native_network() : n_(goose::loopback_network::create()) {}
  native_link attach(nb::handle mac, std::size_t queue_capacity) {
    auto l = n_->attach(runtime().get_executor(), mac_from_py(mac), queue_capacity);
    return {l, l};
  }
  [[nodiscard]] std::uint64_t frames_sent() const noexcept { return n_->frames_sent(); }

 private:
  std::shared_ptr<goose::loopback_network> n_;
};

native_link raw_socket_open(nb::dict options) {
  const dict_view d{options};
  goose::raw_socket_options o;
  d.read("interface_name", o.interface_name);
  if (d.given("ether_types")) o.ether_types = nb::cast<std::vector<std::uint16_t>>(d.at("ether_types"));
  d.read("promiscuous", o.promiscuous);
  d.read("all_multicast", o.all_multicast);
  if (d.given("multicast_groups")) {
    for (nb::handle h : d.at("multicast_groups")) o.multicast_groups.push_back(mac_from_py(h));
  }
  d.read("receive_outgoing", o.receive_outgoing);
  d.read("socket_priority", o.socket_priority);
  std::optional<result<std::shared_ptr<goose::raw_socket_link>>> r;
  {
    const nb::gil_scoped_release release;
    r.emplace(goose::raw_socket_link::open(runtime().get_executor(), std::move(o)));
  }
  return {value_or_raise(std::move(*r)), nullptr};
}

// ------------------------------------------------------------------ GOOSE publisher

class native_goose_publisher {
 public:
  static native_goose_publisher create(const native_link& l, nb::dict config, nb::handle values) {
    auto c = goose_pub_from_py(config);
    auto v = values_from_py(values);
    std::optional<result<std::shared_ptr<goose::publisher>>> r;
    {
      const nb::gil_scoped_release release;
      r.emplace(goose::publisher::create(l.get(), std::move(c), std::move(v)));
    }
    return native_goose_publisher(value_or_raise(std::move(*r)));
  }

  void start() {
    const nb::gil_scoped_release release;
    p_->start();
  }
  void stop() {
    const nb::gil_scoped_release release;
    p_->stop();
  }
  void publish(nb::handle values, nb::handle when) {
    auto v = values_from_py(values);
    const auto t = when_from_py(when);
    std::optional<result<void>> r;
    {
      const nb::gil_scoped_release release;
      r.emplace(p_->publish(std::move(v), t));
    }
    if (!*r) raise_error(r->error());
  }
  bool update(nb::handle values, nb::handle when) {
    auto v = values_from_py(values);
    const auto t = when_from_py(when);
    std::optional<result<bool>> r;
    {
      const nb::gil_scoped_release release;
      r.emplace(p_->update(std::move(v), t));
    }
    return value_or_raise(std::move(*r));
  }
  void set_nds_com(bool on) {
    const nb::gil_scoped_release release;
    p_->set_nds_com(on);
  }
  void set_simulation(bool on) {
    const nb::gil_scoped_release release;
    p_->set_simulation(on);
  }
  [[nodiscard]] nb::object config() const { return goose_pub_to_py(p_->config()); }
  [[nodiscard]] nb::object stats() const {
    goose::publisher_stats s;
    {
      const nb::gil_scoped_release release;
      s = p_->stats();
    }
    nb::dict d;
    d["st_num"] = s.st_num;
    d["sq_num"] = s.sq_num;
    d["messages_sent"] = s.messages_sent;
    d["send_errors"] = s.send_errors;
    d["last_error"] = s.last_error ? make_error(s.last_error) : nb::none();
    return d;
  }

 private:
  explicit native_goose_publisher(std::shared_ptr<goose::publisher> p) : p_(std::move(p)) {}
  std::shared_ptr<goose::publisher> p_;
};

// ------------------------------------------------------------------ SV publisher

class native_sv_publisher {
 public:
  static native_sv_publisher create(const native_link& l, nb::dict config) {
    auto c = sv_pub_from_py(config);
    std::optional<result<std::shared_ptr<sv::publisher>>> r;
    {
      const nb::gil_scoped_release release;
      r.emplace(sv::publisher::create(l.get(), std::move(c)));
    }
    return native_sv_publisher(value_or_raise(std::move(*r)));
  }

  std::uint16_t push(nb::handle seq_data, nb::handle refr_tm) {
    const auto t = utc_from_py(refr_tm);
    // A bytes object is read in place: the GIL stays held (push() does not block).
    if (PyBytes_Check(seq_data.ptr())) {
      const byte_view b{reinterpret_cast<const std::uint8_t*>(PyBytes_AS_STRING(seq_data.ptr())),
                        static_cast<std::size_t>(PyBytes_GET_SIZE(seq_data.ptr()))};
      return value_or_raise(p_->push(b, t));
    }
    const auto b = bytes_from_py(seq_data);
    return value_or_raise(p_->push(b, t));
  }
  // `source(smp_cnt) -> bytes` is called on the I/O thread with the GIL, once per sample.
  void start(double period_s, nb::handle source) {
    if (!std::isfinite(period_s) || period_s <= 0) throw nb::value_error("the period must be positive");
    const auto period = std::chrono::nanoseconds{static_cast<std::int64_t>(std::llround(period_s * 1e9))};
    auto fn = std::make_shared<py_ref>(source);
    sv::sample_source src = [fn](std::uint16_t smp_cnt, byte_buffer& out) {
      if (interpreter_finalizing()) return;
      const nb::gil_scoped_acquire gil;
      try {
        out = bytes_from_py(nb::handle(fn->get())(smp_cnt));
      } catch (nb::python_error& e) {
        e.discard_as_unraisable("openiec61850 SV sample source");
      } catch (...) {
      }
    };
    std::optional<result<void>> r;
    {
      const nb::gil_scoped_release release;
      r.emplace(p_->start(period, std::move(src)));
    }
    if (!*r) raise_error(r->error());
  }
  void stop() {
    const nb::gil_scoped_release release;
    p_->stop();
  }
  [[nodiscard]] nb::object config() const { return sv_pub_to_py(p_->config()); }
  [[nodiscard]] nb::object stats() const {
    sv::publisher_stats s;
    {
      const nb::gil_scoped_release release;
      s = p_->stats();
    }
    nb::dict d;
    d["samples"] = s.samples;
    d["frames_sent"] = s.frames_sent;
    d["send_errors"] = s.send_errors;
    d["next_smp_cnt"] = s.next_smp_cnt;
    return d;
  }

 private:
  explicit native_sv_publisher(std::shared_ptr<sv::publisher> p) : p_(std::move(p)) {}
  std::shared_ptr<sv::publisher> p_;
};

// ------------------------------------------------------------------ subscriptions

nb::object goose_event_to_py(goose::event& e) {
  const auto& m = e.msg;
  nb::dict msg;
  msg["destination"] = mac_to_py(m.destination);
  msg["source"] = mac_to_py(m.source);
  msg["vlan"] = vlan_to_py(m.vlan);
  msg["app_id"] = m.app_id;
  msg["reserved1"] = m.reserved1;
  msg["reserved2"] = m.reserved2;
  msg["gocb_ref"] = m.gocb_ref;
  msg["time_allowed_to_live"] = m.time_allowed_to_live;
  msg["dat_set"] = m.dat_set;
  msg["go_id"] = opt(m.go_id);
  msg["t"] = data_to_py(m.t.to_mms());
  msg["st_num"] = m.st_num;
  msg["sq_num"] = m.sq_num;
  msg["simulation"] = m.simulation;
  msg["conf_rev"] = m.conf_rev;
  msg["nds_com"] = m.nds_com;
  msg["num_dat_set_entries"] = m.num_dat_set_entries;
  nb::list values;
  for (const auto& v : m.values) values.append(data_to_py(v));
  msg["values"] = values;
  msg["sequence"] = static_cast<int>(m.sequence.status);
  msg["lost"] = m.sequence.lost;
  nb::dict d;
  d["kind"] = static_cast<int>(e.kind);
  d["reason"] = static_cast<int>(e.reason);
  d["message"] = msg;
  d["dropped_before"] = e.dropped_before;
  return d;
}

using goose_pump = pump<goose::event, nb::object (*)(goose::event&)>;

class native_goose_subscription {
 public:
  native_goose_subscription(std::shared_ptr<goose::subscriber> s, std::shared_ptr<goose_pump> p)
      : s_(std::move(s)), p_(std::move(p)) {
    s_->set_handler([p = p_](const goose::event& e) { p->push(e); });
  }
  native_goose_subscription(native_goose_subscription&&) noexcept = default;
  native_goose_subscription& operator=(native_goose_subscription&&) = delete;
  native_goose_subscription(const native_goose_subscription&) = delete;
  native_goose_subscription& operator=(const native_goose_subscription&) = delete;
  ~native_goose_subscription() {
    if (!s_) return;
    s_->close();
    s_->set_handler({});
    p_->end();
  }

  void request() { p_->request(); }
  void close() {
    const nb::gil_scoped_release release;
    s_->close();
    p_->end();
  }
  [[nodiscard]] std::uint64_t dropped() const { return p_->dropped(); }
  [[nodiscard]] nb::object config() const { return goose_sub_to_py(s_->config()); }
  [[nodiscard]] nb::object stats() const {
    goose::subscriber_stats s;
    {
      const nb::gil_scoped_release release;
      s = s_->stats();
    }
    nb::dict d;
    d["messages"] = s.messages;
    d["timeouts"] = s.timeouts;
    d["mismatches"] = s.mismatches;
    d["lost"] = s.lost;
    d["duplicates"] = s.duplicates;
    d["out_of_order"] = s.out_of_order;
    d["simulated_ignored"] = s.simulated_ignored;
    d["dropped"] = s.dropped + p_->dropped();
    return d;
  }

 private:
  std::shared_ptr<goose::subscriber> s_;
  std::shared_ptr<goose_pump> p_;
};

// One SV ASDU, owned.
struct sv_record {
  mac_address source{};
  std::uint16_t app_id = 0;
  bool simulation = false;
  std::string sv_id;
  std::optional<std::string> dat_set;
  std::uint16_t smp_cnt = 0;
  std::uint32_t conf_rev = 0;
  std::optional<mms::utc_time> refr_tm;
  std::uint8_t smp_synch = 0;
  std::optional<std::uint16_t> smp_rate;
  std::optional<std::uint16_t> smp_mod;
  byte_buffer seq_data;
  sv::continuity status = sv::continuity::first;
  std::uint32_t lost = 0;
  bool conf_rev_mismatch = false;
};

// (source, app_id, simulation, sv_id, dat_set, smp_cnt, conf_rev, refr_tm, smp_synch, smp_rate,
//  smp_mod, seq_data, status, lost, conf_rev_mismatch)
nb::object sv_record_to_py(sv_record& r) {
  return nb::make_tuple(mac_to_py(r.source), r.app_id, r.simulation, r.sv_id, opt(r.dat_set), r.smp_cnt,
                        r.conf_rev, r.refr_tm ? utc_to_py(*r.refr_tm) : nb::none(), r.smp_synch,
                        opt(r.smp_rate), opt(r.smp_mod), to_bytes(r.seq_data), static_cast<int>(r.status),
                        r.lost, r.conf_rev_mismatch);
}

using sv_pump = pump<sv_record, nb::object (*)(sv_record&)>;

class native_sv_subscription {
 public:
  native_sv_subscription(std::shared_ptr<sv::subscriber> s, std::shared_ptr<sv_pump> p)
      : s_(std::move(s)), p_(std::move(p)) {
    s_->set_handler([p = p_, expected = s_->config().conf_rev](
                        const sv::frame_view& f, const sv::asdu_view& a, const sv::smp_cnt_tracker::check& c) {
      sv_record r;
      r.source = f.source;
      r.app_id = f.app_id;
      r.simulation = f.simulation();
      r.sv_id = std::string(a.sv_id);
      if (a.dat_set) r.dat_set = std::string(*a.dat_set);
      r.smp_cnt = a.smp_cnt;
      r.conf_rev = a.conf_rev;
      r.refr_tm = a.refr_tm;
      r.smp_synch = a.smp_synch;
      r.smp_rate = a.smp_rate;
      r.smp_mod = a.smp_mod;
      r.seq_data.assign(a.seq_data.begin(), a.seq_data.end());
      r.status = c.status;
      r.lost = c.lost;
      r.conf_rev_mismatch = expected && *expected != a.conf_rev;
      p->push(std::move(r));
    });
  }
  native_sv_subscription(native_sv_subscription&&) noexcept = default;
  native_sv_subscription& operator=(native_sv_subscription&&) = delete;
  native_sv_subscription(const native_sv_subscription&) = delete;
  native_sv_subscription& operator=(const native_sv_subscription&) = delete;
  ~native_sv_subscription() {
    if (!s_) return;
    s_->close();
    s_->set_handler({});
    p_->end();
  }

  void request() { p_->request(); }
  void close() {
    const nb::gil_scoped_release release;
    s_->close();
    p_->end();
  }
  [[nodiscard]] std::uint64_t dropped() const { return p_->dropped(); }
  [[nodiscard]] nb::object config() const { return sv_sub_to_py(s_->config()); }
  [[nodiscard]] nb::object stats() const {
    sv::subscriber_stats s;
    {
      const nb::gil_scoped_release release;
      s = s_->stats();
    }
    nb::dict d;
    d["samples"] = s.samples;
    d["lost"] = s.lost;
    d["duplicates"] = s.duplicates;
    d["out_of_order"] = s.out_of_order;
    d["conf_rev_mismatches"] = s.conf_rev_mismatches;
    d["simulated_ignored"] = s.simulated_ignored;
    d["dropped"] = s.dropped + p_->dropped();
    return d;
  }

 private:
  std::shared_ptr<sv::subscriber> s_;
  std::shared_ptr<sv_pump> p_;
};

// ------------------------------------------------------------------ receiver

class native_receiver {
 public:
  explicit native_receiver(const native_link& l) : r_(goose::receiver::create(l.get())) {}
  native_receiver(native_receiver&&) noexcept = default;
  native_receiver& operator=(native_receiver&&) = delete;
  native_receiver(const native_receiver&) = delete;
  native_receiver& operator=(const native_receiver&) = delete;
  ~native_receiver() {
    if (r_) r_->stop();
  }

  void start() {
    const nb::gil_scoped_release release;
    r_->start();
  }
  void stop() {
    const nb::gil_scoped_release release;
    r_->stop();
  }
  native_goose_subscription subscribe_goose(nb::dict config, nb::handle sink, std::size_t max_batch) {
    auto c = goose_sub_from_py(config);
    auto p = std::make_shared<goose_pump>(sink, c.queue_capacity, max_batch, &goose_event_to_py);
    std::shared_ptr<goose::subscriber> s;
    {
      const nb::gil_scoped_release release;
      s = r_->subscribe(std::move(c));
    }
    return {std::move(s), std::move(p)};
  }
  native_sv_subscription subscribe_sv(nb::dict config, nb::handle sink, std::size_t max_batch) {
    auto c = sv_sub_from_py(config);
    auto p = std::make_shared<sv_pump>(sink, c.queue_capacity, max_batch, &sv_record_to_py);
    std::shared_ptr<sv::subscriber> s;
    {
      const nb::gil_scoped_release release;
      s = r_->subscribe(std::move(c));
    }
    return {std::move(s), std::move(p)};
  }
  [[nodiscard]] nb::object stats() const {
    goose::receiver_stats s;
    {
      const nb::gil_scoped_release release;
      s = r_->stats();
    }
    nb::dict d;
    d["frames"] = s.frames;
    d["malformed"] = s.malformed;
    d["unmatched"] = s.unmatched;
    d["other"] = s.other;
    return d;
  }

 private:
  std::shared_ptr<goose::receiver> r_;
};

// ------------------------------------------------------------------ 9-2 LE helpers

// seqData of 9-2 LE: [(value, quality32)] x 8 <-> 64 octets.
nb::object le_decode(nb::handle data) {
  const auto b = bytes_from_py(data);
  const auto s = value_or_raise(sv::le::decode(b));
  nb::list out;
  for (const auto& c : s.channels) out.append(nb::make_tuple(c.value, c.q.raw));
  return out;
}

nb::bytes le_encode(nb::handle channels) {
  sv::le::samples s;
  std::size_t i = 0;
  for (nb::handle h : channels) {
    if (i >= sv::le::channel_count) throw nb::value_error("9-2 LE has 8 channels");
    const auto t = nb::cast<nb::tuple>(h);
    s.channels[i] = {nb::cast<std::int32_t>(t[0]), {nb::cast<std::uint32_t>(t[1])}};
    ++i;
  }
  if (i != sv::le::channel_count) throw nb::value_error("9-2 LE has 8 channels");
  const auto out = sv::le::encode(s);
  return nb::bytes(reinterpret_cast<const char*>(out.data()), out.size());
}

}  // namespace

void bind_goose(nb::module_& m) {
  nb::class_<py_batch>(m, "_Batch", "Items delivered by a native subscription (internal).")
      .def("items", &py_batch::items)
      .def_prop_ro("ended", [](const py_batch& b) { return b.ended; })
      .def_prop_ro("error", [](const py_batch& b) { return b.error ? make_error(b.error) : nb::none(); })
      .def_prop_ro("dropped", [](const py_batch& b) { return b.dropped; });

  nb::class_<native_link>(m, "GooseLink", "A layer 2 link (internal; see openiec61850.goose).")
      .def_prop_ro("address", &native_link::address)
      .def_prop_ro("dropped", &native_link::dropped)
      .def("send", &native_link::send, nb::arg("frame"))
      .def("close", &native_link::close)
      .def_static("open_raw", &raw_socket_open, nb::arg("options"));

  nb::class_<native_network>(m, "LoopbackNetwork", "In-memory broadcast domain (internal).")
      .def(nb::init<>())
      .def("attach", &native_network::attach, nb::arg("mac"), nb::arg("queue_capacity") = 1024)
      .def_prop_ro("frames_sent", &native_network::frames_sent);

  nb::class_<native_goose_publisher>(m, "GoosePublisher", "GOOSE publisher (internal).")
      .def_static("create", &native_goose_publisher::create, nb::arg("link"), nb::arg("config"),
                  nb::arg("values"))
      .def("start", &native_goose_publisher::start)
      .def("stop", &native_goose_publisher::stop)
      .def("publish", &native_goose_publisher::publish, nb::arg("values"), nb::arg("when").none() = nb::none())
      .def("update", &native_goose_publisher::update, nb::arg("values"), nb::arg("when").none() = nb::none())
      .def("set_nds_com", &native_goose_publisher::set_nds_com, nb::arg("on"))
      .def("set_simulation", &native_goose_publisher::set_simulation, nb::arg("on"))
      .def("config", &native_goose_publisher::config)
      .def("stats", &native_goose_publisher::stats);

  nb::class_<native_sv_publisher>(m, "SvPublisher", "Sampled Values publisher (internal).")
      .def_static("create", &native_sv_publisher::create, nb::arg("link"), nb::arg("config"))
      .def("push", &native_sv_publisher::push, nb::arg("seq_data"), nb::arg("refr_tm").none() = nb::none())
      .def("start", &native_sv_publisher::start, nb::arg("period"), nb::arg("source"))
      .def("stop", &native_sv_publisher::stop)
      .def("config", &native_sv_publisher::config)
      .def("stats", &native_sv_publisher::stats);

  nb::class_<native_goose_subscription>(m, "GooseSubscription", "GOOSE subscription (internal).")
      .def("request", &native_goose_subscription::request)
      .def("close", &native_goose_subscription::close)
      .def_prop_ro("dropped", &native_goose_subscription::dropped)
      .def("config", &native_goose_subscription::config)
      .def("stats", &native_goose_subscription::stats);

  nb::class_<native_sv_subscription>(m, "SvSubscription", "SV subscription (internal).")
      .def("request", &native_sv_subscription::request)
      .def("close", &native_sv_subscription::close)
      .def_prop_ro("dropped", &native_sv_subscription::dropped)
      .def("config", &native_sv_subscription::config)
      .def("stats", &native_sv_subscription::stats);

  nb::class_<native_receiver>(m, "Receiver", "GOOSE / SV receiver (internal).")
      .def(nb::init<const native_link&>(), nb::arg("link"))
      .def("start", &native_receiver::start)
      .def("stop", &native_receiver::stop)
      .def("subscribe_goose", &native_receiver::subscribe_goose, nb::arg("config"), nb::arg("sink"),
           nb::arg("max_batch") = 64)
      .def("subscribe_sv", &native_receiver::subscribe_sv, nb::arg("config"), nb::arg("sink"),
           nb::arg("max_batch") = 1024)
      .def("stats", &native_receiver::stats);

  m.def("goose_config_from_scl", &config_from_scl, nb::arg("kind"), nb::arg("source"), nb::arg("is_text"),
        nb::arg("ied"), nb::arg("ld_inst"), nb::arg("cb_name"), nb::arg("access_point") = "",
        nb::arg("frequency") = 50);
  m.def("le_decode", &le_decode, nb::arg("seq_data"));
  m.def("le_encode", &le_encode, nb::arg("channels"));
}

}  // namespace openiec61850::python
