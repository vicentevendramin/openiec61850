#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>
#include <asio/steady_timer.hpp>
#include <asio/strand.hpp>

#include "openiec61850/server/server.hpp"
#include "openiec61850/model/entry_id.hpp"
#include "openiec61850/model/mms_mapping.hpp"
#include "openiec61850/model/rcb_options.hpp"
#include "openiec61850/model/timestamp.hpp"

namespace openiec61850::server::detail {

using strand_type = asio::strand<asio::any_io_executor>;
using clock = std::chrono::steady_clock;
using dae = mms::data_access_error;

// A step below a value-holding attribute: an array element or a structure component.
struct selector {
  bool index = false;
  std::uint32_t value = 0;  // element index or component position

  friend bool operator==(const selector&, const selector&) = default;
};

// What an MMS variable name or an ACSI reference designates: a node seen under an FC (unset only
// for a whole LN), possibly an element inside the value of an array attribute.
struct target {
  node_id node = no_node;
  std::optional<model::functional_constraint> fc;
  std::vector<selector> path;
};

struct member {
  target t;
  model::mms_variable var;  // as returned by GetNamedVariableListAttributes
  std::string mms_ref;      // report data-reference "LD/LN$FC$DO$DA"
};

struct data_set {
  std::string domain;  // empty: association specific
  std::string item;    // "LN$DS", or the name without "@"
  bool deletable = false;
  std::uint64_t owner = 0;  // association-specific: the session
  std::string mms_text;     // "LD/LN$DS" or "@DS"
  std::vector<member> members;
  // Value-holding node -> the members containing it.
  std::unordered_map<node_id, std::vector<std::size_t>> by_holder;
};

struct included {
  mms::data value;
  model::trigger_conditions reason;
};

// One report: a BRCB buffer entry, or a URCB report about to be sent.
struct report_entry {
  std::uint32_t sq_num = 0;
  model::entry_id id;
  model::entry_time time{0, std::uint16_t{0}};
  std::vector<std::optional<included>> members;
};

struct pending_member {
  model::trigger_conditions reason;
  std::uint64_t tick = 0;
};

struct rcb {
  explicit rcb(const strand_type& s) : buf_timer(s), intg_timer(s), resv_timer(s) {}

  node_id node = no_node;
  node_id ln = no_node;
  bool buffered = false;
  std::string mms_ref;  // "LD/LN$BR$name"
  std::map<std::string, node_id, std::less<>> attrs;

  std::string rpt_id;
  bool rpt_ena = false;
  bool resv = false;  // URCB
  std::string dat_set;
  std::shared_ptr<data_set> ds;
  std::uint32_t conf_rev = 1;
  model::optional_fields opt;
  std::uint32_t buf_tm = 0;
  std::uint32_t sq_num = 0;  // of the next report
  model::trigger_conditions trg;
  std::uint32_t intg_pd = 0;
  model::entry_id entry;                       // BRCB: last entry sent (or written)
  model::entry_time time_of_entry{0, std::uint16_t{0}};
  std::int32_t resv_tms = 0;                   // BRCB (Ed.2)
  std::uint64_t owner = 0;                     // session holding it (reserved or enabled)
  std::string held_for;                        // BRCB: peer address keeping a reservation
  byte_buffer held_bytes;
  std::uint64_t hold_gen = 0;

  // Events waiting for the buffer time to expire.
  std::vector<std::optional<pending_member>> pending;
  std::size_t pending_count = 0;
  bool flush_posted = false;
  bool buf_running = false;
  std::uint64_t buf_gen = 0;
  asio::steady_timer buf_timer;
  std::uint64_t intg_gen = 0;
  asio::steady_timer intg_timer;
  asio::steady_timer resv_timer;

  // BRCB buffer.
  std::deque<report_entry> buffer;
  std::size_t next_send = 0;  // index of the next entry to send
  bool overflow_next = false;
  bool ever_enabled = false;
  bool pump_posted = false;
};

// The SGCB of a logical device (7-2 §16). The values of the active group live in
// server_state::values (so reads, reports and logs need nothing special); every group is also
// kept in `groups`, and the edit buffer in `edit_values`.
struct sgcb {
  explicit sgcb(const strand_type& s) : resv_timer(s) {}

  node_id node = no_node;
  node_id ld = no_node;
  std::map<std::string, node_id, std::less<>> attrs;
  std::uint8_t num = 1;
  std::uint8_t act = 1;
  std::uint8_t edit = 0;
  std::uint16_t resv_tms = 0;
  model::timestamp lact_tm;
  std::uint64_t owner = 0;  // session holding the edit buffer
  std::vector<node_id> holders;  // FC SG value-holding nodes of the LD
  std::unordered_map<node_id, std::size_t> index;  // holder -> position
  std::vector<std::vector<mms::data>> groups;      // [group - 1][position]
  std::vector<mms::data> edit_values;              // [position]
  std::uint64_t resv_gen = 0;
  asio::steady_timer resv_timer;
};

// One logged data value (8-1 §17.3.3: a Journal-Variable with the data reference, followed by
// one tagged "ReasonCode").
struct logged_value {
  std::string reference;  // "LD/LN$FC$DO$DA"
  mms::data value;
  model::trigger_conditions reason;
};

struct log_entry {
  model::entry_id id;
  model::entry_time time{0, std::uint16_t{0}};
  std::vector<logged_value> values;
};

// A log (MMS journal "LN$name" of the LD's domain).
struct log_store {
  std::string domain;
  std::string item;
  std::deque<log_entry> entries;
};

struct lcb {
  explicit lcb(const strand_type& s) : intg_timer(s) {}

  node_id node = no_node;
  node_id ln = no_node;
  std::map<std::string, node_id, std::less<>> attrs;
  bool ena = false;
  std::string log_ref;  // "LD/LN$Log"; empty: none
  log_store* log = nullptr;
  std::string dat_set;
  std::shared_ptr<data_set> ds;
  model::trigger_conditions trg;
  std::uint32_t intg_pd = 0;
  std::uint64_t intg_gen = 0;
  asio::steady_timer intg_timer;
};

struct gocb {
  node_id node = no_node;
  node_id ln = no_node;
  std::map<std::string, node_id, std::less<>> attrs;
  model::object_reference reference;
  goose_control_settings live;
  std::string dat_set;
  std::shared_ptr<data_set> ds;
};

// A file open by FileOpen (ISO 9506-2 file read state machine).
struct open_file {
  std::string path;
  std::uint64_t position = 0;
  std::uint64_t size = 0;
};

struct session {
  explicit session(const strand_type& s) : wake(s, clock::time_point::max()) {}

  std::uint64_t id = 0;
  std::optional<association::server_association> assoc;
  std::string address;       // peer IP address, textual
  byte_buffer address_bytes;  // Owner value
  std::size_t max_pdu = 0;    // the client's local detail; 0: no limit
  std::deque<asio::awaitable<result<void>>> outbox;
  asio::steady_timer wake;
  bool closed = false;
  std::map<std::string, std::shared_ptr<data_set>, std::less<>> aa_sets;
  std::map<std::int32_t, open_file> files;  // by FRSM ID
  std::int32_t next_frsm = 1;

  void push(asio::awaitable<result<void>> a) {
    if (closed || !assoc) return;
    outbox.push_back(std::move(a));
    wake.cancel();
  }
};

// The reply to a confirmed request; owns everything the response views. Not movable.
struct reply {
  reply() = default;
  reply(const reply&) = delete;
  reply& operator=(const reply&) = delete;

  enum class kind : std::uint8_t { response, error, reject };
  kind type = kind::response;
  mms::confirmed_service_response response;
  mms::service_error error;
  std::int64_t reject_reason = 0;

  std::deque<mms::data> data;
  std::deque<std::string> strings;
  std::vector<std::string_view> names;
  std::vector<mms::access_result> results;
  std::vector<mms::write_result> writes;
  std::vector<mms::variable_spec> specs;
  std::vector<mms::journal_entry> journal;
  std::deque<std::vector<mms::journal_variable>> journal_vars;
  std::vector<mms::directory_entry> directory;
  std::deque<std::vector<std::string_view>> file_names;
  std::deque<std::array<std::uint8_t, 8>> ids;
  byte_buffer bytes;

  void fail(mms::error_class c, std::int64_t code) {
    type = kind::error;
    error = mms::service_error(c, code);
  }
  void reject(std::int64_t reason) {
    type = kind::reject;
    reject_reason = reason;
  }
};

// A value assignment below a value-holding node.
struct assignment {
  node_id holder = no_node;
  std::vector<selector> path;
  mms::data value;
};

// The fields of a control request that the next request of the sequence must repeat.
struct control_params {
  mms::data ctl_val;
  std::optional<model::orcat> or_cat;
  byte_buffer or_ident;
  std::uint64_t ctl_num = 0;
  bool test = false;
};

struct selection {
  std::uint64_t session = 0;
  std::uint64_t gen = 0;
  std::unique_ptr<asio::steady_timer> timer;
  std::optional<control_params> sbow;  // sbo-with-enhanced-security: the SelectWithValue
};

struct server_state;

// Shared by an execution and the control_completion handles given to the application.
struct completion_state {
  std::weak_ptr<server_state> state;
  node_id object = no_node;
  std::uint64_t gen = 0;
  std::atomic<bool> done{false};

  static control_completion make(std::shared_ptr<completion_state> s) {
    return control_completion(std::move(s));
  }
};

// An accepted Operate not finished yet: waiting for its activation time (operTm) or for the
// application's completion.
struct execution {
  std::uint64_t session = 0;
  std::uint64_t gen = 0;
  bool enhanced = false;
  bool waiting_activation = false;
  control_request req;
  mms::data oper;              // the Oper value as written (echoed by CommandTermination)
  node_id oper_node = no_node;  // the Oper attribute
  std::unique_ptr<asio::steady_timer> timer;  // activation or operate_timeout
  std::shared_ptr<completion_state> completion;
};

struct server_state : std::enable_shared_from_this<server_state> {
  server_state(asio::any_io_executor ex, data_model m, server_options o);

  strand_type strand;
  data_model model;
  server_options options;
  model::name_limits limits;
  std::vector<mms::data> values;  // by node; set for value-holding nodes

  std::vector<std::string> domains;  // sorted
  std::map<node_id, std::vector<std::string>> variable_names;  // by LD, sorted

  std::map<std::pair<std::string, std::string>, std::shared_ptr<data_set>> data_sets;
  std::size_t dynamic_data_sets = 0;
  std::vector<std::unique_ptr<rcb>> rcbs;
  std::unordered_map<node_id, rcb*> rcb_of;  // control block node -> rcb

  std::map<std::uint64_t, std::shared_ptr<session>> sessions;
  std::uint64_t next_session = 1;
  std::atomic<std::size_t> associations{0};
  std::atomic<std::size_t> live_tasks{0};
  std::atomic<bool> stopped{false};
  std::optional<association::association_listener> listener;
  asio::ip::tcp::endpoint endpoint;
  std::vector<asio::steady_timer*> stop_waiters;

  std::uint64_t tick = 0;
  std::uint64_t next_entry = 0;
  std::map<node_id, selection> selections;  // controllable DO -> sbo selection
  std::map<node_id, execution> executions;  // controllable DO -> operation in progress
  std::uint64_t next_control_gen = 0;

  std::vector<std::unique_ptr<sgcb>> sgcbs;
  std::unordered_map<node_id, sgcb*> sgcb_of;         // SGCB node -> sgcb
  std::unordered_map<node_id, sgcb*> sgcb_of_holder;  // FC SG holder -> sgcb
  std::map<std::pair<std::string, std::string>, std::unique_ptr<log_store>> logs;
  std::vector<std::unique_ptr<lcb>> lcbs;
  std::unordered_map<node_id, lcb*> lcb_of;
  std::vector<std::unique_ptr<gocb>> gocbs;
  std::unordered_map<node_id, gocb*> gocb_of;

  // --- setup (server.cpp)
  result<void> init();

  // --- model access (access.cpp)
  [[nodiscard]] const node& at(node_id id) const noexcept { return model.at(id); }
  [[nodiscard]] std::optional<target> resolve_mms(const mms::object_name& name,
                                                  byte_view alternate_access) const;
  [[nodiscard]] result<target> resolve_ref(const model::object_reference& ref) const;
  [[nodiscard]] result<mms::data> value_of(const target& t) const;
  [[nodiscard]] result<mms::type_description> type_of(const target& t) const;
  // Splits a value for `t` into assignments to value-holding nodes (no checks).
  void plan(const target& t, const mms::data& v, std::vector<assignment>& out) const;
  // Applies assignments and triggers the reports.
  void apply(std::vector<assignment> plan);
  [[nodiscard]] std::string mms_reference(const target& t) const;
  [[nodiscard]] result<model::object_reference> acsi_reference(const target& t) const;
  [[nodiscard]] std::vector<node_id> holders_under(const target& t) const;

  // --- services (services.cpp)
  void dispatch(session& s, const mms::confirmed_service_request& req, reply& out);
  std::optional<dae> write_one(session& s, const target& t, const mms::data& value);
  result<std::shared_ptr<data_set>> make_data_set(std::string domain, std::string item,
                                                  const mms::list_view<mms::variable_spec>& vars);
  [[nodiscard]] std::shared_ptr<data_set> find_data_set(const session* s,
                                                        std::string_view mms_text) const;

  // --- reporting (reporting.cpp)
  void init_rcb(const report_control_definition& def);
  void sync(rcb& r);
  std::optional<dae> write_rcb(session& s, rcb& r, std::string_view attr, const mms::data& v);
  void before_change(node_id holder);
  void on_change(node_id holder, model::trigger_conditions reasons);
  void flush(rcb& r);
  void schedule_flush(rcb& r);
  void general_interrogation(rcb& r);
  void integrity(rcb& r);
  void emit(rcb& r, report_entry e);
  void pump(rcb& r);
  void send_report(session& s, rcb& r, const report_entry& e, bool overflow);
  void start_integrity(rcb& r);
  void disable(rcb& r);
  void release_session_rcbs(session& s);
  void data_set_deleted(const std::shared_ptr<data_set>& ds);
  [[nodiscard]] report_entry snapshot_all(rcb& r, model::trigger_conditions reason);

  // --- setting groups (setting_groups.cpp)
  void init_sgcb(const setting_group_definition& def);
  void sync(sgcb& g);
  std::optional<dae> write_sgcb(session& s, sgcb& g, std::string_view attr, const mms::data& v);
  // A write to the edit buffer ("$SE$" of an FC SG attribute).
  std::optional<dae> write_edit(session& s, const target& t, const mms::data& v);
  // The edit buffer value for a holder (the active value when no edit is in progress).
  [[nodiscard]] const mms::data& edit_value(node_id holder) const;
  void activate_group(sgcb& g, std::uint8_t sg);
  void release_edit(sgcb& g);
  void setting_groups_session_closed(session& s);
  // After apply(): keeps the stored active group in step with values.
  void store_active(node_id holder);

  // --- logs (logging.cpp)
  void init_logs();
  void sync(lcb& l);
  std::optional<dae> write_lcb(session& s, lcb& l, std::string_view attr, const mms::data& v);
  // Logs the changes of one apply() (one entry per LCB).
  void log_changes(const std::vector<std::pair<node_id, model::trigger_conditions>>& changes);
  void log_integrity(lcb& l);
  void start_log_integrity(lcb& l);
  void add_log_entry(lcb& l, std::vector<logged_value> values);
  void dispatch_ext(session& s, const mms::read_journal_request& r, reply& out);
  void dispatch_ext(session& s, const mms::initialize_journal_request& r, reply& out);
  void dispatch_ext(session& s, const mms::report_journal_status_request& r, reply& out);

  // --- GOOSE control blocks (goose_control.cpp)
  void init_gocb(const goose_control_definition& def);
  void sync(gocb& g);
  std::optional<dae> write_gocb(session& s, gocb& g, std::string_view attr, const mms::data& v);
  [[nodiscard]] goose_control_state state_of(const gocb& g) const;

  // --- files (file_services.cpp)
  void dispatch_ext(session& s, const mms::file_open_request& r, reply& out);
  void dispatch_ext(session& s, const mms::file_read_request& r, reply& out);
  void dispatch_ext(session& s, const mms::file_close_request& r, reply& out);
  void dispatch_ext(session& s, const mms::file_rename_request& r, reply& out);
  void dispatch_ext(session& s, const mms::file_delete_request& r, reply& out);
  void dispatch_ext(session& s, const mms::file_directory_request& r, reply& out);

  // --- control (control.cpp)
  // Returns true when the target is handled by the control model (CO data objects).
  bool control_read(session& s, const target& t, mms::data& out);
  std::optional<dae> control_write(session& s, const target& t, const mms::data& v);
  void control_session_closed(session& s);
  // Ends an execution (on the strand): the CommandTermination of enhanced security.
  void finish_execution(node_id object, std::uint64_t gen, control_result r);
  // Runs a time-activated Operate whose activation time has come.
  void activate(node_id object, std::uint64_t gen);
  void control_shutdown();

  // --- sessions (server.cpp)
  [[nodiscard]] session* find_session(std::uint64_t id) const;
  void shutdown();
};

// Hooks for the fuzzer and tests: a state without a listener, and a session without an
// association.
[[nodiscard]] result<std::shared_ptr<server_state>> make_offline_state(asio::any_io_executor ex,
                                                                       data_model m,
                                                                       server_options o);

}  // namespace openiec61850::server::detail
