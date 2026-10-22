#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <asio/any_io_executor.hpp>

#include "openiec61850/association/server_association.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/mms/pdu.hpp"
#include "openiec61850/mms/type_description.hpp"
#include "openiec61850/model/basic_type.hpp"
#include "openiec61850/model/entry_id.hpp"
#include "openiec61850/model/rcb_options.hpp"
#include "openiec61850/model/timestamp.hpp"

// A small IEC 61850 server over server_association, serving a static model, for the client tests
// (and later the Python tests). Not a conformant server: just enough of IEC 61850-8-1 to exercise
// the client. Single-threaded: create it, the client and the test coroutine on one io_context.
//
// Model (domain "IED1LD0"):
//   LLN0   ST Mod{stVal INT8, q, t}
//          BR brcb01{RptID, RptEna, DatSet, ConfRev, OptFlds, BufTm, SqNum, TrgOps, IntgPd, GI,
//                    PurgeBuf, EntryID, TimeOfEntry, ResvTms, Owner}
//          RP urcb01{RptID, RptEna, Resv, DatSet, ConfRev, OptFlds, BufTm, SqNum, TrgOps, IntgPd,
//                    GI, Owner}
//   MMXU1  MX TotW{mag{f FLOAT32}, q, t}, PhV{phsA{cVal{mag{f}}, q, t}, phsB{cVal{mag{f}}, q, t}}
//          CF TotW{db INT32U}
//   XCBR1  ST Pos{stVal Dbpos, q, t}
//          CF Pos{ctlModel INT8}
// Domain "IED1LD1": LLN0 ST Mod{stVal, q, t}; GGIO1 ST Ind1{stVal BOOLEAN, q, t}.
// Data set IED1LD0/LLN0$DS1 = MMXU1$MX$TotW, XCBR1$ST$Pos$stVal, XCBR1$ST$Pos$q,
//                             MMXU1$MX$PhV$phsA$cVal$mag$f (not deletable).
// brcb01: RptID "brcb01-id", DatSet DS1, ConfRev 1. urcb01: RptID "" (reports carry the RCB
// reference), DatSet DS1, ConfRev 1. Both TrgOps dchg|qchg|gi.
//
// RCB behaviour: a URCB is reserved by Resv = true or by writing any attribute; writes from
// another association are refused (object-access-denied). Configuration attributes cannot be
// written while RptEna is true (temporarily-unavailable). A BRCB buffers entries once it has
// been enabled, also while disabled or unowned; enabling it sends the buffered entries after the
// EntryID last written (all of them when it is zero). GI = true sends a GI report. When an
// association ends, its RCBs are disabled and released.

namespace openiec61850::testing {

struct fake_server_options {
  // Identifiers per GetNameList response (moreFollows when truncated); zero: no limit.
  std::size_t name_list_page = 0;
  association::server_options association;
};

class fake_server {
 public:
  explicit fake_server(asio::any_io_executor ex, fake_server_options options = {});
  ~fake_server();
  fake_server(const fake_server&) = delete;
  fake_server& operator=(const fake_server&) = delete;

  // Listens on 127.0.0.1 (ephemeral port) and starts accepting associations.
  [[nodiscard]] result<void> start();
  [[nodiscard]] std::uint16_t port() const noexcept;
  // Closes the listener and aborts every association.
  void stop();
  // Closes the TCP connection of every association without an ABRT (the server "disappears");
  // their RCBs are released at once.
  void drop_connections();

  [[nodiscard]] std::size_t associations_accepted() const noexcept;
  [[nodiscard]] std::size_t active_associations() const noexcept;
  // Confirmed requests received, by service tag (mms::confirmed_service).
  [[nodiscard]] std::size_t requests(mms::confirmed_service s) const;
  // Variables written successfully, in order, as "domain/item".
  [[nodiscard]] const std::vector<std::string>& write_log() const noexcept;
  void clear_write_log();

  // Model values, by domain and item ("MMXU1$MX$TotW$mag$f").
  [[nodiscard]] std::optional<mms::data> value(std::string_view domain, std::string_view item) const;
  bool set_value(std::string_view domain, std::string_view item, mms::data v);
  // Sets a value in IED1LD0 and reports it, with `reason`, through every RCB whose data set has a
  // member containing it and whose TrgOps include the reason.
  bool update(std::string_view item, mms::data v,
              model::trigger_conditions reason =
                  model::trigger_conditions::of({model::trigger::data_change}));
  // Sends an InformationReport "RPT" with these access results to every association.
  void send_report(std::vector<mms::data> access_results);

  // While on, confirmed requests are counted but left unanswered (until the association ends).
  void hold_requests(bool on);

  [[nodiscard]] std::size_t buffered_entries(std::string_view brcb) const;
  [[nodiscard]] bool rcb_enabled(std::string_view rcb) const;

  struct state;

 private:
  std::shared_ptr<state> state_;
};

}  // namespace openiec61850::testing
