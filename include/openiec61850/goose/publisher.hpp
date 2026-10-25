#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "openiec61850/core/result.hpp"
#include "openiec61850/goose/frame.hpp"
#include "openiec61850/goose/link.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/model/timestamp.hpp"

// GOOSE Publicador (IEC 61850-7-2 §18.2, IEC 61850-8-1 §18.1).
//
// Retransmission scheme (8-1 §18.1.2.5 leaves the curve to the implementation; the SCL GSE
// element gives MinTime and MaxTime):
//
//   event   ─ message stNum+1, sqNum 0, sent at once
//           ─ retransmission sqNum n (n >= 1) sent interval(n) after the previous message,
//             interval(n) = min(MinTime * 2^(n-1), MaxTime)
//           ─ ... then every MaxTime until the next event.
//
// So with MinTime 4 ms and MaxTime 1000 ms: 0, +4, +8, +16, +32 ... +512, +1000, +1000 ...
//
// timeAllowedtoLive of a message = tal_multiplier (default 2) x the interval until the next
// message, so a subscriber detects the loss of one message without false alarms, and a silent
// publisher within tal_multiplier intervals. While the intervals double, the loss of one message
// makes the gap interval(n+1) + interval(n+2) = 3 x interval(n+1), so with the default of 2 a
// single lost fast retransmission raises a TAL timeout at the subscriber; use 3 or more (or a
// subscriber tal_margin) to tolerate it. tal_override fixes the TAL instead (e.g. to the same
// value in every message, as some IEDs do).
//
// Counters (8-1 §18.1.2.5, 7-2 Ed.2 §18.2.3.6): stNum starts at 1 and wraps from 2^32-1 to 1;
// sqNum restarts at 0 on each event and wraps from 2^32-1 to 1.

namespace openiec61850::goose {

// The interval before the message with sqNum `sq_num` (>= 1).
[[nodiscard]] std::chrono::milliseconds retransmission_interval(
    std::uint32_t sq_num, std::chrono::milliseconds min_time,
    std::chrono::milliseconds max_time) noexcept;

struct publisher_config {
  mac_address destination = goose_multicast_base;
  std::optional<mac_address> source;  // the link address when unset
  std::optional<vlan_tag> vlan = vlan_tag{};
  std::uint16_t app_id = goose_app_id_default;

  std::string gocb_ref;  // "IED1LD0/LLN0$GO$gcb01"
  std::string dat_set;   // "IED1LD0/LLN0$DataSet1"
  std::string go_id;     // omitted from the messages when empty
  std::uint32_t conf_rev = 1;
  bool nds_com = false;
  // Ed.2 simulation: sets both the PDU "simulation" field and the Reserved1 S bit.
  bool simulation = false;

  std::chrono::milliseconds min_time{10};
  std::chrono::milliseconds max_time{1000};
  std::uint32_t tal_multiplier = 2;
  std::optional<std::chrono::milliseconds> tal_override;

  std::uint8_t time_accuracy = model::time_accuracy_class::unspecified;
};

struct publisher_stats {
  std::uint32_t st_num = 0;
  std::uint32_t sq_num = 0;
  std::uint64_t messages_sent = 0;
  std::uint64_t send_errors = 0;
  std::error_code last_error;
};

// Threading: every method is safe from any thread; the publisher's state lives on a strand of
// the link's executor, retransmissions are driven by a timer on it. The handle is shared; stop()
// (or destroying the last handle) ends the retransmissions.
class publisher {
 public:
  // Validates the configuration (errc::invalid_state for an empty gocbRef / datSet, MinTime 0,
  // MaxTime < MinTime, a TAL multiplier of 0, invalid values).
  [[nodiscard]] static result<std::shared_ptr<publisher>> create(std::shared_ptr<link> l,
                                                                 publisher_config config,
                                                                 std::vector<mms::data> values);
  ~publisher();
  publisher(const publisher&) = delete;
  publisher& operator=(const publisher&) = delete;

  // Sends the first message (stNum 1, sqNum 0) and starts the retransmissions. No-op when
  // already started.
  void start();
  // Stops the retransmissions; start() resumes them with a new event.
  void stop();

  // A new state: stNum+1, sqNum 0, t = `when` (now by default), sent at once, then the fast
  // retransmissions. Also starts the publisher. errc::invalid_state when a value is invalid.
  result<void> publish(std::vector<mms::data> values,
                       std::optional<model::timestamp> when = std::nullopt);
  // Publishes only when the values differ from the current ones (data change detection);
  // returns whether an event was generated.
  result<bool> update(std::vector<mms::data> values,
                      std::optional<model::timestamp> when = std::nullopt);
  // Changes ndsCom / simulation for the next messages (no new event).
  void set_nds_com(bool on);
  void set_simulation(bool on);

  [[nodiscard]] const publisher_config& config() const noexcept;
  [[nodiscard]] publisher_stats stats() const;

  struct impl;
  explicit publisher(std::shared_ptr<impl> p) noexcept;

 private:
  std::shared_ptr<impl> impl_;
};

}  // namespace openiec61850::goose
