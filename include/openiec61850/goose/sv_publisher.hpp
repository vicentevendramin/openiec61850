#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/goose/link.hpp"
#include "openiec61850/goose/sv.hpp"

// Sampled Values Publicador (IEC 61850-9-2 §8, MSVCB). Each sample becomes one ASDU; a frame is
// sent as soon as asdus_per_frame ASDUs are collected. smpCnt counts samples from 0 and wraps
// at smp_cnt_wrap (the number of samples per second for smpMod samples-per-period / -second,
// 9-2 §8.5.2), or at 65536 when it is 0.
//
// Two ways to drive it:
//  - push(): the application calls it once per sample from its own sampling loop (ideally a
//    real-time thread synchronised to the sampling clock); it encodes and sends synchronously on
//    the caller's thread, without allocating once warmed up.
//  - start(period, source): an Asio timer on the link's executor calls `source` once per period.
//    This is meant for tests and simulations: a steady_timer on a general-purpose OS has
//    jitter in the 10-100 us range and drifts with load, far from the 250 us / 208 us sample
//    period of 9-2 LE at 4000 / 4800 Hz, so it must not be used to emulate a merging unit on
//    a real process bus. The timer catches up (sends several samples at once) when late.

namespace openiec61850::sv {

struct publisher_config {
  mac_address destination = goose::sv_multicast_base;
  std::optional<mac_address> source;  // the link address when unset
  std::optional<vlan_tag> vlan = vlan_tag{};
  std::uint16_t app_id = goose::sv_app_id_default;
  bool simulation = false;  // Reserved1 S bit (Ed.2)

  std::string sv_id;
  std::optional<std::string> dat_set;  // "LD/LLN0$PhsMeas1" (SmvOpts dataSet)
  std::uint32_t conf_rev = 1;
  std::uint8_t smp_synch = smp_synch::none;
  std::optional<std::uint16_t> smp_rate;  // SmvOpts sampleRate
  std::optional<std::uint16_t> smp_mod;   // sent when set and not samples_per_period (Ed.2)
  bool refresh_time = false;              // SmvOpts refreshTime: refrTm in every ASDU
  std::uint16_t asdus_per_frame = 1;      // noASDU
  std::uint32_t smp_cnt_wrap = 4000;      // 0 = 65536
};

using sample_source = std::function<void(std::uint16_t smp_cnt, byte_buffer& seq_data)>;

struct publisher_stats {
  std::uint64_t samples = 0;
  std::uint64_t frames_sent = 0;
  std::uint64_t send_errors = 0;
  std::uint16_t next_smp_cnt = 0;
};

class publisher {
 public:
  // errc::invalid_state for an empty svID or asdus_per_frame 0.
  [[nodiscard]] static result<std::shared_ptr<publisher>> create(std::shared_ptr<goose::link> l,
                                                                 publisher_config config);
  ~publisher();
  publisher(const publisher&) = delete;
  publisher& operator=(const publisher&) = delete;

  // Adds one sample (seqData octets) with the next smpCnt; returns that smpCnt. Sends the frame
  // when it is complete (the send error, if any, is returned and counted). Not thread-safe:
  // call from one thread at a time, and not together with start().
  result<std::uint16_t> push(byte_view seq_data,
                             std::optional<mms::utc_time> refr_tm = std::nullopt);
  result<std::uint16_t> push(const le::samples& s,
                             std::optional<mms::utc_time> refr_tm = std::nullopt);

  // Timer-driven sampling (see above). errc::invalid_state for a zero period or no source; no-op
  // when already running.
  result<void> start(std::chrono::nanoseconds period, sample_source source);
  void stop();

  [[nodiscard]] const publisher_config& config() const noexcept;
  [[nodiscard]] publisher_stats stats() const;

  struct impl;
  explicit publisher(std::shared_ptr<impl> p) noexcept;

 private:
  std::shared_ptr<impl> impl_;
};

}  // namespace openiec61850::sv
