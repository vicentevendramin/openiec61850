#pragma once

#include <cstdint>
#include <memory>

#include <asio/any_io_executor.hpp>

#include "openiec61850/goose/link.hpp"
#include "openiec61850/goose/subscriber.hpp"
#include "openiec61850/goose/sv_subscriber.hpp"

// Reads one link and dispatches GOOSE and SV frames to the subscriptions registered on it.
// Every frame is decoded once and offered to the matching subscriptions; it is not copied for
// subscriptions that do not match.
//
// Threading: the receive loop and every subscription run on one strand of the link's executor.
// subscribe() and stop() are safe from any thread.

namespace openiec61850::goose {

struct receiver_stats {
  std::uint64_t frames = 0;
  std::uint64_t malformed = 0;  // GOOSE / SV frames that failed to decode
  std::uint64_t unmatched = 0;  // decoded, but no subscription wanted them
  std::uint64_t other = 0;      // other EtherTypes
};

class receiver {
 public:
  [[nodiscard]] static std::shared_ptr<receiver> create(std::shared_ptr<link> l);
  ~receiver();  // stops
  receiver(const receiver&) = delete;
  receiver& operator=(const receiver&) = delete;

  // Starts the receive loop (no-op when running).
  void start();
  // Stops the loop and closes every subscription; the link is left open.
  void stop();

  [[nodiscard]] std::shared_ptr<subscriber> subscribe(subscriber_config config);
  [[nodiscard]] std::shared_ptr<sv::subscriber> subscribe(sv::subscriber_config config);

  [[nodiscard]] receiver_stats stats() const;
  [[nodiscard]] asio::any_io_executor get_executor() const;

  struct impl;
  explicit receiver(std::shared_ptr<impl> p) noexcept;

 private:
  std::shared_ptr<impl> impl_;
};

}  // namespace openiec61850::goose
