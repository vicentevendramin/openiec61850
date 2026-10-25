#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/goose/frame.hpp"

// Layer 2 links for the GOOSE / SV Publicador and Assinante.
//
// A link sends and receives whole Ethernet frames (no FCS). Two implementations:
//  - raw_socket_link: a Linux AF_PACKET socket bound to one interface (needs CAP_NET_RAW);
//  - loopback_link: an in-memory broadcast domain for tests and simulations (no privileges).
// Other transports (pcap, a TAP device, a hardware offload) can implement the interface.

namespace openiec61850::goose {

class link {
 public:
  link() = default;
  link(const link&) = delete;
  link& operator=(const link&) = delete;
  virtual ~link() = default;

  [[nodiscard]] virtual asio::any_io_executor get_executor() const = 0;

  // Hardware address of the link, used as the default source address of publishers.
  [[nodiscard]] virtual mac_address address() const noexcept = 0;

  // Queues one frame for transmission without blocking. Safe from any thread. Fails with
  // errc::invalid_state once closed, or with the system error (e.g. would_block when the
  // transmit queue is full).
  [[nodiscard]] virtual result<void> send(byte_view frame) = 0;

  // Waits for the next frame and copies it into `buffer`; returns its size. A frame larger than
  // the buffer is truncated (the size returned is the copied size). Only one receive may be
  // outstanding. Completes with asio::error::operation_aborted (or errc::invalid_state) once the
  // link is closed. The awaiting coroutine runs on the caller's executor.
  [[nodiscard]] virtual asio::awaitable<result<std::size_t>> receive(
      std::span<std::uint8_t> buffer) = 0;

  // Stops the link: a pending receive completes and later sends fail. Safe from any thread.
  virtual void close() noexcept = 0;
};

// ------------------------------------------------------------------ loopback

class loopback_link;

// A broadcast domain shared by loopback links: every frame sent on one link is delivered to all
// the other open links of the network (never back to the sender). Thread-safe.
class loopback_network : public std::enable_shared_from_this<loopback_network> {
 public:
  [[nodiscard]] static std::shared_ptr<loopback_network> create();

  // A new link on `ex`. `queue_capacity` frames are buffered per link; later frames are dropped
  // and counted (loopback_link::dropped()).
  [[nodiscard]] std::shared_ptr<loopback_link> attach(asio::any_io_executor ex, mac_address address,
                                                      std::size_t queue_capacity = 1024);

  // Test hook called for every frame and receiving link (by its address); returning false drops
  // the frame (loss injection). Called on the sender's thread.
  void set_filter(std::function<bool(byte_view frame, const mac_address& to)> filter);

  // Frames sent on the network so far.
  [[nodiscard]] std::uint64_t frames_sent() const noexcept;

  struct impl;
  explicit loopback_network(std::shared_ptr<impl> p) noexcept : impl_(std::move(p)) {}

 private:
  std::shared_ptr<impl> impl_;
};

class loopback_link final : public link {
 public:
  ~loopback_link() override;

  [[nodiscard]] asio::any_io_executor get_executor() const override;
  [[nodiscard]] mac_address address() const noexcept override;
  [[nodiscard]] result<void> send(byte_view frame) override;
  [[nodiscard]] asio::awaitable<result<std::size_t>> receive(
      std::span<std::uint8_t> buffer) override;
  void close() noexcept override;

  // Frames dropped because the receive queue was full.
  [[nodiscard]] std::uint64_t dropped() const noexcept;

  struct impl;
  explicit loopback_link(std::shared_ptr<impl> p) noexcept : impl_(std::move(p)) {}

 private:
  std::shared_ptr<impl> impl_;
};

// ------------------------------------------------------------------ raw socket (Linux)

struct raw_socket_options {
  std::string interface_name;  // e.g. "eth0"
  // Kernel (classic BPF) filter on the EtherType, looking through one 802.1Q tag. Empty: all.
  std::vector<std::uint16_t> ether_types{ethertype_goose, ethertype_sv};
  // PACKET_MR_PROMISC.
  bool promiscuous = false;
  // PACKET_MR_ALLMULTI: receive every multicast frame (simplest for subscribers).
  bool all_multicast = true;
  // PACKET_MR_MULTICAST memberships, when all_multicast is off.
  std::vector<mac_address> multicast_groups;
  // Deliver the frames this host sends (seen by packet sockets as PACKET_OUTGOING).
  bool receive_outgoing = false;
  // SO_PRIORITY for sent frames (maps to the egress queue / VLAN PCP on some drivers); -1 keeps
  // the default.
  int socket_priority = -1;
};

// Linux AF_PACKET link. Frames are received with their 802.1Q tag even when the NIC stripped it
// (it is rebuilt from PACKET_AUXDATA). Not available on other platforms (open() fails with
// errc::unsupported).
class raw_socket_link final : public link {
 public:
  // Errors: errc::unsupported (not Linux), std::errc::operation_not_permitted without
  // CAP_NET_RAW, std::errc::no_such_device for an unknown interface, other system errors.
  [[nodiscard]] static result<std::shared_ptr<raw_socket_link>> open(asio::any_io_executor ex,
                                                                     raw_socket_options options);
  ~raw_socket_link() override;

  [[nodiscard]] asio::any_io_executor get_executor() const override;
  [[nodiscard]] mac_address address() const noexcept override;
  [[nodiscard]] result<void> send(byte_view frame) override;
  [[nodiscard]] asio::awaitable<result<std::size_t>> receive(
      std::span<std::uint8_t> buffer) override;
  void close() noexcept override;

  [[nodiscard]] int interface_index() const noexcept;

  struct impl;
  explicit raw_socket_link(std::shared_ptr<impl> p) noexcept;

 private:
  std::shared_ptr<impl> impl_;
};

}  // namespace openiec61850::goose
