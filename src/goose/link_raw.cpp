#include <algorithm>
#include <atomic>
#include <cstring>

#include <asio/as_tuple.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>

#include "openiec61850/goose/link.hpp"

#if defined(__linux__)
#include <arpa/inet.h>
#include <cerrno>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <asio/generic/raw_protocol.hpp>
#endif

namespace openiec61850::goose {

#if defined(__linux__)

namespace {

std::error_code last_error() noexcept { return {errno, std::system_category()}; }

// Classic BPF: accept the frame when its EtherType, directly or after one 802.1Q tag, is one of
// `types`. With VLAN offload the kernel runs the filter on the untagged frame, which the first
// branch covers.
std::vector<sock_filter> build_filter(const std::vector<std::uint16_t>& types) {
  const auto n = types.size();
  std::vector<sock_filter> prog;
  auto stmt = [&](std::uint16_t code, std::uint32_t k) {
    prog.push_back(sock_filter{code, 0, 0, k});
  };
  auto jump = [&](std::uint16_t code, std::uint32_t k, std::size_t jt, std::size_t jf) {
    prog.push_back(sock_filter{code, static_cast<std::uint8_t>(jt), static_cast<std::uint8_t>(jf), k});
  };
  // Layout: 0 ldh[12]; 1 jeq vlan; 2..2+n-1 jeq type; 2+n ret 0; 3+n ldh[16];
  // 4+n..4+2n-1 jeq type; 4+2n ret 0; 5+2n ret accept.
  const std::size_t accept = 5 + 2 * n;
  stmt(BPF_LD | BPF_H | BPF_ABS, 12);
  jump(BPF_JMP | BPF_JEQ | BPF_K, ethertype_vlan, (3 + n) - 2, 0);
  for (std::size_t i = 0; i < n; ++i) {
    const std::size_t at = 2 + i;
    jump(BPF_JMP | BPF_JEQ | BPF_K, types[i], accept - at - 1, 0);
  }
  stmt(BPF_RET | BPF_K, 0);
  stmt(BPF_LD | BPF_H | BPF_ABS, 16);
  for (std::size_t i = 0; i < n; ++i) {
    const std::size_t at = 4 + n + i;
    jump(BPF_JMP | BPF_JEQ | BPF_K, types[i], accept - at - 1, 0);
  }
  stmt(BPF_RET | BPF_K, 0);
  stmt(BPF_RET | BPF_K, 0x40000);
  return prog;
}

}  // namespace

struct raw_socket_link::impl {
  impl(asio::any_io_executor e, raw_socket_options o) : ex(std::move(e)), socket(ex), options(std::move(o)) {}

  asio::any_io_executor ex;
  asio::generic::raw_protocol::socket socket;
  raw_socket_options options;
  int fd = -1;
  int ifindex = 0;
  mac_address addr{};
  std::atomic<bool> closed{false};
};

result<std::shared_ptr<raw_socket_link>> raw_socket_link::open(asio::any_io_executor ex,
                                                               raw_socket_options options) {
  if (options.ether_types.size() > 100) return errc::invalid_state;  // BPF jump offsets are 8 bits
  const int fd = ::socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
  if (fd < 0) return last_error();
  auto fail = [fd](std::error_code ec) {
    ::close(fd);
    return ec;
  };

  const unsigned ifindex = ::if_nametoindex(options.interface_name.c_str());
  if (ifindex == 0) return fail(std::make_error_code(std::errc::no_such_device));

  ifreq ifr{};
  std::strncpy(ifr.ifr_name, options.interface_name.c_str(), IFNAMSIZ - 1);
  mac_address addr{};
  if (::ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
    std::memcpy(addr.data(), ifr.ifr_hwaddr.sa_data, 6);
  }

  const int one = 1;
  if (::setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, &one, sizeof one) != 0) {
    return fail(last_error());
  }
  if (!options.ether_types.empty()) {
    auto prog = build_filter(options.ether_types);
    sock_fprog fprog{static_cast<unsigned short>(prog.size()), prog.data()};
    if (::setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof fprog) != 0) {
      return fail(last_error());
    }
  }
  if (options.socket_priority >= 0 &&
      ::setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &options.socket_priority,
                   sizeof options.socket_priority) != 0) {
    return fail(last_error());
  }

  sockaddr_ll sll{};
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = static_cast<int>(ifindex);
  if (::bind(fd, reinterpret_cast<const sockaddr*>(&sll), sizeof sll) != 0) {  // NOLINT
    return fail(last_error());
  }

  auto membership = [&](unsigned short type, const mac_address* mac) {
    packet_mreq mr{};
    mr.mr_ifindex = static_cast<int>(ifindex);
    mr.mr_type = type;
    if (mac != nullptr) {
      mr.mr_alen = 6;
      std::memcpy(mr.mr_address, mac->data(), 6);
    }
    return ::setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof mr) == 0;
  };
  if (options.promiscuous && !membership(PACKET_MR_PROMISC, nullptr)) return fail(last_error());
  if (options.all_multicast && !membership(PACKET_MR_ALLMULTI, nullptr)) {
    return fail(last_error());
  }
  for (const auto& g : options.multicast_groups) {
    if (!membership(PACKET_MR_MULTICAST, &g)) return fail(last_error());
  }

  auto p = std::make_shared<impl>(std::move(ex), std::move(options));
  asio::error_code ec;
  p->socket.assign(asio::generic::raw_protocol(AF_PACKET, htons(ETH_P_ALL)), fd, ec);
  if (ec) return fail(ec);
  p->fd = fd;
  p->ifindex = static_cast<int>(ifindex);
  p->addr = addr;
  return std::make_shared<raw_socket_link>(std::move(p));
}

raw_socket_link::raw_socket_link(std::shared_ptr<impl> p) noexcept : impl_(std::move(p)) {}

raw_socket_link::~raw_socket_link() {
  impl_->closed = true;
  asio::error_code ec;
  impl_->socket.close(ec);
}

asio::any_io_executor raw_socket_link::get_executor() const { return impl_->ex; }

mac_address raw_socket_link::address() const noexcept { return impl_->addr; }

int raw_socket_link::interface_index() const noexcept { return impl_->ifindex; }

result<void> raw_socket_link::send(byte_view frame) {
  if (impl_->closed) return errc::invalid_state;
  const auto n = ::send(impl_->fd, frame.data(), frame.size(), MSG_DONTWAIT);
  if (n < 0) return last_error();
  if (static_cast<std::size_t>(n) != frame.size()) {
    return std::make_error_code(std::errc::message_size);
  }
  return {};
}

asio::awaitable<result<std::size_t>> raw_socket_link::receive(std::span<std::uint8_t> buffer) {
  auto self = impl_;
  for (;;) {
    if (self->closed) co_return result<std::size_t>(asio::error::operation_aborted);
    sockaddr_ll from{};
    iovec iov{buffer.data(), buffer.size()};
    alignas(cmsghdr) std::uint8_t control[CMSG_SPACE(sizeof(tpacket_auxdata))];
    msghdr msg{};
    msg.msg_name = &from;
    msg.msg_namelen = sizeof from;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof control;
    const auto n = ::recvmsg(self->fd, &msg, MSG_DONTWAIT);
    if (n < 0) {
      if (errno == EINTR) continue;
      if (errno != EAGAIN && errno != EWOULDBLOCK) co_return result<std::size_t>(last_error());
      auto [ec] = co_await self->socket.async_wait(asio::socket_base::wait_read,
                                                   asio::as_tuple(asio::use_awaitable));
      if (ec) co_return result<std::size_t>(ec);
      continue;
    }
    if (from.sll_pkttype == PACKET_OUTGOING && !self->options.receive_outgoing) continue;
    std::size_t size = std::min(static_cast<std::size_t>(n), buffer.size());

    // Re-insert the 802.1Q tag stripped by VLAN offload.
    for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
      if (c->cmsg_level != SOL_PACKET || c->cmsg_type != PACKET_AUXDATA) continue;
      tpacket_auxdata aux{};
      std::memcpy(&aux, CMSG_DATA(c), sizeof aux);
      if ((aux.tp_status & TP_STATUS_VLAN_VALID) == 0 || size < 12) break;
      std::uint16_t tpid = ethertype_vlan;
#ifdef TP_STATUS_VLAN_TPID_VALID
      if ((aux.tp_status & TP_STATUS_VLAN_TPID_VALID) != 0) tpid = aux.tp_vlan_tpid;
#endif
      const std::size_t moved = std::min(size - 12, buffer.size() >= 16 ? buffer.size() - 16 : 0);
      std::memmove(buffer.data() + 16, buffer.data() + 12, moved);
      if (buffer.size() >= 16) {
        buffer[12] = static_cast<std::uint8_t>(tpid >> 8);
        buffer[13] = static_cast<std::uint8_t>(tpid & 0xFFU);
        buffer[14] = static_cast<std::uint8_t>(aux.tp_vlan_tci >> 8);
        buffer[15] = static_cast<std::uint8_t>(aux.tp_vlan_tci & 0xFFU);
        size = 16 + moved;
      }
      break;
    }
    co_return size;
  }
}

void raw_socket_link::close() noexcept {
  if (impl_->closed.exchange(true)) return;
  asio::post(impl_->ex, [self = impl_] {
    asio::error_code ec;
    self->socket.close(ec);
  });
}

#else  // !__linux__

struct raw_socket_link::impl {};

result<std::shared_ptr<raw_socket_link>> raw_socket_link::open(asio::any_io_executor,
                                                               raw_socket_options) {
  return errc::unsupported;
}
raw_socket_link::raw_socket_link(std::shared_ptr<impl> p) noexcept : impl_(std::move(p)) {}
raw_socket_link::~raw_socket_link() = default;
asio::any_io_executor raw_socket_link::get_executor() const { return {}; }
mac_address raw_socket_link::address() const noexcept { return {}; }
int raw_socket_link::interface_index() const noexcept { return 0; }
result<void> raw_socket_link::send(byte_view) { return errc::unsupported; }
asio::awaitable<result<std::size_t>> raw_socket_link::receive(std::span<std::uint8_t>) {
  co_return result<std::size_t>(errc::unsupported);
}
void raw_socket_link::close() noexcept {}

#endif

}  // namespace openiec61850::goose
