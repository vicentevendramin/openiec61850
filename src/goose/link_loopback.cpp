#include <algorithm>
#include <atomic>
#include <mutex>
#include <vector>

#include <asio/as_tuple.hpp>
#include <asio/experimental/concurrent_channel.hpp>
#include <asio/use_awaitable.hpp>

#include "openiec61850/goose/link.hpp"

namespace openiec61850::goose {

using channel_type = asio::experimental::concurrent_channel<void(asio::error_code, byte_buffer)>;

struct loopback_link::impl {
  impl(asio::any_io_executor e, mac_address a, std::size_t capacity)
      : ex(std::move(e)), addr(a), channel(ex, capacity == 0 ? 1 : capacity) {}

  asio::any_io_executor ex;
  mac_address addr;
  channel_type channel;
  std::atomic<std::uint64_t> dropped{0};
  std::atomic<bool> closed{false};
  std::weak_ptr<loopback_network::impl> network;
};

struct loopback_network::impl {
  std::mutex mutex;
  std::vector<std::weak_ptr<loopback_link::impl>> links;
  std::function<bool(byte_view, const mac_address&)> filter;
  std::atomic<std::uint64_t> sent{0};

  void deliver(const loopback_link::impl* from, byte_view frame) {
    std::vector<std::shared_ptr<loopback_link::impl>> targets;
    std::function<bool(byte_view, const mac_address&)> f;
    {
      std::lock_guard lock{mutex};
      std::erase_if(links, [](const auto& w) { return w.expired(); });
      for (const auto& w : links) {
        if (auto l = w.lock(); l && l.get() != from && !l->closed) targets.push_back(std::move(l));
      }
      f = filter;
    }
    ++sent;
    for (const auto& l : targets) {
      if (f && !f(frame, l->addr)) continue;
      if (!l->channel.try_send(asio::error_code{}, byte_buffer(frame.begin(), frame.end()))) {
        ++l->dropped;
      }
    }
  }
};

std::shared_ptr<loopback_network> loopback_network::create() {
  return std::make_shared<loopback_network>(std::make_shared<impl>());
}

std::shared_ptr<loopback_link> loopback_network::attach(asio::any_io_executor ex,
                                                        mac_address address,
                                                        std::size_t queue_capacity) {
  auto li = std::make_shared<loopback_link::impl>(std::move(ex), address, queue_capacity);
  li->network = impl_;
  {
    std::lock_guard lock{impl_->mutex};
    impl_->links.push_back(li);
  }
  return std::make_shared<loopback_link>(std::move(li));
}

void loopback_network::set_filter(
    std::function<bool(byte_view frame, const mac_address& to)> filter) {
  std::lock_guard lock{impl_->mutex};
  impl_->filter = std::move(filter);
}

std::uint64_t loopback_network::frames_sent() const noexcept { return impl_->sent; }

loopback_link::~loopback_link() { close(); }

asio::any_io_executor loopback_link::get_executor() const { return impl_->ex; }

mac_address loopback_link::address() const noexcept { return impl_->addr; }

result<void> loopback_link::send(byte_view frame) {
  if (impl_->closed) return errc::invalid_state;
  auto net = impl_->network.lock();
  if (!net) return errc::invalid_state;
  net->deliver(impl_.get(), frame);
  return {};
}

asio::awaitable<result<std::size_t>> loopback_link::receive(std::span<std::uint8_t> buffer) {
  auto self = impl_;
  if (self->closed) co_return result<std::size_t>(errc::invalid_state);
  auto [ec, frame] = co_await self->channel.async_receive(asio::as_tuple(asio::use_awaitable));
  if (ec) {
    if (self->closed) co_return result<std::size_t>(asio::error::operation_aborted);
    co_return result<std::size_t>(ec);
  }
  const std::size_t n = std::min(frame.size(), buffer.size());
  std::copy_n(frame.begin(), n, buffer.begin());
  co_return n;
}

void loopback_link::close() noexcept {
  if (impl_->closed.exchange(true)) return;
  impl_->channel.close();
}

std::uint64_t loopback_link::dropped() const noexcept { return impl_->dropped; }

}  // namespace openiec61850::goose
