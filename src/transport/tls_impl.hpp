#pragma once

#include <asio/ip/tcp.hpp>
#include <asio/ssl/context.hpp>
#include <asio/ssl/stream.hpp>

#include "openiec61850/transport/tls.hpp"

namespace openiec61850::transport {

struct tls_context::impl {
  tls_config config;
  asio::ssl::context ssl{asio::ssl::context::tls};
};

using tls_stream = asio::ssl::stream<asio::ip::tcp::socket&>;

// Pins the expected certificate name on a stream that is about to shake hands.
[[nodiscard]] std::error_code set_expected_peer_name(tls_stream& stream, const std::string& name);
// Sets the name sent in the server_name extension. IP literals are not sent (RFC 6066 §3).
void set_server_name_indication(tls_stream& stream, const std::string& host);
[[nodiscard]] tls_session_info describe_session(tls_stream& stream);
// Asks for new traffic keys in both directions; sent with the next write. False on TLS 1.2.
bool request_key_update(tls_stream& stream);

}  // namespace openiec61850::transport
