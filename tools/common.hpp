#pragma once

#include <cstdint>
#include <initializer_list>
#include <memory>
#include <utility>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/transport/tls.hpp"

// Helpers shared by the command-line tools: text form of MMS values and a tiny option parser.

namespace openiec61850::tools {

// One line of text for a value: true/false, integers, floats, "strings", bit strings as
// b'0101' (bit 0 first), octet strings as hex, UtcTime as ISO 8601, {structures}, [arrays].
[[nodiscard]] std::string format_value(const mms::data& v);

// Parses `text` as a value of MMS type `type` (bit strings: `bits` wide). Accepts true/false/1/0,
// decimal integers, floats, strings as is, bit strings as 0/1 digits (optionally b'...'), octet
// strings as hex digits. errc::malformed_encoding for text that does not fit, errc::unsupported for
// structured types.
[[nodiscard]] result<mms::data> parse_value(std::string_view text, mms::data_type type,
                                            std::size_t bits = 0);
// The same, taking the type (and bit-string width) from an existing value.
[[nodiscard]] result<mms::data> parse_value_like(std::string_view text, const mms::data& like);

// "--name value" / "--flag" options followed by positional arguments.
class arguments {
 public:
  // Options named in `valued` take a value; every other "--x" is a flag.
  arguments(int argc, char** argv, std::initializer_list<std::string_view> valued);

  // The value of "--name V" or "--name=V" (the last one given).
  [[nodiscard]] std::optional<std::string> value(std::string_view name) const;
  [[nodiscard]] bool flag(std::string_view name) const;
  [[nodiscard]] const std::vector<std::string>& positional() const noexcept { return positional_; }
  // Options seen that are not in `known` (for usage errors).
  [[nodiscard]] std::optional<std::string> unknown(std::initializer_list<std::string_view> known) const;
  // A valued option given last without its value.
  [[nodiscard]] std::optional<std::string> missing_value() const { return missing_; }

 private:
  std::vector<std::pair<std::string, std::optional<std::string>>> options_;
  std::vector<std::string> positional_;
  std::optional<std::string> missing_;
};

// Parses a decimal number in [min, max].
[[nodiscard]] std::optional<long long> parse_number(std::string_view text, long long min,
                                                    long long max);

// The context for the --tls* options: null without --tls, errc::unsupported without TLS support.
[[nodiscard]] result<std::shared_ptr<transport::tls_context>> tls_from_arguments(const arguments& args,
                                                                                 bool server);

}  // namespace openiec61850::tools
