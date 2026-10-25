#pragma once

#include <string_view>

#include "openiec61850/core/result.hpp"
#include "openiec61850/goose/publisher.hpp"
#include "openiec61850/goose/subscriber.hpp"
#include "openiec61850/goose/sv_publisher.hpp"
#include "openiec61850/goose/sv_subscriber.hpp"
#include "openiec61850/scl/document.hpp"

// Publisher / subscriber configuration from SCL (IEC 61850-6): the GSEControl or
// SampledValueControl of LN0 in IED `ied_name` / LD `ld_inst`, and its GSE / SMV address in the
// ConnectedAP of that IED (access point `ap_name`, or any when empty).
//
//   gocbRef  = <LDName>/LLN0$GO$<cbName>   (IEC 61850-8-1 §18.1.2.1, MMS form)
//   datSet   = <LDName>/LLN0$<datSet>
//   goID     = GSEControl appID, or gocbRef when absent
//   MinTime / MaxTime from <GSE>, APPID / MAC / VLAN from its <Address>
//
// Errors: errc::invalid_state when the IED, LD, control block or its GSE / SMV address is
// missing; errc::malformed_encoding for an invalid address (scl::parse_l2_address);
// errc::unsupported for a GSSE control block.

namespace openiec61850::goose {

[[nodiscard]] result<publisher_config> publisher_config_from_scl(const scl::document& doc,
                                                                 std::string_view ied_name,
                                                                 std::string_view ld_inst,
                                                                 std::string_view cb_name,
                                                                 std::string_view ap_name = {});

// Filters on APPID, destination and gocbRef; expects datSet, goID, confRev and the number of
// data set members. TAL margin and queue capacity keep their defaults.
[[nodiscard]] result<subscriber_config> subscriber_config_from_scl(const scl::document& doc,
                                                                   std::string_view ied_name,
                                                                   std::string_view ld_inst,
                                                                   std::string_view cb_name,
                                                                   std::string_view ap_name = {});

}  // namespace openiec61850::goose

namespace openiec61850::sv {

// svID, confRev, smpRate / smpMod / refrTm / datSet per SmvOpts, noASDU; smp_cnt_wrap is
// smpRate x `frequency_hz` for SmpPerPeriod, smpRate for SmpPerSec, 0 otherwise.
[[nodiscard]] result<publisher_config> publisher_config_from_scl(const scl::document& doc,
                                                                 std::string_view ied_name,
                                                                 std::string_view ld_inst,
                                                                 std::string_view cb_name,
                                                                 std::string_view ap_name = {},
                                                                 std::uint16_t frequency_hz = 50);

[[nodiscard]] result<subscriber_config> subscriber_config_from_scl(
    const scl::document& doc, std::string_view ied_name, std::string_view ld_inst,
    std::string_view cb_name, std::string_view ap_name = {}, std::uint16_t frequency_hz = 50);

}  // namespace openiec61850::sv
