#pragma once

#include <nanobind/nanobind.h>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "openiec61850/client/report.hpp"
#include "openiec61850/client/types.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/model/object_reference.hpp"
#include "openiec61850/transport/tls.hpp"

// Conversions between C++ values and the plain Python values the pure Python layer
// (openiec61850/_values.py, _client.py) builds its public types from. GIL held.
//
// MMS Data travels as tagged tuples whose first element is the mms::data_type value:
//   (1, [elements]) array            (2, [components]) structure
//   (3, bool)                        (4, bytes, bit_count) bit-string
//   (5, int) integer                 (6, int) unsigned
//   (7, float, is_double)            (9, bytes) octet-string
//   (10, str) visible-string         (11, str) generalized-time
//   (12, ms_of_day, days | None)     (13, int) bcd
//   (14, bytes, bit_count)           (15, (arcs...)) objId
//   (16, str) MMSString              (17, seconds, fraction, quality) utc-time

namespace openiec61850::python {

namespace nb = nanobind;

nb::object data_to_py(const mms::data& d);
// Raises TypeError / ValueError for a malformed tagged value.
mms::data data_from_py(nb::handle h);

nb::bytes to_bytes(byte_view b);
byte_buffer bytes_from_py(nb::handle h);

// Raises ValueError for an invalid reference.
model::object_reference ref_from_py(nb::handle h, const model::parse_options& opts);
nb::object ref_to_py(const model::object_reference& r);
nb::object opt_ref_to_py(const std::optional<model::object_reference>& r);

std::chrono::milliseconds seconds_from_py(nb::handle h);

nb::object entry_time_to_py(const model::entry_time& t);
model::entry_time entry_time_from_py(nb::handle h);
model::entry_id entry_id_from_py(nb::handle h);

nb::object directory_to_py(const client::logical_node_directory& d);
nb::object definition_to_py(const client::data_definition& d);
nb::object rcb_values_to_py(const client::rcb_values& v);
nb::object report_to_py(const client::report& r);
nb::object event_to_py(const client::connection_event& e);
nb::object association_info_to_py(const association::association_info& i);

// Setting groups, logs, files and GoCBs (client/types.hpp). Times of files are POSIX seconds.
nb::object timestamp_to_py(const std::optional<model::timestamp>& t);
nb::object sgcb_values_to_py(const client::sgcb_values& v);
nb::object lcb_values_to_py(const client::lcb_values& v);
// [(entry_id bytes, (ms_of_day, days), [(reference, tagged value, reason raw | None)])]
nb::object log_entries_to_py(std::vector<client::log_entry> v);
nb::object file_entry_to_py(const client::file_entry& e);
nb::object gocb_values_to_py(const client::gocb_values& v);
client::lcb_settings lcb_settings_from_py(nb::handle d, const model::parse_options& opts);
client::gocb_settings gocb_settings_from_py(nb::handle d, const model::parse_options& opts);

client::report_settings report_settings_from_py(nb::handle d, const model::parse_options& opts);
client::rcb_settings rcb_settings_from_py(nb::handle d, const model::parse_options& opts);
client::client_options client_options_from_py(nb::handle d);
// The native form of openiec61850.TlsConfig; raises when it cannot be loaded.
std::shared_ptr<transport::tls_context> tls_context_from_py(nb::handle config, bool server);
// A dict for openiec61850.TlsSession, or None.
nb::object tls_session_to_py(const std::optional<transport::tls_session_info>& session);

}  // namespace openiec61850::python
