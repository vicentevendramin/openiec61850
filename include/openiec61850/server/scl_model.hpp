#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string_view>

// basic_type.hpp first (see the note in model/quality.hpp about -Wshadow).
#include "openiec61850/model/basic_type.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/scl/diagnostics.hpp"
#include "openiec61850/scl/document.hpp"
#include "openiec61850/scl/instance.hpp"
#include "openiec61850/scl/load.hpp"
#include "openiec61850/server/model.hpp"

// A server data model from an SCL file (ICD / IID / CID / SCD): the server of one IED access
// point is instantiated (scl::instantiate) and mapped onto model_builder:
//
//   LDevice / LN0 / LN                     logical devices and nodes (LLN0 first)
//   DO / SDO, DA / BDA                     data objects and attributes in template order, with
//                                          fc, bType (basic type and string size), count (arrays;
//                                          an array of DOs takes one node per element, counted
//                                          against instantiate.max_nodes) and dchg / qchg / dupd
//   DA / BDA <Val>, DAI <Val>              initial values (Enum values as their ord; Timestamp and
//                                          EntryTime as xs:dateTime; values of array elements by
//                                          index, DOI / SDI ix selecting an element of an array of
//                                          DOs; for FC SG / SE the value of the active setting
//                                          group)
//   DataSet / FCDA                         data sets (functionally constrained references)
//   ReportControl                          BRCB / URCB instances: with indexed="true" (the
//                                          default) RptEnabled max instances named name01,
//                                          name02... (IEC 61850-8-1 §17.2 / IEC 61850-6), with
//                                          indexed="false" one instance named as the control;
//                                          rptID, datSet, confRev, bufTime, intgPd, TrgOps and
//                                          OptFields as given
//
//   SettingControl (LLN0)                  the SGCB (numOfSGs, actSG); <Val sGroup> of FC SG
//                                          attributes give each group's initial value
//   LogControl                             LCBs (datSet, logEna, TrgOps, intgPd) and their logs
//                                          (logName in the LN given by prefix / lnClass / lnInst
//                                          of the LD given by ldInst, by default the same LD)
//   GSEControl (type GOOSE)                GoCBs (appID as GoID, datSet, confRev, fixedOffs) with
//                                          the Communication GSE address (MAC-Address, APPID,
//                                          VLAN-ID, VLAN-PRIORITY, MinTime, MaxTime)
//
// Control objects need nothing special: ctlModel and sboTimeout (FC CF) are ordinary attributes
// whose SCL values drive the server's control model.
//
// Not mapped: attributes whose bType has no basic type (INT64U, PhyComAddr, SvOptFlds,
// LogOptFlds), SMV and GSSE control blocks. In lenient mode (default) they are skipped with a warning diagnostic, as are
// values that do not fit their attribute; data set members referring to a skipped attribute are
// dropped (and a data set left empty, with the report controls using it). In strict mode any of
// them fails the load with errc::invalid_model.

namespace openiec61850::server {

struct scl_load_options {
  // load_model_file(): parsing options.
  scl::load_options load;
  scl::instantiate_options instantiate;
  // Fail (errc::invalid_model) instead of skipping what cannot be mapped (see above).
  bool strict = false;
  // Setting group whose <Val sGroup> initialise FC SG / SE attributes; 0: SettingControl actSG
  // of LLN0 (1 when absent).
  std::uint32_t setting_group = 0;
  // Upper bound for RptEnabled max (instance names have two digits).
  std::uint32_t max_report_instances = 99;
};

// The model of IED `ied` (the first IED of the document when empty), access point
// `access_point` (the first one with a server when empty). Errors: those of scl::instantiate
// (errc::invalid_state when the IED / access point / server does not exist,
// errc::malformed_encoding in strict instantiation...), errc::invalid_model (strict mode, or a
// model the builder refuses), the builder's errors. Problems are appended to `diags`.
[[nodiscard]] result<data_model> load_model(const scl::document& doc, std::string_view ied = {},
                                            std::string_view access_point = {},
                                            const scl_load_options& options = {},
                                            scl::diagnostics* diags = nullptr);

// Loads the file (scl::load_file) and then load_model(); the load diagnostics are appended to
// `diags` too.
[[nodiscard]] result<data_model> load_model_file(const std::filesystem::path& path,
                                                 std::string_view ied = {},
                                                 std::string_view access_point = {},
                                                 const scl_load_options& options = {},
                                                 scl::diagnostics* diags = nullptr);

}  // namespace openiec61850::server
