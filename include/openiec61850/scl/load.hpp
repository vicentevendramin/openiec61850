#pragma once

#include <cstddef>
#include <filesystem>
#include <string_view>

#include "openiec61850/core/result.hpp"
#include "openiec61850/scl/diagnostics.hpp"
#include "openiec61850/scl/document.hpp"

// Loading ICD / IID / CID / SCD / SSD files (IEC 61850-6 Ed.1, Ed.2, Ed.2.1).
//
// Elements are recognised by local name in the SCL namespace (http://www.iec.ch/61850/2003/SCL,
// with any prefix) or in no namespace at all, so files that omit the xmlns declaration still load.
// Elements of other namespaces (vendor extensions) and <Private> are skipped. External entities
// and DTDs are never processed.
//
// Besides parsing, loading validates the document: required attributes, names, duplicate names,
// type references of DataTypeTemplates (missing or circular types, bType, fc), LN types,
// data set references of control blocks and EnumType literals of default values. Instantiation
// (instance.hpp) checks what depends on a particular IED: DOI/DAI paths and FCDAs.
//
// Lenient mode (default): every problem is a diagnostic; constructs with errors are dropped or
// kept with defaults, and the document is returned unless the XML is not well-formed or the root
// is not <SCL>. Strict mode: any error-level diagnostic fails the load with
// errc::malformed_encoding; the diagnostics still describe every problem.

namespace openiec61850::scl {

struct load_options {
  bool strict = false;
  std::size_t max_input_size = std::size_t{512} * 1024 * 1024;
  // Nesting of DOI/SDI elements and of Services children.
  std::size_t max_depth = 64;
  // Diagnostics stored (further ones are only counted); 0 = unlimited.
  std::size_t max_diagnostics = 10000;
};

struct load_result {
  // Fails with errc::malformed_encoding (bad XML, not SCL, strict-mode errors),
  // errc::length_overflow (input larger than max_input_size) or a system error (file I/O).
  result<document> doc;
  diagnostics diags;

  [[nodiscard]] bool ok() const noexcept { return doc.has_value(); }
};

[[nodiscard]] load_result load_string(std::string_view xml, const load_options& opts = {});
[[nodiscard]] load_result load_file(const std::filesystem::path& path,
                                    const load_options& opts = {});

}  // namespace openiec61850::scl
