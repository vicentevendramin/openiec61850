#pragma once

#include "openiec61850/scl/diagnostics.hpp"
#include "openiec61850/scl/document.hpp"

namespace openiec61850::scl::detail {

// Cross-reference checks of a parsed document (see load.hpp).
void validate(const document& doc, diagnostics& diags);

}  // namespace openiec61850::scl::detail
