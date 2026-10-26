#pragma once

#include <nanobind/nanobind.h>

namespace openiec61850::python {

void bind_client(nanobind::module_& m);
void bind_model(nanobind::module_& m);
void bind_server(nanobind::module_& m);
void bind_goose(nanobind::module_& m);

}  // namespace openiec61850::python
