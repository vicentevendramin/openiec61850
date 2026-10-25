# Getting started

openiec61850 is a C++20 library with a Python `asyncio` API on top of it. Both expose the same
features (binding parity, ADR 0002). The examples below talk to a server at `10.0.0.5:102`.

## Requirements

- C++20 compiler (GCC 13+, Clang 17+ or MSVC 19.38+), CMake 3.25+, Ninja.
- [vcpkg](https://github.com/microsoft/vcpkg) with `VCPKG_ROOT` set. Dependencies (Asio
  standalone, pugixml, optionally OpenSSL 3) come from `vcpkg.json` in manifest mode (ADR 0005).
- Python 3.10+ for the Python package.

## Python

```bash
pip install .
```

```python
import asyncio
import openiec61850 as iec

async def main():
    async with await iec.Client.connect("10.0.0.5") as client:
        for ld in await client.server_directory():
            print(ld, await client.logical_device_directory(ld))

        print(await client.read("IED1LD0/MMXU1.TotW.mag.f[MX]"))
        await client.write("IED1LD0/MMXU1.TotW.db[CF]", 100)

        async with await client.enable_reporting("IED1LD0/LLN0.urcb01[RP]", gi=True) as reports:
            async for report in reports:
                for entry in report.entries:
                    print(report.seq_num, entry.reference, entry.value, entry.reason)

asyncio.run(main())
```

`openiec61850.sync.Client` offers the same methods as a blocking facade for scripts and REPLs.
Pass `recovery=True` to `connect()` to have the association (and its RCBs) restored after a
connection loss.

### A first server

```python
import asyncio
import openiec61850 as iec
from openiec61850 import FC, BasicType as B, TrgOps

b = iec.ModelBuilder()
ld = b.logical_device("IED1LD0")
lln0 = ld.logical_node("LLN0")
lln0.data_object("Mod").attribute("stVal", FC.ST, B.ENUMERATED, value=1)
ggio = ld.logical_node("GGIO1")
ind = ggio.data_object("Ind1")
ind.attribute("stVal", FC.ST, B.BOOLEAN, triggers=TrgOps.DATA_CHANGE)
ind.attribute("q", FC.ST, B.QUALITY, triggers=TrgOps.QUALITY_CHANGE)
ind.attribute("t", FC.ST, B.TIMESTAMP)
ggio.data_object("Set").attribute("setVal", FC.SP, B.INT32, value=7)
lln0.data_set("DS1", ["IED1LD0/GGIO1.Ind1[ST]"])
lln0.report_control(iec.ReportControl("urcb01", data_set="DS1",
                                      trg_ops=TrgOps.DATA_CHANGE | TrgOps.GENERAL_INTERROGATION))
model = b.build()               # or: iec.Model.from_scl("bay.cid"); see model.diagnostics

def on_write(association, ref, value):
    # SP / SV / CF / DC / BL / SG / SE writes by clients; None accepts.
    return iec.DataAccessError.OBJECT_VALUE_INVALID if value < 0 else None

async def main():
    async with await iec.Server.start(model, "0.0.0.0", 102, on_write=on_write) as server:
        while True:
            server.update("IED1LD0/GGIO1.Ind1.stVal", True)       # reports follow the TrgOps
            await asyncio.sleep(1)

asyncio.run(main())
```

- `update()` / `update_many()` take plain Python values typed from the model, never block and
  may be called from any thread; `await server.read(ref)` returns the current value.
- Hooks (`on_write`, `on_control`, `authorize`) are called on the native I/O thread, which waits
  for their answer: keep them short and non-blocking. For a long Operate, return an awaitable from
  `on_control` (or make it `async def`): it runs on the event loop and its `ControlResult`
  completes the command (CommandTermination with enhanced security). Alternatively return
  `ControlResult.pending()` and call `request.complete(...)` later from any thread. Select and
  Cancel must be answered at once.
- `openiec61850.sync.Server.start(...)` is the blocking variant.

## C++

### Building

```bash
export VCPKG_ROOT=~/vcpkg
cmake --preset release            # or dev / asan; see CMakePresets.json
cmake --build --preset release
ctest --preset release
```

There are no install rules yet. To use the library from another CMake project, add the source
tree as a subdirectory and link `openiec61850::openiec61850` (`interop/runner/CMakeLists.txt`
does exactly this and is a working template):

```cmake
set(VCPKG_MANIFEST_DIR "${OPENIEC61850_ROOT}" CACHE PATH "")      # before project()
set(OPENIEC61850_BUILD_TESTS OFF CACHE BOOL "" FORCE)
project(my_app LANGUAGES CXX)
add_subdirectory(${OPENIEC61850_ROOT} openiec61850 EXCLUDE_FROM_ALL)
target_link_libraries(my_app PRIVATE openiec61850::openiec61850)
```

### A first client

Every ACSI service of `openiec61850::client::client` is a coroutine (`asio::awaitable`) returning
`openiec61850::result<T>` (a value or a `std::error_code`; no exceptions on the protocol path).

```cpp
#include <cstdio>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/this_coro.hpp>

#include "openiec61850/client/client.hpp"

namespace client = openiec61850::client;
namespace model = openiec61850::model;

asio::awaitable<void> run() {
  client::client_options options;
  options.association.host = "10.0.0.5";
  options.association.port = 102;

  auto c = co_await client::client::connect(co_await asio::this_coro::executor, options);
  if (!c) {
    std::printf("connect: %s\n", c.error().message().c_str());
    co_return;
  }

  if (auto lds = co_await c->get_server_directory()) {
    for (const auto& ld : *lds) std::printf("LD %s\n", ld.c_str());
  }

  auto ref = model::object_reference::parse("IED1LD0/MMXU1.TotW.mag.f[MX]");
  if (auto v = co_await c->read(*ref)) {
    if (auto f = client::to_float(*v)) std::printf("TotW = %f\n", static_cast<double>(*f));
  }

  auto rcb = model::object_reference::parse("IED1LD0/LLN0.urcb01[RP]");
  client::report_settings settings;
  settings.general_interrogation = true;
  if (co_await c->enable_reporting(*rcb, settings)) {
    if (auto r = co_await c->next_report()) {
      for (const auto& e : r->entries) std::printf("%s\n", e.data_reference.c_str());
    }
  }

  (void)co_await c->release();
}

int main() {
  asio::io_context ctx;
  asio::co_spawn(ctx, run(), asio::detached);
  ctx.run();
}
```

Notes:

- References use the IEC 61850 form `LD/LN.DO.DA[FC]`; `read()` / `write()` need an FC.
- Requests may be issued concurrently on one client; they share the association's outstanding
  request slots.
- Code that cannot use coroutines bridges with `transport::spawn(c.get_executor(), c.read(ref),
  handler)`; the handler runs on the I/O thread.
- Controls: `c->operate(object, mms::data::boolean(true))` picks direct / SBO / enhanced security
  from `CF.ctlModel`; `c->get_control(object)` returns a handle for step-by-step select / operate
  / cancel (see `include/openiec61850/client/control.hpp`).
- The generic MMS layer (`openiec61850/mms/*.hpp`) is public for diagnostics and for servers that
  do not follow IEC 61850-8-1 exactly.

## Next

- [Architecture overview](architecture.md)
- [Contributing: benchmarks and interop](contributing.md)
- [Glossary](../../GLOSSARY.md) and [ADRs](../adr/)
