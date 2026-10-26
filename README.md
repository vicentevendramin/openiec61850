# openiec61850

A clean-room implementation of the IEC 61850 standard with a C++20 native core and a first-class Python API (`asyncio`), licensed under Apache-2.0.

> Status: early development. The API is not stable yet.

## Why

- **Permissive license**: Apache-2.0 and not derived from libiec61850 (GPLv3), so it can be used in closed-source products.
- **Binding parity**: every public feature of the native core is also available in Python.
- **Asynchronous**: the core runs its own I/O thread that never holds the GIL, and scales to many associations and many concurrent requests.

## Building

```bash
export VCPKG_ROOT=~/vcpkg
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

Python:

```bash
# The test-only fake-server extension (openiec61850._testing) is opt-in and never shipped in wheels.
pip install ".[test]" -Ccmake.define.OPENIEC61850_BUILD_PYTHON_TESTING=ON
pytest
```

## Python

The `asyncio` API is the primary one; `openiec61850.sync.Client` and `openiec61850.sync.Server`
are thin blocking facades with the same method names.

```python
import asyncio
import openiec61850 as iec

async def main():
    async with await iec.Client.connect("10.0.0.5", recovery=True) as client:
        print(await client.server_directory())
        print(await client.read("IED1LD0/MMXU1.TotW.mag.f[MX]"))        # 1.5
        # Plain values are typed from the server's data definition (fetched once);
        # typed wrappers such as iec.Float32 / iec.Int32 need no round trip.
        await client.write("IED1LD0/MMXU1.TotW.db[CF]", 100)

        async with await client.enable_reporting(
            "IED1LD0/LLN0.urcb01[RP]",
            opt_flds=iec.OptFlds.SEQUENCE_NUMBER | iec.OptFlds.REASON_FOR_INCLUSION,
            gi=True,
        ) as reports:
            async for report in reports:
                for entry in report.entries:
                    print(report.seq_num, entry.reference, entry.value, entry.reason)

        # Control (select-before-operate is driven by the object's ctlModel).
        breaker = await client.control("IED1LD1/XCBR1.Pos")
        try:
            await breaker.select_with_value(True)
            await breaker.operate(True, interlock_check=True,
                                  origin=iec.Originator(iec.OrCat.STATION_CONTROL, b"hmi"))
        except iec.ControlRefused as e:
            print("refused:", e.add_cause, e.last_appl_error)
        await client.operate("IED1LD1/GGIO1.SPCSO1", False)  # one-shot

asyncio.run(main())
```

A server is built from a model (programmatic or SCL) and driven with `update()` from any thread;
application hooks decide writes and commands:

```python
import asyncio
import openiec61850 as iec

model = iec.Model.from_scl("station.cid", ied="BAY1")        # or iec.ModelBuilder()...build()

async def on_control(request):                                  # Operates run on the event loop
    await asyncio.sleep(0.2)                                    # e.g. drive the breaker
    return iec.ControlResult.ok()                               # or .refused(iec.AddCause...)

async def main():
    async with await iec.Server.start(model, port=102, on_control=on_control,
                                      on_write=lambda assoc, ref, value: None) as server:
        server.update("Bay1Prot/MMXU1.Hz.mag.f", 50.02, quality=iec.Quality())
        await server.wait_stopped()

asyncio.run(main())
```

Setting groups, logs, files and GoCBs on the client side; SGCB, LCBs, logs, GoCBs and a file
store on the server side:

```python
async with await iec.Client.connect("10.0.0.5") as client:
    await client.select_active_sg("IED1LD0", 2)
    await client.select_edit_sg("IED1LD0", 3)
    await client.set_edit_sg_value("IED1LD0/PTOC1.StrVal.setMag.f[SE]", 3.5)
    await client.confirm_edit_sg_values("IED1LD0")
    for entry in await client.query_log_by_time("IED1LD0/LLN0.EventLog"):
        print(entry.entry_id, entry.time, entry.values())
    for f in await client.list_files("COMTRADE"):
        await client.download_file(f.name, f.name.replace("/", "_"))    # streamed to disk
    await client.set_gocb_values("IED1LD0/LLN0.gcb01[GO]", go_ena=True)

server = await iec.Server.start(model, port=102, files=iec.DirectoryFileStore("/var/comtrade"),
                               on_goose_control=lambda state: print(state.go_ena))
```

GOOSE and Sampled Values live in `openiec61850.goose` (loopback network for tests, raw sockets on
Linux):

```python
from openiec61850 import goose

link = goose.RawSocketLink.open("eth1")                       # needs CAP_NET_RAW
pub = goose.GoosePublisher(link, goose.GoosePublisherConfig.from_scl("bay.cid", "BAY1", "LD0", "gcb01"),
                           [False, iec.Quality()])
pub.start()
pub.publish([True, iec.Quality()])                            # stNum + 1, fast retransmissions

async with goose.Receiver(link) as rx:
    async for event in rx.subscribe(gocb_ref="BAY1LD0/LLN0$GO$gcb01"):
        print(event.kind, event.message.st_num, event.message.values)
    async for batch in rx.subscribe_sv(sv_id="MU01").batches():  # lists of SvSample
        currents = [s.le.currents for s in batch]
```

## Documentation

- [Glossary](GLOSSARY.md)
- [Architecture decision records](docs/adr/)
- [Contributing](CONTRIBUTING.md)
- [Guides](docs/guides/) (getting started, architecture, contributing, releasing)
- [Changelog](CHANGELOG.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
