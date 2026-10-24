# Contributing: benchmarks and interop

General rules (clean-room, layout, error handling) are in [CONTRIBUTING.md](../../CONTRIBUTING.md).
This guide covers the two suites that live outside the default build: the benchmarks and the
interop tests.

## Benchmarks (`benchmarks/`)

The suite is the start of the *Benchmark de referência* (GLOSSARY): the official measure of
"fast". It uses Google Benchmark, which comes from the `benchmarks` vcpkg feature. It builds only
with `OPENIEC61850_BUILD_BENCHMARKS=ON`, so the default, `release`, `asan` and `fuzz` builds never
see it.

```bash
export VCPKG_ROOT=~/vcpkg
cmake --preset bench                 # Release, tests off, benchmarks on -> build/bench
cmake --build --preset bench
build/bench/benchmarks/openiec61850_bench                                  # everything
build/bench/benchmarks/openiec61850_bench --benchmark_filter='Loopback'    # a subset
build/bench/benchmarks/openiec61850_bench --benchmark_min_time=0.01s       # quick smoke
```

| Benchmark | Measures |
|---|---|
| `BM_BerTlvWalk/N` | depth-first `ber::decode_tlv` over a Read response with N values |
| `BM_MmsDecodeReadResponse_{View,Owning}/N` | `decode_pdu` of a Read response with N MV-like values, read through `data_view` vs copied into owning `mms::data` |
| `BM_MmsDecodeInformationReport_{View,Owning}/N` | the same for a report InformationReport with N entries |
| `BM_ParseReport/entries:N/refs:R` | `decode_pdu` + `client::parse_report`, with (R=1) and without data-references |
| `BM_EncodeReadRequest/N` | `encode_pdu` of a Read request for N variables |
| `BM_LoopbackRead/in_flight:N` | `client::read()` round trips per second with N in flight, client and fake server over TCP loopback |
| `BM_LoopbackReports/batch:N` | reports per second from the fake server through an enabled URCB into `next_report()` |

The loopback benchmarks compile `tests/client/fake_server.cpp` into the benchmark executable
without changing it. Client and server share one I/O thread, so the loopback numbers show the CPU
cost of the whole stack in both directions, not network latency. `items_per_second` is the
headline figure: values, entries, variables, reads or reports per second, depending on the
benchmark.

### Recording results

Results are recorded as Google Benchmark JSON. The file includes the machine context: CPU,
caches, load average, library build type.

```bash
cmake --build --preset bench --target bench-json     # 5 repetitions, aggregates only
# -> build/bench/results/latest.json
```

or by hand:

```bash
build/bench/benchmarks/openiec61850_bench --benchmark_repetitions=5 \
  --benchmark_report_aggregates_only=true \
  --benchmark_out_format=json --benchmark_out=results-$(git rev-parse --short HEAD).json
```

Guidelines:

- Record on an idle machine with a fixed CPU frequency governor. Never record on a laptop on
  battery or inside the sanitizer builds.
- Compare runs with Google Benchmark's `tools/compare.py benchmarks old.json new.json`. When a
  change claims a speed-up, put the comparison in the merge request.
- The comparison against libiec61850 that the glossary requires runs its binaries on the same
  machine (ADR 0001 allows running them). Its numbers are recorded the same way, next to ours.
- CI (`analysis:bench-smoke`) runs only a short smoke run and keeps `bench-results/smoke.json` as an
  artifact. Shared runners are too noisy to catch regressions.

### Adding a benchmark

- Put codec benchmarks in `bench_codec.cpp` and stack/loopback ones in `bench_loopback.cpp`.
  Build inputs with `payloads.hpp` outside the timed loop.
- Call `SetItemsProcessed` (and `SetBytesProcessed` for codecs) so results stay comparable across
  sizes. Use `state.SkipWithError` instead of asserting.
- Keep payloads realistic: shapes taken from IEC 61850-8-1 (MV structures, report layouts), not
  random bytes.

## Interop (`interop/`)

ADR 0007 validates interoperability against independent implementations instead of physical
IEDs. The first peer is the libiec61850 example servers.

**Clean-room (ADR 0001):** `interop/libiec61850/Dockerfile` downloads a libiec61850 release and
builds it with its own build system. Only the resulting executables are used. Do not open,
read, grep or copy anything from that source tree, not even to work out why a test fails. Debug
from the wire instead (Wireshark's MMS dissector, the runner's output, our own logs).

### Layout

| Path | Role |
|---|---|
| `interop/libiec61850/Dockerfile` | builds the example servers (`LIBIEC61850_VERSION`, optional `LIBIEC61850_SHA256`) |
| `interop/runner/` | `openiec61850_interop`, a C++ program using our client, built as a standalone CMake project (`cmake -S interop/runner -B build/interop`) and as a Docker image |
| `interop/compose.yaml` | `basic-io` (`server_example_basic_io`) and `control` (`server_example_control`) on the compose network, also published on `127.0.0.1:10102` / `:10103`, plus the `runner` |
| `interop/run.sh` | builds everything, starts the servers, runs the runner, tears down |

### Running

```bash
interop/run.sh                                 # exit status 0 when nothing FAILed
KEEP_UP=1 interop/run.sh                       # leave the servers up afterwards
LIBIEC61850_VERSION=1.5.3 interop/run.sh       # another release

# Against servers that are already up, with a local build of the runner:
cmake -S interop/runner -B build/interop -G Ninja && cmake --build build/interop
build/interop/openiec61850_interop --timeout 5 127.0.0.1:10102 127.0.0.1:10103
```

The runner does not know the server's model. It discovers the model through the directory
services and then runs these checks against each server:

| Check | What it does |
|---|---|
| `connect` | establishes the association |
| `discover` | runs Get{Server,LogicalDevice,LogicalNode,Data}Directory on every LD and LN, then GetDataDefinition |
| `read` | reads one ST/MX object, then up to 16 objects in one Read |
| `write` | writes back a CF/DC/SP value just read. **WARN** if every candidate is refused with a proper negative response |
| `report` | `enable_reporting` with GI on the first URCB (else BRCB), waits for a report, disables reporting |
| `control/<model>` | for each control model found (direct/SBO, normal/enhanced security), `operate()` on the first BOOLEAN-controlled object, checks that `stVal` follows, then restores it |
| `release` | Conclude and A-RELEASE |

Each check prints `PASS`, `WARN`, `SKIP` (the model has nothing to exercise) or `FAIL`. The exit
status is non-zero only on `FAIL`.

### CI

The `interop:libiec61850` job (stage `interop`) runs `interop/run.sh` in a `docker:27` image. It
needs the homelab runner with Docker (`tags: [homelab]`, a placeholder until the runner tag is
final). It runs only on the default branch and on merge requests from this project, never for
external contributions (ADR 0006). It is `allow_failure: true` until it has proven stable.

### When interop fails

1. Look at the runner output and the server logs, which `run.sh` prints on failure. Capture the
   traffic with `tcpdump -i any port 10102`, or inside the compose network, and decode it with
   Wireshark.
2. Decide from the standard text, not from the peer's behaviour, which side is wrong. If the peer
   deviates and we still want to accept it, add a tolerance option and a regression case built
   from the capture (ADR 0007: field reports and deviations become corpus and regression cases).
3. Never "fix" a mismatch by mimicking libiec61850 internals.

### Known deviations

- **Session Version Number.** The libiec61850 1.6.0 example servers close the TCP connection
  without any SPDU when the session CN proposes both versions (Version Number PV = 3, bits 1 and
  2). The PV is a bit map of the proposed versions (ISO 8327-1 / X.225 §8.3.1). They accept a CN
  that proposes version 2 only, so the client proposes version 2 only by default
  (`association_params::session_versions`).
- **Writes refused.** The example servers refuse writes to CF/DC with object-access-denied, so
  the `write` check reports WARN.
