# Contributing: benchmarks and interop

General rules (clean-room, layout, error handling) are in [CONTRIBUTING.md](../../CONTRIBUTING.md).
This guide covers the two suites that live outside the default build, the benchmarks and the
interop tests, and the command-line tools used for interop debugging.

## Benchmarks (`benchmarks/`)

The suite is the start of the *Reference benchmark* (GLOSSARY): the official measure of
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
- The comparison against libiec61850 that the glossary requires is the next section.
- CI (`analysis:bench-smoke`) runs only a short smoke run and keeps `bench-results/smoke.json` as an
  artifact. Shared runners are too noisy to catch regressions.

### Reference benchmark (`benchmarks/reference/`)

`run.sh` compares openiec61850 with libiec61850 on one machine, without Docker or sudo. It downloads
and builds libiec61850, builds our server and a load generator (both Release, with the same stated
`-O3 -DNDEBUG`), and runs `harness.py`.

```bash
export VCPKG_ROOT=~/vcpkg
benchmarks/reference/run.sh                                # 7 rounds, about 20 minutes
benchmarks/reference/run.sh --rounds 2 --duration 0.5 --warmup 0.2 --client-runs 5   # smoke
benchmarks/reference/run.sh --only reads                   # reads | associations | clients
python3 benchmarks/reference/harness.py --reanalyze build/reference/results/raw.json
# -> build/reference/results/{raw.json,summary.csv,summary.md}; WORK_DIR and OUT move them
```

**Clean-room (ADR 0001):** libiec61850 is used only through its prebuilt example executables, their
command line and their output. Nothing is compiled against its API, and `run.sh` deletes its source
tree after building. Do not read that tree when a number looks wrong.

| Group | Measures |
|---|---|
| `read/{scalar,do}/in_flight:N` | our client against each server on one association: closed-loop reads of `GGIO1.AnIn1.mag.f` or `GGIO1.AnIn1`, N=1 sequential, N=5 and 16 pipelined |
| `associations:A` | A associations, one sequential worker each, two client threads. A=1, 2, 4 on both servers, then 16, 64, 256 on ours |
| `client/*` | wall time of 100 runs per round of their example clients against each server |

Method:

- Loopback, no TLS. Every server runs on CPUs 4 and 6 and the clients on CPUs 8 and 10.
- The load generator is the same binary with the same settings for both servers.
- Each round restarts both servers and runs each cell against both in turns, swapping the order on
  odd rounds. Each read sample is 1 s of warm-up and 5 s measured.
- Every sample is kept. The summary gives the median with IQR and range, and paired per-round
  ratios. A sample is flagged noisy when other processes used more than 0.1 core of the pinned
  CPUs. Ratios are also shown over only the rounds with no flagged sample, next to the full set.
- `--simulate --period 100` makes our server change values at the 10 Hz measured on theirs.
- `raw.json` records the machine, commit, flags, load and peer source hash.

What it cannot show:

- It compares two *example programs*, not two libraries: their example server, their build
  defaults, its 2-association limit and its update loop, against our command-line tool.
- It measures our client on both sides, so the client's own ceiling hides server capacity. Check
  `client_cores`: near 1.0 per client thread means the result is bounded by the client.
- Their client against their server, the pairing that shows their whole stack, is not measured,
  because that would need a program written against their API. Their example clients only give wall
  times, which sit on a floor that does not depend on the server.
- Loopback says nothing about real networks, and the models are not identical (the value read has
  the same shape on both; `value_leaves` in `raw.json` checks it).

Record reference numbers only on a quiet machine. Put them in `benchmarks/reference/results/` as
`summary.md`, `summary.csv`, `raw.json` (if small) and a short reading of them, stating where we
lose. The maintainer reviews them first: until then ADR 0008 keeps performance claims out of the
README, `pyproject.toml` and the GLOSSARY. Current state:
[results](../../benchmarks/reference/results/README.md).

### Adding a benchmark

- Put codec benchmarks in `bench_codec.cpp` and stack/loopback ones in `bench_loopback.cpp`.
  Build inputs with `payloads.hpp` outside the timed loop.
- Call `SetItemsProcessed` (and `SetBytesProcessed` for codecs) so results stay comparable across
  sizes. Use `state.SkipWithError` instead of asserting.
- Keep payloads realistic: shapes taken from IEC 61850-8-1 (MV structures, report layouts), not
  random bytes.

## Interop (`interop/`)

ADR 0007 validates interoperability against independent implementations instead of physical
IEDs. Two peers are covered: IEC61850bean ([below](#iec61850bean)) and libiec61850, tested in both
directions:

- **our client against their servers**: the runner drives the libiec61850 example servers;
- **their clients against our server**: the libiec61850 example clients run against
  `openiec61850-server` (see [Command-line tools](#command-line-tools-tools)).

**Clean-room (ADR 0001):** `interop/libiec61850/Dockerfile` downloads a libiec61850 release and
builds it with its own build system. Only the resulting executables are used. Do not open,
read, grep or copy anything from that source tree, not even to work out why a test fails. Debug
from the wire instead (Wireshark's MMS dissector, the runner's output, our own logs).

### Layout

| Path | Role |
|---|---|
| `interop/libiec61850/Dockerfile` | builds the example servers and example clients (`LIBIEC61850_VERSION`, optional `LIBIEC61850_SHA256`) |
| `interop/runner/` | `openiec61850_interop`, a C++ program using our client, built as a standalone CMake project (`cmake -S interop/runner -B build/interop`) and as a Docker image |
| `interop/server/` | Docker image of `openiec61850-server` serving `simpleIO.icd`, the model the example clients expect |
| `interop/clients/` | `run_clients.sh`, which runs the example clients against a server and grades their output; its image is the libiec61850 one plus the script |
| `interop/compose.yaml` | `basic-io` (`server_example_basic_io`), `control` (`server_example_control`) and `openiec61850-server` on the compose network, also published on `127.0.0.1:10102` / `:10103` / `:10104`, plus `runner` and `clients` |
| `interop/run.sh` | builds everything, runs both directions, prints a summary, tears down |

### Running

```bash
interop/run.sh                                 # exit status 0 when nothing FAILed
ONLY=runner interop/run.sh                     # one direction: runner | clients
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
| `data-set` | GetDataSetDirectory and GetDataSetValues of the first data set |
| `data-set/dynamic` | creates a data set, reads it back and deletes it. **WARN** if the creation is refused |
| `report` | `enable_reporting` with GI on the first URCB (else BRCB), waits for a report, disables reporting |
| `report/brcb` | the same on the first BRCB, when the model has both |
| `report/dchg` | with `--expect-dchg`: waits for a report with reason data-change |
| `control/<model>` | for each control model found (direct/SBO, normal/enhanced security), `operate()` on the first BOOLEAN-controlled object, checks that `stVal` follows, then restores it |
| `release` | Conclude and A-RELEASE |

Each check prints `PASS`, `WARN`, `SKIP` (the model has nothing to exercise) or `FAIL`. The exit
status is non-zero only on `FAIL`.

### IEC61850bean

`interop/iec61850bean/` runs the released IEC61850bean jars the same way, as a binary only, in
both directions: `ONLY=bean interop/run.sh`, or `interop/iec61850bean/run_native.sh` on a host
without Docker. Its [README](../../interop/iec61850bean/README.md) has the coverage and the peer's
known defects. TLS is not covered, as its console applications have no option for it.

### Reverse direction: libiec61850 clients against our server

`interop/server/simpleIO.icd` reproduces the model the example clients expect: LD
`simpleIOGenericIO`, `GGIO1` with `AnIn1..4`, `SPCSO1..9` (the control models of
`server_example_control`), `Ind1..4`, the data sets `Events`, `Events2`, `Measurements`,
`ControlEvents` and their RCB instances (`EventsRCB01`, `EventsIndexed01..03`,
`Measurements01..03`...). It was written from black-box observation only: the clients' printed
output and errors, and the discovery of the libiec61850 example servers with `openiec61850-client
discover`. The server runs with `--simulate`, so integrity and data-change reports flow.

`run_clients.sh [--timeout S] HOST [PORT]` runs each example client (host and port as
arguments), stops the ones that run until interrupted with SIGINT after the timeout, and checks
the exit status and output patterns:

| Check | Client | What it expects |
|---|---|---|
| `mms_utility/{identify,domains,directory,read}` | `mms_utility -i / -d / -t / -r` | Identify, domain list, domain variables (with RCBs), a Read |
| `client_example2/discovery` | `iec61850_client_example2` | LD/LN/DO tree, data sets with members, RP/BR instances |
| `client_example4/dataset` | `iec61850_client_example4` | four `AnIn` values from a data set read |
| `client_example1/read+report` | `iec61850_client_example1` | a float read, `EventsRCB01` enabled, reports received |
| `client_example_reporting/reports` | `iec61850_client_example_reporting` | reports with RptID `Events1` and member references |
| `client_example_rcbAsync/rcb` | `iec61850_client_example_rcbAsync` | async reads, data set values, RCB values |
| `client_async/services` | `iec61850_client_async` | async directory, reads, data set values, a control |
| `client_example_control/control` | `client_example_control` | SPCSO1..4 and 9 operated (direct/SBO, normal/enhanced), three CommandTermination+ |

The patterns were checked against the libiec61850 example servers themselves, which pass the same
checks (`basic-io` for all but the control check, `control` for that one). To run the clients by
hand against any server:

```bash
docker run --rm --network host openiec61850-interop/clients:1.6.0 127.0.0.1 10104
docker run --rm --network host --entrypoint iec61850_client_example2 \
  openiec61850-interop/libiec61850:1.6.0 127.0.0.1 10104
```

### CI

The `interop:libiec61850` job (stage `interop`) runs `interop/run.sh` (both directions) in a
`docker:27` image. It
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
- **Read of a whole LN with a small PDU size.** `mms_utility -l 300 -a simpleIOGenericIO -r GGIO1`
  fails ("ERROR 40") against both our server and the libiec61850 example server, since the value
  does not fit the negotiated PDU size. Not a deviation; noted because it looks like one.

## Command-line tools (`tools/`)

Two small programs, built by default (`OPENIEC61850_BUILD_TOOLS`, off for the Python wheels) and
installed into `bin/`:

```bash
# Serve the IED model of an SCL file; prints "listening on ADDR:PORT" once ready.
openiec61850-server --scl interop/server/simpleIO.icd --port 10102 --simulate --verbose
#   --ied NAME / --ap NAME   IED and access point (default: the first ones)
#   --bind ADDR, --port N    0 picks a free port
#   --password PW            require ACSE password authentication
#   --simulate, --period MS  random-walk MX FLOAT values, toggle status-only BOOLEAN stVal
#   --control-delay MS       complete operations later (enhanced: CommandTermination after MS)
#   --verbose                associations, writes, controls, SCL diagnostics (stderr)

# Explore a server.
openiec61850-client --port 10102 discover
openiec61850-client --port 10102 read 'simpleIOGenericIO/GGIO1.AnIn1.mag.f[MX]'
openiec61850-client --port 10102 write 'simpleIOGenericIO/GGIO1.NamPlt.d[DC]' text
openiec61850-client --port 10102 --count 3 reports 'simpleIOGenericIO/LLN0.EventsRCB01[RP]'
openiec61850-client --port 10102 operate simpleIOGenericIO/GGIO1.SPCSO2 true
```

The server accepts every write and every control and mirrors ctlVal into stVal (a BOOLEAN ctlVal
into a Dbpos stVal as on/off). SIGINT or SIGTERM stops it cleanly. `--verbose` logs what the
server API exposes: associations (accepted or refused), writes and control requests; there is no
per-request hook for reads and directory services. The client takes values as text
(`true`/`false`, numbers, strings, bit strings as `0`/`1` digits, octet strings as hex) and
converts them to the type it reads first (write) or to the ctlVal type (operate). Exit status: 0
on success, 1 when a service fails, 2 on usage errors.

The CTest `tools.smoke` (`tools/smoke_test.sh`) starts the server on port 0 and runs `discover`,
`read`, `write`, `operate` on the four control models, `reports` and the error paths with the
client.
