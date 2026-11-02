# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the version is 0.x, a minor
release may break the API. The release process is in
[docs/guides/releasing.md](docs/guides/releasing.md).

## [Unreleased]

## [0.2.0] - 2026-11-02

### Added

- Python wheels for macOS arm64 and Windows AMD64, for CPython 3.10 to 3.13.

### Changed

- C++ API: the SCL `s_addr` members are now `short_addr`, since Winsock defines `s_addr` as a
  macro. C++ code that read them must use the new name. The Python API does not change.

### Fixed

- SCL float values build on macOS, whose libc++ has no floating-point `std::from_chars`.
- Builds with MSVC: POSIX and libstdc++ time calls were replaced.
- Windows listeners no longer set `SO_REUSEADDR`, which allowed binding a port already in use, and
  refused connections raise `ConnectionRefused` there.

### Known limitations

The notes of 0.1.0 still apply, except for the wheels above. macOS and Windows are built and
tested on GitHub Actions only, and their job does not block a release. Wheel tests skip those that
need the fake server, which release wheels do not contain.

## [0.1.0] - 2026-11-01

### Fixed

- TLS: an abort with traffic in flight no longer keeps the socket open for the whole close
  timeout (1 s); the pending read is cancelled before the TLS shutdown.
- A peer that stops reading no longer grows memory without limit, on either role: the server's
  queue of answers and reports, the rejects of a request flood and the transport's output buffer
  were all unbounded (measured: 19 MiB/s with reports enabled, 130 MiB/s with a request flood).
  New `channel_options::max_output_bytes` (16 MiB) and `write_stall_timeout` (30 s without
  progress), plain and TLS, in Python on `IsoParameters` and `ServerIsoParameters`: past them the
  association ends, `errc::output_limit_exceeded` (`OutputLimitExceeded`) or `timed_out`, and the
  others do not notice.
- `server::stop()` and `abort()` no longer hang on a peer that does not read: the ABRT gets 1 s.
- A client that keeps reading is no longer aborted at `max_output_bytes` during an `update()` storm:
  the server sent one PDU per turn on its strand, and a turn came after all the updates waiting
  there. The whole queue now goes out per turn, in bounded groups on the association's strand, and
  updates are applied 64 calls per turn, so that the rest of the I/O thread gets to run.

### Changed

- Reports of an association aborted that way: a URCB loses what was queued and is disabled; a BRCB
  stops at half the limit, keeps its entries in its buffer and goes back to those not written, so
  that the next association gets them. `server::slow_peer_aborts()` counts those aborts.
- `server::update()` fails with `errc::overloaded` (`ServerOverloaded`) with
  `server_options::max_pending_updates` (8192) changes pending, instead of queueing on the strand
  shared with the clients without limit. Never blocks, and drops nothing it accepted;
  `server::pending_updates()` tells how far behind the strand is.
- `incoming_request::encoded_answer()`, `server_association::send_batch()`: PDUs encoded by the caller.
  The server no longer encodes a response twice to check its size.

### Added

- `benchmarks/reference/`: the reference benchmark against libiec61850 (provisional results, not
  reviewed), and `--max-associations` in `openiec61850-server`.
- Native core (C++20, Asio standalone, one I/O thread, `result<T>` + `std::error_code` errors).
- Full ISO stack for MMS: BER codec (X.690), TPKT and COTP class 0 (RFC 1006, X.224), session
  (X.225, kernel + duplex), presentation (X.226, kernel), ACSE (X.227), with sans-I/O state
  machines and COTP over TCP.
- MMS codec (ISO 9506): Initiate/Conclude/Cancel/Reject, Identify, GetNameList, Read, Write,
  GetVariableAccessAttributes, named variable lists, InformationReport, journal and file
  services, with zero-copy `data_view` and owning values.
- MMS association layer for both roles: pipelined requests, timeouts, orderly release, abort,
  password authentication. Confirmed services run in both directions: `server_association::request()`
  and `client_association::set_request_handler()`.
- SetFile (MMS obtainFile): `client::set_file()` from memory or a stream, and in the server a pull
  into the `file_store` (`write()`, `writable()`) with the `on_obtain_file` hook,
  `max_obtain_file_size` and `obtain_file_timeout`. Off without the hook; advertised in
  servicesSupportedCalled only when usable. In Python `Client.write_file`, `Client.upload_file`, the same on `sync.Client`,
  `Server.start(on_obtain_file=...)` and `FileStore.write`.
- IEC 61850 naming and basic types: object references, functional constraints, the 8-1 MMS
  mapping, Quality, TimeStamp, EntryID, TrgOps/OptFlds, control enums.
- ACSI client: directory discovery, data definitions, read/write, data sets, URCB/BRCB reporting
  with GI and association recovery (BRCB resume from EntryID), control (direct and SBO, normal
  and enhanced security), setting groups, logs, file services, GoCB attributes, MMS service
  error details.
- ACSI server: model builder and SCL-driven models, read/write with access checks and hooks,
  data sets, URCB/BRCB reporting engine (dchg/qchg/dupd, BufTm, IntgPd, GI, buffer overflow),
  control with all four control models (CommandTermination, operTm, Test/Beh handling),
  setting groups, logs, file store, GoCB attributes.
- TLS (IEC 62351-3) for MMS on client and server, enabled with `OPENIEC61850_ENABLE_TLS`:
  mutual certificate authentication, peer name checks, CRLs, TLS 1.2 and 1.3, the peer certificate
  exposed to the `authorize` hook and in `association_info`, TLS 1.3 key updates by time or
  volume. Python: `TlsConfig`, `TlsSession`, `TLS_PORT`, `TlsError`, with wheels built with TLS.
  Tools: `--tls` and the `--tls-*` options.
- SCL (IEC 61850-6) parser for ICD/CID/IID/SCD with validation diagnostics, IED instantiation and
  GSE/SMV address extraction.
- Arrays of data objects in server models: DO and SDO with `count` (SCL, `ln_handle::data_object`,
  `do_handle::sub_object` / `element`, Python `count=` and `DataObjectBuilder.element`), seen as MMS
  arrays with element access through AlternateAccess, `DOI` / `SDI` `ix` initial values, `FCDA` `ix`
  and the `LD/LN$FC$DO(1)$DA` form in report and log DataRefs (`to_mms_data_reference`,
  `from_mms_data_reference`), also used for data set members indexed into an array attribute. `get_data_definition` accepts array indices and
  `get_data_directory` lists the data of array elements.
- Control of elements of arrays of data objects: `get_control` / `operate` accept `LD/LN.DO(i)`
  (Python `Client.control` / `operate`), with AlternateAccess on the wire and LastApplError and
  CommandTermination routed to the element.
- Logs of other logical devices: SCL `LogControl` `ldInst` and `log_control_settings::log_ld`
  (Python `LogControl.log_ld`).
- `Timestamp` and `EntryTime` initial values in SCL and `parse_value` (xs:dateTime).
- GOOSE and Sampled Values (9-2 LE) publishers and subscribers over Linux AF_PACKET, with
  retransmission and TAL supervision.
- Python package `openiec61850`: `asyncio` client and server APIs, typed values, exception
  hierarchy, `openiec61850.sync` blocking facades. Release wheels never ship the test-only
  `openiec61850._testing` extension.
  Python also covers the rest of the stack options (`IsoParameters`, `ServerIsoParameters`, the
  responding AP title, `accept_connection`), the `authorize` diagnostic (`AcseDiagnostic`), the
  CO structure of a `Control`, and GOOSE / SV frames and supervision without I/O
  (`encode_goose`, `decode_goose`, `encode_sv`, `decode_sv`, `SequenceTracker`, `SmpCntTracker`).
- Command-line tools `openiec61850-server` and `openiec61850-client`.
- Google Benchmark suite and a libiec61850 interoperability harness run as Docker binaries
  (both directions).
- IEC61850bean as the second interoperability peer of ADR 0007, in both directions
  (`interop/iec61850bean`, `ONLY=bean interop/run.sh`). Run natively; its Docker path has not been
  run yet, and TLS is not covered. Its defects are listed in `interop/iec61850bean/README.md`.
- CMake package: `find_package(openiec61850 CONFIG)` exporting `openiec61850::openiec61850`,
  with installed headers and tools, a version file, and a vcpkg overlay port in
  `packaging/vcpkg`.
- Release tooling: cibuildwheel configuration (manylinux_2_28), GitLab release job, GitHub
  Actions for public PR checks and PyPI trusted publishing. The version comes only from
  `project(... VERSION)` in `CMakeLists.txt`.

### Changed

- `client::get_data_set_values()` sets specificationWithResult, which IEC61850bean requires.
- `client::get_rcb_values()` reads an empty EntryID as unset instead of failing, which also made
  enabling a BRCB fail on IEC61850bean.

### Known limitations

This is an alpha release (ADR 0008): the API may change and no conformance to IEC 61850 is
claimed. Not verified against the text of the standards: the ObtainFile encoding, the `(n)` form
of data references into arrays of data objects, the 8-1 clauses cited for it, and the mandatory
cipher suites of IEC 62351-3. TLS was tested against OpenSSL and between openiec61850 peers, not
against another IEC 61850 implementation. TLS 1.2 keys are not renewed during an association.
Not implemented: GOOSE and Sampled Values security (IEC 62351-6), certificate authentication in
ACSE (IEC 62351-4), third-party `sourceFileServer` in ObtainFile. The reference benchmark against
libiec61850 does not exist yet, so nothing is promised about performance. macOS and Windows
builds are not exercised in the homelab.
