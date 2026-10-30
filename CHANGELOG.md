# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the version is 0.x, a minor
release may break the API. The release process is in
[docs/guides/releasing.md](docs/guides/releasing.md).

## [Unreleased]

### Added

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
- Command-line tools `openiec61850-server` and `openiec61850-client`.
- Google Benchmark suite and a libiec61850 interoperability harness run as Docker binaries
  (both directions).
- CMake package: `find_package(openiec61850 CONFIG)` exporting `openiec61850::openiec61850`,
  with installed headers and tools, a version file, and a vcpkg overlay port in
  `packaging/vcpkg`.
- Release tooling: cibuildwheel configuration (manylinux_2_28), GitLab release job, GitHub
  Actions for public PR checks and PyPI trusted publishing. The version comes only from
  `project(... VERSION)` in `CMakeLists.txt`.
