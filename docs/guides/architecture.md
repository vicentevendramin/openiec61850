# Architecture overview

openiec61850 is a clean-room implementation (ADR 0001) of the IEC 61850 MMS profile
(IEC 61850-8-1) over the ISO/OSI upper layers on TCP. Each layer is a separate component with its
own public headers (`include/openiec61850/<component>/`), sources, tests and fuzzers.

## Layers

```
            Python asyncio API (python/openiec61850, nanobind)   ── binding parity, ADR 0002
                                   │
   ┌───────────────────────────────┴───────────────────────────────┐
   │ client/      ACSI Cliente: directory, data access, data sets, │ IEC 61850-7-2 / 8-1
   │ server/      reporting (RCBs), control; ACSI Servidor         │
   ├───────────────────────────────────────────────────────────────┤
   │ model/  scl/ object references, FCs, MMS name mapping,        │ IEC 61850-7-x / -6
   │              basic types, quality, timestamps; SCL parser     │
   ├───────────────────────────────────────────────────────────────┤
   │ association/ client_association / server_association:        │ the "Associação"
   │              connect, Initiate negotiation, request slots,    │
   │              invoke IDs, release/abort                        │
   ├───────────────────────────────────────────────────────────────┤
   │ mms/         MMS PDU codec, Data (data_view / data),          │ ISO 9506-2
   │              TypeDescription                                  │
   ├───────────────────────────────────────────────────────────────┤
   │ iso/acse/    AARQ/AARE/RLRQ/RLRE/ABRT                         │ ISO 8650
   │ iso/presentation/  CP/CPA/CPR/ARU, P-DATA                      │ ISO 8823
   │ iso/session/ CN/AC/RF/DT/FN/DN/AB                             │ ISO 8327
   ├───────────────────────────────────────────────────────────────┤
   │ transport/   cotp_channel: TCP + TLS (optional) + TPKT + COTP │ RFC 1006, ISO 8073,
   │              class 0;                                         │ IEC 62351-3
   │              io_runtime (I/O thread), spawn bridge            │
   ├───────────────────────────────────────────────────────────────┤
   │ ber/         BER reader / writer / TLV decoder                │ ITU-T X.690
   │ core/        result<T>, error codes, byte_view / byte_buffer  │
   └───────────────────────────────────────────────────────────────┘
                      Asio standalone (epoll / IOCP), OpenSSL 3 for TLS (ADR 0005)
```

Data flows down as encoders appending to a `byte_buffer`, and up as decoders over a
`byte_view`. Decoders never trust a length from the network: every access is bounds-checked and
errors come back as `result<T>`, never as exceptions.

Zero-copy decoding: `mms::decode_pdu` validates the whole PDU once and hands out views
(`mms::data_view`, `mms::list_view<T>`) into the receive buffer. Callers that keep values copy
them into owning `mms::data` trees; the client does this for the values it returns, because its
results must own their data to cross threads and the Python boundary. The benchmarks measure both
paths (`*_View` vs `*_Owning`).

## Threading model (ADR 0004)

- **One I/O thread per runtime.** `transport::io_runtime` owns an `asio::io_context` and the
  thread that runs it. Many associations share one runtime.
- **One strand per object.** A COTP channel, an association, a client and a server each keep all
  their state on a strand of that executor, so they need no locks. Coroutine methods may be
  awaited from a coroutine on *any* executor: they hop onto the strand and resume the caller on
  its own executor.
- **Concurrency inside an association.** Requests are pipelined: several confirmed requests can be
  outstanding at once (up to the negotiated `maxServOutstandingCalling`), matched by invoke ID.
- **Unsolicited traffic.** Reports and connection events go to bounded queues consumed with
  `next_report()` / `next_event()` (async iterator style), or to a callback set with
  `set_report_handler()` / `set_event_handler()`. Handlers run on the client's strand and must
  not block or throw.
- **Python never blocks the loop and the I/O thread never holds the GIL.** The binding starts
  each operation with `transport::spawn` on the I/O thread; its completion is posted back to the
  `asyncio` loop, which resolves a future. `openiec61850.sync` wraps the `asyncio` API for
  blocking callers.
- **Server.** The server keeps its model and RCB state on one strand; `update()` and `stop()` are
  safe from any thread, application handlers run on the strand.

This replaces the blocking-call-plus-callback-threads model used elsewhere: it scales to many
associations and to many concurrent requests on one association.

## Testing layers

| Level | Where | What |
|---|---|---|
| Unit | `tests/<component>/` (Catch2) | codecs and state machines per layer |
| Loopback | `tests/client/fake_server.*`, `tests/server/` | client against a fake server, server against the client |
| Fuzzing | `fuzz/<component>/` (libFuzzer) | every decoder that reads network input |
| Python | `tests/python/` (pytest) | the `asyncio` API against the fake server extension |
| Benchmarks | `benchmarks/` (Google Benchmark) | codec costs and loopback throughput |
| Interop | `interop/` (Docker or native) | both directions against libiec61850 and IEC61850bean (ADR 0007) |
