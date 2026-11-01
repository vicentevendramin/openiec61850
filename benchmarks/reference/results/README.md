# Reference benchmark: provisional results

**These are not reference numbers.** The host was shared with other CPU-heavy jobs during the run
(load average about 8, up to 19 foreign cores), and 72 of 203 samples are flagged noisy. Rerun on a
quiet machine before using them. They await maintainer review, and ADR 0008 keeps them out of the
README, `pyproject.toml` and the GLOSSARY. Method and limits:
[contributing guide](../../../docs/guides/contributing.md#benchmark-de-referencia-benchmarksreference).

| | |
|---|---|
| Run | 2026-10-31, 7 rounds, 1 s warm-up + 5 s per read sample, 100 client runs per sample |
| Commit | `b6ccd84`, libiec61850 1.6.0 (`0dd0adc7...`) |
| Machine | i5-14600K, 20 CPUs, 15 GiB, WSL2 6.18.54.1, GCC 15.2, frequency governor unknown |
| Build | Release, `-O3 -DNDEBUG` on both; TLS off; TCP loopback |

Files: `summary.md` (every cell), `summary.csv`, `raw.json` (every sample).

## Reads, one association

Median [IQR] over 7 rounds. Ratio: ours / theirs per round, median (range); "clean" uses only the
rounds where neither sample was flagged. Server CPU comes from 10 ms ticks and includes warm-up.

| Read, in flight | libiec61850 server, reads/s | openiec61850 server, reads/s | Ratio | Clean ratio (n) |
|---|---|---|---|---|
| scalar, 1 | 23,204 [20,587-23,542] | 19,432 [17,060-19,761] | 0.84 (0.82-0.86) | 0.84 (4) |
| scalar, 5 | 67,642 [66,785-68,177] | 106,070 [105,064-108,607] | 1.57 (1.55-1.76) | 1.56 (6) |
| scalar, 16 | 51,766 [51,595-54,109] | 104,095 [102,180-107,287] | 2.01 (1.71-2.11) | 2.08 (3) |
| DO, 1 | 19,944 [18,598-20,715] | 17,415 [16,218-18,333] | 0.83 (0.82-1.05) | 0.87 (2) |
| DO, 5 | 60,796 [54,632-63,181] | 104,915 [96,092-105,434] | 1.73 (0.97-2.18) | 1.73 (3) |
| DO, 16 | 50,568 [34,686-51,545] | 98,127 [56,778-100,385] | 1.91 (0.60-2.19) | 1.95 (3) |

| Read, in flight | p50 latency theirs, us | p50 latency ours, us | Server CPU/read theirs, us | Server CPU/read ours, us | Client core theirs / ours |
|---|---|---|---|---|---|
| scalar, 1 | 39.1 | 45.7 | 17.5 | 29.4 | 0.64 / 0.56 |
| scalar, 5 | 71.9 | 39.6 | 7.2 | 9.0 | 0.98 / 0.96 |
| scalar, 16 | 302.6 | 129.7 | 8.8 | 9.1 | 0.97 / 0.95 |
| DO, 1 | 45.5 | 51.6 | 19.7 | 32.4 | 0.65 / 0.56 |
| DO, 5 | 76.6 | 40.6 | 8.7 | 9.1 | 0.96 / 0.96 |
| DO, 16 | 314.6 | 133.5 | 9.1 | 9.5 | 0.97 / 0.95 |

Both servers negotiated 5 outstanding requests, so N=16 also measures queueing in our client.

## Associations

One sequential worker per association, two client threads. Reads/s, median [IQR].

| Associations | libiec61850 server | openiec61850 server | Ratio | p50 connect theirs / ours, ms |
|---|---|---|---|---|
| 1 | 18,065 [16,673-19,647] | 13,248 [12,190-13,551] | 0.68 (0.66-0.78) | 0.47 / 0.49 |
| 2 | 38,742 [23,730-39,047] | 29,343 [26,215-30,448] | 0.78 (0.59-1.87) | 20.53 / 0.52 |
| 4 | 2 up, 2 refused | 76,827 [74,052-80,468] | not comparable | |
| 16 | not served | 109,049 [105,007-109,938] | | -/0.22 |
| 64 | not served | 107,998 [105,070-110,811] | | -/0.22 |
| 256 | not served | 80,808 [74,348-84,247] | | -/0.22 |

All 256 associations stayed up with no read errors. p99 at 256 was 5.7 ms. Our tool runs one I/O
thread and sits at 1.00 core from 16 associations up, so that is its ceiling here, not the
library's.

## Example clients

Wall time per run, median of round medians, with paired ratios of 1.000-1.001 and no failures.

| Client | libiec61850 server, ms | openiec61850 server, ms |
|---|---|---|
| `mms_utility -i` | 32.79 | 32.84 |
| `mms_utility -r` | 32.77 | 32.82 |
| `iec61850_client_example2` | 64.97 | 64.91 |
| `iec61850_client_example4` | 33.04 | 32.84 |

These show no difference, and they cannot: the times sit on a floor of about 32.8 ms or twice that,
whichever server answers, so the server's share is lost below it. They show only that both servers
complete the same runs. `iec61850_client_example2` printed 176 lines against theirs and 364 against
ours, so the two models differ and that discovery is not the same work.

## Where we lose

- **Sequential reads**: 16% fewer reads/s on the scalar (0.82-0.86) and about 6.6 us more median
  latency. This is the steadiest result here.
- **One or two associations with two client threads**: 22-32% fewer reads/s.
- **Server CPU per read**: higher in every comparable cell. About 1.7x when sequential and 1.03-1.25x
  when pipelined. Nothing shown here has our server doing the same work on less CPU.
- **Client threads**: the same one-association load is slower with two client threads than with
  one, against both servers, and more against ours (13,248 vs 19,432 reads/s).

## Limits of the pipelined gain

The 1.6-2x pipelined figures are a gain of the *pair* with our client, not proof of server capacity.
Our client is near 1.0 core in those cells, so it bounds them. Their server stays near 0.45-0.5
core, and why it does not go further cannot be told from outside. With our client tuned to our
server, the pairing may favour us. Their client against their server is not measured.

## Noise

Samples that fell far below their cell (10,477 reads/s in `read/do/in_flight:16`, against a median
of 98,127, with 3.3 foreign cores on the pinned CPUs) explain the wide ranges. The cells with narrow ranges changed little under the clean
filter. Sequential results are the most trustworthy here, but a quiet rerun may still move all of
them.

## Possible defect: none confirmed

The extra CPU on sequential reads has no hotspot. A sampled profile of our server (a `-g` build,
under heavy load, with no kernel samples) is flat and spread across asio coroutine, strand and
`any_executor` code, with no function above 3% and `ber::decode_tlv` near 1%. `TCP_NODELAY` is on and
each PDU is one write. So this looks like the structural per-wake-up cost of the async core (ADR
0004), which no small safe change removes. Nothing was changed. A quiet profile with kernel samples
is still needed to confirm it.
