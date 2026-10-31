# IEC61850bean interop

IEC61850bean 1.9.0 is the second independent implementation of ADR 0007. Like libiec61850 it is
used only as a binary: the released jars from Maven Central, pinned in `fetch.sh`, are run through
their console applications. Do not read its sources or fetch a sources jar, not even to work out
why a test fails. Debug from the wire and from what the applications print.

```bash
ONLY=bean interop/run.sh                    # Docker
interop/iec61850bean/run_native.sh          # no Docker; downloads a pinned JDK if there is no java
ONLY=client interop/iec61850bean/run_native.sh   # one direction: server | client
```

Both directions serve `interop/server/simpleIO.icd`.

| Direction | Covered |
|---|---|
| our client (`interop/runner`) against the console server | discovery, read, write, data sets (static and dynamic), URCB reports (GI, data change), control with normal security |
| the console client (`run_client.sh`) against `openiec61850-server` | discovery, read, dynamic data sets, URCB reports (integrity, GI) |

Not covered:

- The console client has no write and no control action, and refuses BRCBs ("not yet supported by
  the console application"), so our server's write, control and BRCB services are not exercised by
  this peer. Data-change reports are not checked in this direction either.
- **TLS.** Neither console application has a TLS option, so nothing here says anything about
  IEC 62351-3 with this peer.
- Setting groups, logs, files and GOOSE: no console action.

## Known defects of the peer

The runner takes `--bean-defects` for this peer. Each entry below is asserted to still be there:
`WARN` while it shows, `FAIL` once it stops, so a new release cannot leave this list stale. The
client's checks are not relaxed for any of them. The reference is libiec61850 1.6.0, which behaves
correctly on the same frames.

| Check | Defect in 1.9.0 | Reference |
|---|---|---|
| `release` | Logs a decoding failure for the Conclude-RequestPDU and never answers it, so `release()` times out and the client aborts. | The same 22 bytes get a Conclude-ResponsePDU from libiec61850. |
| `report/data-reference` | Sets `OptFlds.data-reference` in its reports without sending the references. Every such report contradicts its own header and is refused. | libiec61850 sends the references for the same request. The runner requests reports without this field elsewhere. |
| `report/opt-flds-rewrite` | Accepts one write of `OptFlds` per RCB for as long as the server runs, even from another association: later ones get object-access-denied. | Five replayed sequences succeed on libiec61850 and `openiec61850-server`. The runner gives each check its own URCB. |
| `report/brcb` | Accepts `RptEna` and `GI` on a BRCB, then sends no report at all. | The same sequence gets reports from libiec61850. Seen with the console server only. |
| `control/*-enhanced` | Refuses enhanced security (its log: unsupported ctlModel). A limitation rather than a bug. | libiec61850 operates the same objects. |

Two more differences are handled in the client, with regression tests in `tests/client`:

- It refuses a Read of a named variable list unless `specificationWithResult` is TRUE, although
  the field defaults to FALSE, and its response leaves the specification out. The client now asks
  for it in `get_data_set_values()`, which is valid for every server.
- `EntryID` of a BRCB is an empty octet string until its first report. The client reads that as no
  entry yet; any other length than 8 is still an error.

Also seen, and left alone:

- `stVal` does not follow `ctlVal`: the console server has no process behind its control objects,
  so `control/*` is `WARN`. `server.sh` toggles `SPCSO4.stVal` through the console's `w` action to
  produce data changes.
- It names a single-instance indexed RCB `EventsRCB`, without the `01` that libiec61850 and
  `openiec61850-server` add.
- It and we spell the BRCB attribute `TimeOfEntry`, libiec61850 `TimeofEntry`. Which one the
  standard asks for has not been checked against its text, and the attribute is optional for
  `get_rcb_values()`, so nothing fails either way.
